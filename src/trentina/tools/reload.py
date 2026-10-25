"""Profile reload tool — apply a profiles.yaml edit without a gateway restart.

Restarting to apply a profile edit is not cheap. On restart the gateway
re-judges every tool description in every profile through all three defense
layers before the first `tools/list` can answer; on the CrunchTools
deployment (~380 tools across two active profiles) that ran for over forty
minutes, during which clients time out on connect. A one-line allowlist
change cannot cost that, or it stops being made — and editing the file
without a reload did nothing at all, because `_build_profile_tools` rebuilds
its aggregate from the IN-MEMORY `Profile`. The file that decides which
destructive tools an agent may call is the worst possible place for an edit
that silently does nothing.

What makes the reload cheap is what it deliberately leaves alone:

* The perimeter verdict cache. Its key is (kind, defense thresholds,
  description text) — not the profile name, and nothing a `tools_allow` edit
  touches — so the rebuilt aggregate re-judges nothing. Editing a profile's
  `defense` thresholds DOES change that key and those descriptions are judged
  again, which is the honest cost of changing the policy they were judged
  under, and the only edit that pays it.
* The per-backend tool list cache, so no backend is re-probed and no circuit
  breaker is disturbed. Only the per-profile aggregate — the filtered,
  namespaced view — is dropped and rebuilt.

The swap is all-or-nothing: the new YAML is parsed, validated and its secrets
resolved in full BEFORE anything is mutated, so a bad edit leaves the running
gateway exactly as it was and returns the error. See `loader.ActiveConfig`
for why mutating the registry dict in place is the entire swap.

What a reload touches is decided by the caller's role (``gateway/scope.py``).

An OPERATOR reload is the one described above: the whole file, every profile,
the gateway-wide settings, and the full diff.

An AGENT reload validates the whole file — a bad edit anywhere still refuses,
because half a file is not a config — and then applies exactly one entry: the
caller's own. Other profiles keep serving what they were serving, and their
diffs are not reported, because another agent's backend names, allowlist deltas
and guarded parameter names are the shape of its permissions and nobody else's
business. The note the caller gets back is fixed text, so it says nothing about
whether anyone else moved.

One thing an agent reload will not do is apply a change to its OWN ``role``.
The file is the authority on who is the operator, and file write access is the
real trust boundary — but a profile promoting itself in a single call is a
worse shape than one that costs an operator reload or a restart.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ..gateway.compress import retrigger_compression
from ..gateway.errors import ScopeError
from ..gateway.llm_proxy import validate_profile_llm_keys
from ..gateway.loader import (
    get_active_config,
    load_profiles,
    replace_active_config,
)
from ..gateway.profile import PREPROCESS_AGENT_FIELDS
from ..gateway.router import invalidate_profile_cache
from ..gateway.scope import CallerScope, require_caller
from ..gateway.service import find_operator, judge_of, log_service_identity
from ..gateway.sessions import session_registry
from ..gateway.upstream import close_profile
from ..logsafe import exc_kind, exc_where

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..gateway.loader import ActiveConfig, GatewayConfig
    from ..gateway.profile import Backend, Profile

logger = logging.getLogger(__name__)

AGENT_RELOAD_REFUSED = "profiles file did not validate; ask the operator"
"""What an agent's refused reload says, whatever the cause (#292). The cause
is the whole file's, and the whole file is not an agent's to read."""


def _glob_delta(before: list[str], after: list[str]) -> dict[str, list[str]] | None:
    """Set-style delta between two glob lists, or None if they match.

    Order within an allow/deny list carries no meaning (a name matches any
    pattern in it, and deny always wins over allow), so a reordering is
    correctly reported as no change.
    """
    added = [pat for pat in after if pat not in before]
    removed = [pat for pat in before if pat not in after]
    if not added and not removed:
        return None
    return {"added": added, "removed": removed}


def _guard_delta(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    noun: str = "parameters",
) -> dict[str, dict[str, list[str]]]:
    """Per-tool guard delta, by guarded NAME only.

    Guard patterns are operator-authored and not secrets, but they are also
    not what an operator needs read back — "the guard on `path` changed" is
    the fact, and the file is the authority on what it changed to.

    ``noun`` names what a guard is keyed by, since both guard maps have this
    shape but not the same subject: parameter guards key on a request
    parameter, response guards on a result field.
    """
    delta: dict[str, dict[str, list[str]]] = {}
    for tool in sorted(set(before) | set(after)):
        old = before.get(tool, {})
        new = after.get(tool, {})
        entry = {
            f"{noun}_added": sorted(set(new) - set(old)),
            f"{noun}_removed": sorted(set(old) - set(new)),
            f"{noun}_changed": sorted(
                name for name in set(old) & set(new) if old[name] != new[name]
            ),
        }
        if any(entry.values()):
            delta[tool] = {k: v for k, v in entry.items() if v}
    return delta


def _backend_delta(before: Backend, after: Backend) -> dict[str, Any]:
    """What changed on one backend. Empty dict means nothing did."""
    candidate: dict[str, Any] = {
        "tools_allow": _glob_delta(before.tools_allow, after.tools_allow),
        "tools_deny": _glob_delta(before.tools_deny, after.tools_deny),
        "parameter_guards": _guard_delta(before.parameter_guards, after.parameter_guards),
        "response_guards": _guard_delta(
            before.response_guards, after.response_guards, noun="fields"
        ),
        "fields_changed": sorted(
            name
            for name in type(before).model_fields
            if name not in ("tools_allow", "tools_deny", "parameter_guards", "response_guards")
            and getattr(before, name) != getattr(after, name)
        ),
    }
    return {key: value for key, value in candidate.items() if value}


def _profile_delta(before: Profile, after: Profile) -> dict[str, Any]:
    """What changed on one profile. Empty dict means nothing did."""
    candidate: dict[str, Any] = {
        "backends_added": sorted(set(after.backends) - set(before.backends)),
        "backends_removed": sorted(set(before.backends) - set(after.backends)),
        "backends_changed": {
            name: delta
            for name in sorted(set(before.backends) & set(after.backends))
            if (delta := _backend_delta(before.backends[name], after.backends[name]))
        },
        "fields_changed": sorted(
            name
            for name in type(before).model_fields
            if name not in ("name", "backends") and getattr(before, name) != getattr(after, name)
        ),
    }
    return {key: value for key, value in candidate.items() if value}


def _compression_surface(profiles: dict[str, Profile]) -> set[tuple[str, bool]]:
    """The (url, compresses_descriptions) pairs description compression walks.

    Re-arming compression is worth a fan-out only when this set moved.
    ``precompress_all`` deduplicates by URL and ``_find_uncached`` skips every
    description already cached, so a tools_deny edit would cost one tools/list
    per compressing backend and buy nothing.
    """
    return {
        (backend.url, backend.compresses_descriptions)
        for profile in profiles.values()
        for backend in profile.backends.values()
        if backend.is_remote
    }


def _unapplied(active: ActiveConfig, new_config: GatewayConfig) -> list[str]:
    """Name every edit in the new file that a reload cannot put into force.

    These are the sections bound into route closures at startup. Reporting
    success over one of them would recreate exactly the failure this tool
    exists to end: a validated edit that changed nothing, believed.
    """
    notes: list[str] = []
    current = active.config

    if new_config.llm_providers != current.llm_providers:
        notes.append(
            "llm_providers changed: the /llm proxy binds its provider set at "
            "startup — restart to apply (per-profile llm_keys DID reload)"
        )
    if new_config.matrix != current.matrix:
        notes.append(
            "matrix section changed: the upstream and the route are bound at "
            "startup — restart to apply"
        )
    if not active.alert_route_registered and any(
        p.alert_ingress is not None for p in new_config.profiles.values()
    ):
        notes.append(
            "alert_ingress added but /alert was not registered at "
            "startup (no profile had one) — restart to serve it"
        )
    if not active.matrix_route_registered and any(
        p.matrix_ingress is not None for p in new_config.profiles.values()
    ):
        notes.append(
            "matrix_ingress added but /matrix is off (matrix.enabled) — "
            "restart with it enabled to serve it"
        )
    if not active.oauth_route_registered and any(
        _uses_oauth_proxy(p) for p in new_config.profiles.values()
    ):
        notes.append(
            "oauth.enabled added but no OAuth proxy was built at startup "
            "(no profile used it, or the client credentials were unset) — "
            "restart to serve it"
        )
    if not active.egress_listener_configured and any(
        p.client_egress is not None for p in new_config.profiles.values()
    ):
        notes.append(
            "client_egress added but its listener was not started (no profile "
            "had one at startup) — restart to serve it"
        )
    if not active.git_route_registered and new_config.git_remotes:
        notes.append(
            "git_remotes added but /git was not registered at startup (the "
            "file had none) — restart to serve it"
        )
    if not active.egress_route_registered and new_config.egress_upstreams:
        notes.append(
            "egress_upstreams added but /egress was not registered at startup "
            "(the file had none) — restart to serve it"
        )
    notes.extend(_unapplied_delegated(current, new_config))
    for name, profile in sorted(new_config.profiles.items()):
        notes.extend(_unapplied_proxy_oauth_for(current.profiles.get(name), profile, name))
    notes.extend(_unapplied_bridges(current, new_config))
    return notes


def _unapplied_bridges(current: GatewayConfig, new_config: GatewayConfig) -> list[str]:
    """Name the profiles whose bridges moved (``matrix_bridge`` or
    ``bridges``, #483): a bridge binds its endpoints at startup, so a reload
    validates the edit and applies none."""

    def bridges_of(config: GatewayConfig, name: str) -> Any:
        # A profile added or removed with no bridges moved no bridge.
        profile = config.profiles.get(name)
        return {} if profile is None else profile.channel_bridges()

    moved = sorted(
        name
        for name in set(current.profiles) | set(new_config.profiles)
        if bridges_of(current, name) != bridges_of(new_config, name)
    )
    if not moved:
        return []
    return [f"bridges changed for {moved}: restart to apply"]


def _uses_oauth_proxy(profile: Profile) -> bool:
    """True when a profile needs the built-in proxy rather than an external IdP."""
    oauth = profile.oauth
    return oauth is not None and oauth.enabled and oauth.issuer is None


def _unapplied_delegated(current: GatewayConfig, new_config: GatewayConfig) -> list[str]:
    """Report delegated-mode edits a reload cannot put into force.

    A delegated profile's verifier and advertised issuer are built once at
    startup and bound into the OAuthContext the route closures hold, exactly
    like llm_providers. Editing `issuer` or `audience_env` — or adding a
    delegated profile outright — validates cleanly and changes nothing, which
    is the silent no-op this whole function exists to prevent.

    `allowed_emails` and `allowed_subjects` are deliberately absent: they are
    read from the profile on every request, so they DO apply live. Those are
    the keys an operator edits under pressure, and they keep working.
    """
    notes: list[str] = []
    for name, profile in sorted(new_config.profiles.items()):
        notes.extend(_unapplied_delegated_for(current.profiles.get(name), profile, name))
    return notes


def _unapplied_delegated_for(before: Profile | None, after: Profile, name: str) -> list[str]:
    """The delegated-mode note for one profile, if it has one.

    Shared by the operator and agent paths so the two scopes cannot disagree
    about what a reload did and did not put into force.
    """
    new_oauth = after.oauth
    if new_oauth is None or new_oauth.issuer is None:
        return []
    old_oauth = before.oauth if before is not None else None
    if old_oauth is None or old_oauth.issuer is None:
        return [
            (
                f"profile {name!r} now delegates OAuth to {new_oauth.issuer} but no "
                "verifier was built for it at startup — restart to serve it"
            )
        ]
    if (old_oauth.issuer, old_oauth.audience_env) != (new_oauth.issuer, new_oauth.audience_env):
        return [
            (
                f"profile {name!r} changed oauth.issuer/audience_env: the verifier "
                "and the advertised authorization server are bound at startup — "
                "restart to apply"
            )
        ]
    return []


#: The proxy-mode ``oauth`` fields the built-in proxy reads once, at startup:
#: the provisioned clients, the redirect allowlist every self-registering
#: client is checked against, and the set of resources ``/authorize`` accepts
#: and binds tokens to. ``allowed_emails`` and ``allowed_subjects`` are
#: missing on purpose: they are read per request and do apply live.
PROXY_OAUTH_STARTUP_FIELDS = (
    "enabled",
    "client_id",
    "client_secret_env",
    "client_redirect_uris",
    "allowed_redirect_uris",
)


def _unapplied_proxy_oauth_for(before: Profile | None, after: Profile, name: str) -> list[str]:
    """The restart note for a proxy-mode ``oauth`` edit, if there is one.

    A reload validated these and reported success, and none of them moved
    until the next restart (#298). Shared by the operator and agent paths,
    like ``_unapplied_delegated_for``.
    """
    old = before.oauth if before is not None else None
    new = after.oauth
    if old is None and new is None:
        return []
    if getattr(old, "issuer", None) is not None or getattr(new, "issuer", None) is not None:
        return []  # delegated: _unapplied_delegated_for owns that note
    moved = sorted(
        field
        for field in PROXY_OAUTH_STARTUP_FIELDS
        if getattr(old, field, None) != getattr(new, field, None)
    )
    if not moved:
        return []
    return [
        (
            f"profile {name!r} changed oauth {', '.join(moved)}: the OAuth proxy "
            "binds its clients, redirect URIs and resources at startup — restart to apply"
        )
    ]


AGENT_SCOPE_NOTE = (
    "agent scope — only this profile's section was applied; other profiles "
    "and gateway-wide settings need an operator-scope reload"
)


def _profile_compression_surface(profile: Profile) -> set[tuple[str, bool]]:
    """One profile's slice of the compression surface."""
    return {
        (backend.url, backend.compresses_descriptions)
        for backend in profile.backends.values()
        if backend.is_remote
    }


def _hold_perimeter_fields(before: Profile, after: Profile) -> list[str]:
    """Carry operator-only scan-view settings across an AGENT reload.

    An agent may retune its own performance — the sampling budget, the
    coverage floor, the deadline. It may not reshape its own perimeter, and
    its ``defense`` block (modes, enforcement, audit, judge) is perimeter.
    ``extractor`` decides how much of a payload is read at all, so an agent
    able to set it could narrow what gets scanned on content an operator meant
    to be read in full. The agent does not control profiles.yaml, but it does
    control when a reload happens, and "cannot write the file" is a weaker
    guarantee than "cannot apply the field".

    The held values are reported back, so an operator whose edit did not take
    effect is told rather than left to discover it.
    """
    held = _hold_preprocess_floor(before, after)
    # The whole defense block is held, not just the loosening directions
    # (#298). modes, enforcement, the L2 threshold, the audit switch and the
    # judging model each have a weaker setting, and "tighten only" would need
    # an order on every one of them, kept in step with every field added
    # later. An agent that wants a stricter policy asks the operator, who can
    # apply it in one reload.
    for field_name in type(after.defense).model_fields:
        old = getattr(before.defense, field_name)
        if old != getattr(after.defense, field_name):
            setattr(after.defense, field_name, old)
            held.append(f"defense.{field_name}")
    # Five blocks are perimeter end to end, so each is held whole: the bridge's
    # plaintext side (#162); where the agent's client may be tunnelled (#442);
    # which repositories and branches it may push to (#453); which HTTP
    # destinations, methods and paths it may reach (#511); and which calls are
    # judged before they leave (#456). llm_keys is not held and git/egress_http
    # are: a key buys model calls, while one more pattern is one more place a
    # talked-round agent can send to.
    for block in ("matrix_bridge", "client_egress", "git", "egress_http", "guarded_execution"):
        if getattr(after, block) != getattr(before, block):
            setattr(after, block, getattr(before, block))
            held.append(block)
    held.extend(_hold_matrix_networks(before, after))
    b = before.matrix_ingress
    a = after.matrix_ingress
    if b is None or a is None:
        return held
    for field_name in type(a.preprocess).model_fields:
        if field_name in PREPROCESS_AGENT_FIELDS:
            continue
        old = getattr(b.preprocess, field_name)
        if old != getattr(a.preprocess, field_name):
            setattr(a.preprocess, field_name, old)
            held.append(f"matrix_ingress.preprocess.{field_name}")
    return held


def _hold_matrix_networks(before: Profile, after: Profile) -> list[str]:
    """Hold an agent's own Matrix proxy networks, which are its credential.

    The caller's address picks the profile (#330), so an agent able to add,
    drop or widen its own ``source_networks`` could answer for an address
    the operator never gave it.
    """
    if (after.matrix_ingress is None) != (before.matrix_ingress is None):
        after.matrix_ingress = before.matrix_ingress
        return ["matrix_ingress"]
    if before.matrix_ingress is None or after.matrix_ingress is None:
        return []
    if after.matrix_ingress.source_networks == before.matrix_ingress.source_networks:
        return []
    after.matrix_ingress.source_networks = before.matrix_ingress.source_networks
    return ["matrix_ingress.source_networks"]


def _lost_destination_rules(before: Profile, after: Profile) -> list[str]:
    """The ``destination_params`` rules an agent reload would remove, as ``tool:param``.

    ``destination_params`` is what records who a comms tool was pointed at
    (#266). Two checks, both needed:

    - Profile-wide, as a multiset: whatever the backends are renamed or
      repointed to, every (tool, param) pair must still be there, as many
      times as before.
    - Per backend: one that keeps its name or its URL is the same service,
      so its own rules must stay on it. Without this, moving a rule onto a
      dummy backend passes the count and leaves the real one unaudited.

    A backend renamed AND repointed has no identity left to check, so it is
    held by the count alone. New rules are free to add.

    Args:
        before: The caller's profile as it runs now.
        after: The same profile as the file on disk would make it.

    Returns:
        Every lost rule as ``tool:param``, sorted. Empty means the reload
        keeps every rule, and the caller refuses the reload otherwise.
    """

    def rules(profile: Profile) -> Counter[tuple[str, str]]:
        return Counter(
            pair for b in profile.backends.values() for pair in b.destination_params.items()
        )

    lost = {f"{tool}:{param}" for tool, param in rules(before) - rules(after)}
    by_url = {b.url: b for b in before.backends.values()}
    for name, backend in after.backends.items():
        old = before.backends.get(name) or by_url.get(backend.url)
        for tool, param in (old.destination_params if old else {}).items():
            if backend.destination_params.get(tool) != param:
                lost.add(f"{tool}:{param}")
    return sorted(lost)


def _hold_floor(
    label: str, floor: Sequence[str], new: Any, inherited: Sequence[str], ceiling: Sequence[str]
) -> list[str]:
    """Raise one ``required`` back to at least ``floor``, and keep its processors.

    ``required`` None inherits ``inherited``; unsetting a tool's floor is
    lowering it when the profile's is weaker.
    """
    effective = inherited if new.required is None else new.required
    if not [n for n in floor if n not in effective]:
        return []
    new.required = [*floor, *(n for n in effective if n not in floor)]
    processors = ceiling if new.processors is None else new.processors
    missing = [n for n in new.required if n not in processors]
    if missing:
        new.processors = [*processors, *missing]
    return [f"{label}.required", *([f"{label}.processors"] if missing else [])]


def _hold_preprocess_floor(before: Profile, after: Profile) -> list[str]:
    """An agent may not lower its own pre-processor floor (#183).

    ``required`` is what the agent's ``trentina_preprocess`` cannot remove;
    a reload that could remove it would be the same argument by another road.
    That includes a NEW tool override: its ``required`` replaces the
    profile's, so it is held to the floor the tool had before.
    """
    held = _hold_floor(
        "preprocess",
        before.preprocess.required,
        after.preprocess,
        [],
        after.preprocess.processors,
    )
    for name, backend in after.backends.items():
        old_backend = before.backends.get(name)
        # A deleted override would drop its floor to the profile's: keep it.
        for tool, dropped in (old_backend.preprocess_tools if old_backend else {}).items():
            if dropped.required is not None and tool not in backend.preprocess_tools:
                backend.preprocess_tools[tool] = dropped
                held.append(f"backends.{name}.preprocess_tools.{tool}")
        for tool, override in backend.preprocess_tools.items():
            old = old_backend.preprocess_tools.get(tool) if old_backend else None
            floor = (
                old.required
                if old is not None and old.required is not None
                else before.preprocess.required
            )
            held += _hold_floor(
                f"backends.{name}.preprocess_tools.{tool}",
                floor,
                override,
                after.preprocess.required,
                after.preprocess.processors,
            )
    return held


async def _apply_own_profile(
    scope: CallerScope,
    registry: dict[str, Profile],
    new_config: GatewayConfig,
) -> dict[str, Any]:
    """Agent path: put the caller's own section into force, and nothing else.

    Nothing here touches ``replace_active_config``, the session TTL or the
    session cap: those are gateway-wide, and an agent applying them would be
    changing the terms every other profile runs under.
    """
    name = scope.label
    before = registry.get(name)
    after = new_config.profiles.get(name)

    if before is None or after is None:
        return {
            "reloaded": False,
            "scope": name,
            "error": (
                "this profile is not in the file on disk — an operator reload "
                "or a restart applies a profile that was added or removed"
            ),
        }
    if before.role != after.role:
        return {
            "reloaded": False,
            "scope": name,
            "error": (
                "this profile's role changed on disk — a role change is "
                "applied by an operator reload or a restart, never by the "
                "profile it promotes"
            ),
        }

    if before.tripwires() != after.tripwires():
        # Refused, and in words that name nothing (#357): a decoy the watched
        # agent could drop, or be told about, by reloading is not one.
        return {
            "reloaded": False,
            "scope": name,
            "error": (
                "this profile changed on disk in a way an operator reload or a "
                "restart applies, never the profile itself"
            ),
        }

    lost = _lost_destination_rules(before, after)
    if lost:
        # Refused, not held: a hold must pick which backend a rule lands on,
        # and a rename plus a repoint leaves no right answer (#266).
        return {
            "reloaded": False,
            "scope": name,
            "error": (
                "this reload removes destination_params rules "
                f"({', '.join(lost)}); an operator reload or a restart applies that"
            ),
        }
    held = _hold_perimeter_fields(before, after)
    delta = _profile_delta(before, after)
    registry[name] = after
    invalidated = invalidate_profile_cache(name)
    if _profile_compression_surface(before) != _profile_compression_surface(after):
        retrigger_compression()
    notified = await session_registry.broadcast_tools_changed(name)

    # An agent can edit its own oauth block, and the delegated parts of it are
    # bound at startup exactly as they are on the operator path. Reporting
    # "reloaded" over a changed issuer would be the same silent no-op, just
    # scoped to one profile — so say so here too.
    restart_required = [
        *_unapplied_delegated_for(before, after, name),
        *_unapplied_proxy_oauth_for(before, after, name),
    ]

    logger.warning(
        "gateway: profile %s reloaded its own section — %d field group(s) moved",
        name,
        len(delta),
    )
    result: dict[str, Any] = {
        "reloaded": True,
        "scope": name,
        "applied": [name],
        "changes": {name: delta} if delta else {},
        "caches_invalidated": [name] if invalidated else [],
        "sessions_notified": notified,
        "note": AGENT_SCOPE_NOTE,
    }
    # Two different reasons an agent's own edit may not have taken effect, so
    # they are reported under separate keys rather than one flat list: the
    # settings only an operator may move, and the ones nobody can move without
    # a restart because they are bound into a route closure at startup.
    not_applied: dict[str, Any] = {}
    if held:
        not_applied["operator_only"] = held
        not_applied["reason"] = (
            "these settings shape this profile's perimeter; an "
            "operator reload or a restart applies them"
        )
    if restart_required:
        not_applied["restart_required"] = restart_required
    if not_applied:
        result["not_applied"] = not_applied
    return result


async def reload_profiles() -> dict[str, Any]:
    """Re-read profiles.yaml and put it into force without a restart.

    Returns:
        A result dict. On success ``scope`` says what was reloaded: the
        caller's profile name for an agent, which applied and reports only its
        own section, or "gateway" for an operator, which applied the whole
        file and reports every profile that moved.

        ``reloaded`` is False with an ``error`` when the caller is unknown, or
        when the file did not validate — in which case the running config is
        untouched. That refusal is itself scoped: an operator gets the parse
        error, the ``path`` it failed to load and the ``profiles`` currently
        serving, while an agent gets ``AGENT_RELOAD_REFUSED`` alone, because
        the parse error quotes a file it cannot read and the roster it does
        not hold is not its business (#292).
    """
    active = get_active_config()
    if active is None:
        return {"reloaded": False, "error": "gateway not initialized"}

    try:
        scope = require_caller("reload_profiles")
    except ScopeError as exc:
        logger.warning("reload_profiles refused: %s", exc_kind(exc))
        return {"reloaded": False, "error": str(exc)}

    path = active.path
    before = dict(active.config.profiles)

    try:
        new_config = load_profiles(path)
        # Startup runs this via register_llm_routes; a reload has to run it
        # itself or a profile could name a provider the proxy has never heard
        # of, and the dangling reference would surface as a runtime 502
        # instead of a refused reload.
        validate_profile_llm_keys(active.llm_providers, new_config.profiles)
    except Exception as exc:
        # Deliberately everything: whatever went wrong reading or validating
        # the file, the running config is the one that keeps serving.
        #
        # The journal gets where, never what (#292): load_profiles' message
        # quotes the file — other profiles' names and fields, a YAML snippet,
        # pydantic's input — and the journal is agent-readable. An agent gets
        # a constant for the same reason; the operator, who holds the file,
        # gets the message.
        logger.warning(
            "gateway: profile reload REFUSED from %s: %s at %s",
            path,
            exc_kind(exc),
            exc_where(exc),
        )
        refusal: dict[str, Any] = {
            "reloaded": False,
            "error": str(exc) if scope.is_operator else AGENT_RELOAD_REFUSED,
            "note": "running configuration left unchanged",
        }
        if scope.is_operator:
            refusal["path"] = str(path)
            refusal["profiles"] = sorted(before)
        return refusal

    if not scope.is_operator:
        return await _apply_own_profile(scope, active.config.profiles, new_config)

    after = new_config.profiles
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = {
        name: delta
        for name in sorted(set(before) & set(after))
        if (delta := _profile_delta(before[name], after[name]))
    }

    # Read the startup wiring facts before the swap replaces the holder.
    not_applied = _unapplied(active, new_config)

    # The swap. Every route handler, the compression module and the
    # circuit-breaker wiring hold THIS dict object and read it per request, so
    # refilling it in place is what makes the new config live everywhere at
    # once. Binding the name to a fresh dict would reach none of them.
    registry = active.config.profiles
    registry.clear()
    registry.update(new_config.profiles)
    session_registry.session_ttl = new_config.session_ttl_seconds
    session_registry.max_sessions_per_profile = new_config.max_sessions_per_profile
    replace_active_config(replace(new_config, profiles=registry))
    # A reload can promote, demote or re-key the operator, which moves every
    # centralized model call to a new identity. Say where they run now.
    log_service_identity(registry)

    # Every profile's descriptions are judged by the operator's model. When
    # that moves, every aggregate holds verdicts from the old judge, not only
    # the aggregates of profiles whose own section changed.
    judge_moved = judge_of(find_operator(before)) != judge_of(find_operator(after))
    stale = sorted({*after, *removed}) if judge_moved else [*added, *removed, *changed]
    invalidated = [name for name in stale if invalidate_profile_cache(name)]
    if _compression_surface(before) != _compression_surface(after):
        retrigger_compression()

    # The pinned-connection pool (#511, Phase 2): close the warm clients of a
    # profile whose config changed or was dropped, so they do not outlive the
    # config that named them. An unchanged profile keeps its clients — and any
    # /llm stream in flight — which is the point of pooling the hot path.
    for name in {*changed, *removed}:
        await close_profile(name)

    dropped_sessions = sum(
        session_registry.delete_session(session.session_id)
        for name in removed
        for session in session_registry.get_sessions_for_profile(name)
    )
    notified = {
        name: await session_registry.broadcast_tools_changed(name)
        for name in (sorted(after) if judge_moved else [*added, *changed])
    }

    logger.warning(
        "gateway: profiles reloaded from %s by %s — %d added, %d removed, %d changed",
        path,
        scope.label,
        len(added),
        len(removed),
        len(changed),
    )
    return {
        "reloaded": True,
        "scope": "gateway",
        "path": str(path),
        "profiles": {
            "added": added,
            "removed": removed,
            "changed": sorted(changed),
            "unchanged": sorted((set(before) & set(after)) - set(changed)),
        },
        "changes": changed,
        "caches_invalidated": invalidated,
        "service_identity_moved": judge_moved,
        "sessions_notified": {k: v for k, v in notified.items() if v},
        "sessions_dropped": dropped_sessions,
        "not_applied": not_applied,
    }
