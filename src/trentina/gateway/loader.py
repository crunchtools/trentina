"""YAML profile loader with env-var token resolution.

Fails closed: any missing env var, schema violation, or YAML parse error
raises `ProfileConfigError` at load time. The server refuses to expose
gateway routes if loading fails.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import yaml
from pydantic import SecretStr, ValidationError

from .. import logsafe
from ..channels import Channel
from .drivers import build_preprocessors
from .errors import ProfileConfigError
from .filter import filter_tools
from .profile import (
    GIT_REMOTE_NAME_RE,
    HONEYTOKEN_MIN_CHARS,
    AlertIngressConfig,
    GitRemote,
    MatrixIngressConfig,
    Profile,
    is_matrix_user_id,
)
from .transform import resolve

if TYPE_CHECKING:
    import ipaddress


@dataclass(frozen=True)
class GatewayConfig:
    """Parsed gateway configuration with typed accessors."""

    profiles: dict[str, Profile]
    llm_providers: dict[str, Any] = field(default_factory=dict)
    matrix: dict[str, Any] = field(default_factory=dict)
    git_remotes: dict[str, GitRemote] = field(default_factory=dict)
    session_ttl_seconds: float = 300.0
    max_sessions_per_profile: int = 10


logger = logging.getLogger(__name__)

_ENV_REF_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
_URL_SAFE_VALUE_RE = re.compile(r"[A-Za-z0-9._~%-]+")


def _expand_env_refs(value: str, *, context: str) -> str:
    """Substitute ${VAR} references in a header value or URL from os.environ.

    Fails closed (raises ProfileConfigError) if a referenced var is unset or
    empty — a missing auth secret must not silently become an unauthenticated
    backend call.
    """

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        resolved = read_secret_env(var_name)
        if not resolved:
            raise ProfileConfigError(
                f"{context}: env var {var_name} (or {var_name}"
                f"{_ENV_FILE_SUFFIX}) referenced but not set or empty"
            )
        return resolved

    return _ENV_REF_RE.sub(_replace, value)


def _build_profile(name: str, body: Any) -> Profile:
    """Validate one profile entry and resolve its secrets from the environment.

    Resolves the bearer token from `auth.bearer_token_env`, the provisioned
    OAuth client secret from `oauth.client_secret_env`, the delegated-mode
    expected audience from `oauth.audience_env`, and expands any ${VAR}
    references in backend headers. All fail closed on a missing env var.

    Each `llm_keys` entry supplies its secret one of two ways: `api_key`
    inline in the YAML, or `api_key_env` naming an environment variable.
    An inline key is taken as-is; otherwise the env var is required and an
    entry providing neither is a configuration error.
    """
    if not isinstance(body, dict):
        raise ProfileConfigError(
            f"Profile {name!r}: body must be a mapping, got {type(body).__name__}"
        )
    try:
        profile = Profile(name=name, **body)
    except ValidationError as exc:
        raise ProfileConfigError(f"Profile {name!r}: {exc}") from exc

    _resolve_bearer_token(name, profile)
    for token, planted in profile.honeytokens.items():
        planted.value = _require_env(name, planted.value_env, f"honeytoken {token!r}")
        value = planted.value.get_secret_value()
        if len(value) < HONEYTOKEN_MIN_CHARS:
            raise ProfileConfigError(
                f"Profile {name!r}: honeytoken {token!r} is shorter than "
                f"{HONEYTOKEN_MIN_CHARS} characters and would match by chance"
            )
        # Arguments are searched as JSON, where these two are written escaped.
        if not value.isprintable() or set(value) & {'"', "\\"}:
            raise ProfileConfigError(
                f"Profile {name!r}: honeytoken {token!r} must be printable, with "
                "no double quote or backslash"
            )
    _resolve_oauth_client_secret(name, profile)
    _resolve_oauth_audience(name, profile)
    _resolve_llm_key_secrets(name, profile)
    for remote, grant in profile.git.items():
        grant.token = _require_env(name, grant.token_env, f"git.{remote} token")
    _expand_backend_env_refs(name, profile)
    _check_drivers(name, profile)
    _check_destination_params(name, profile)
    _resolve_matrix_bridge_secrets(name, profile)
    if profile.alert_ingress is not None:
        _resolve_alert_ingress_secrets(name, profile.alert_ingress)

    if profile.matrix_ingress is not None:
        _resolve_matrix_ingress_secrets(name, profile.matrix_ingress)

    return profile


def _check_destination_params(name: str, profile: Profile) -> None:
    """Refuse a ``destination_params`` entry for a tool the backend never serves.

    The allowlist is known at load; the backend's tool list is not. An entry
    the allowlist filters out is an audit rule that can never fire, which is
    a typo the operator should hear about now, not after an incident.
    """
    for backend_name, backend in profile.backends.items():
        for tool in backend.destination_params:
            if not filter_tools([{"name": tool}], backend):
                raise ProfileConfigError(
                    f"Profile {name!r}: backends.{backend_name}.destination_params."
                    f"{tool}: the tool is not allowed on this backend"
                )


def _check_drivers(name: str, profile: Profile) -> None:
    """Resolve every driver the profile names, and discard the result.

    Building them here is the whole point: ``build_preprocessors`` is the only
    place the channel and kind locks live, and a lock that fires on the first
    request that happens to use the driver is not a lock, it is a latent
    outage. This makes them fail at startup, which is where
    ``gateway/drivers.py`` claims they fail.

    Every channel is checked, because each names processors and each can name
    the wrong one.
    """
    build_preprocessors(profile.preprocess, channel=Channel.TOOL, profile_name=name)
    for backend_name, backend in profile.backends.items():
        build_preprocessors(
            backend.preprocess_tool_descriptions,
            channel=Channel.TOOL_DESCRIPTION,
            profile_name=f"{name}:{backend_name}",
        )
        for tool_name, override in backend.preprocess_tools.items():
            if override.processors is None and override.required is None:
                continue
            label = f"{name}:{backend_name}:{tool_name}"
            try:
                cfg = resolve(profile, backend, tool_name)
            except ValidationError as exc:
                # A tool override that narrows processors below the profile's
                # required floor. Refused here, not on the first call.
                raise ProfileConfigError(f"Profile {label!r}: {exc}") from exc
            build_preprocessors(cfg, channel=Channel.TOOL, profile_name=label)
    if profile.matrix_ingress is not None:
        # Built without its key provider: that needs the network and belongs
        # on the request path. What is checked here is the name, the channel
        # and the kind, none of which depend on the keys.
        build_preprocessors(
            profile.matrix_ingress.preprocess,
            channel=Channel.MATRIX,
            profile_name=name,
        )
    if profile.matrix_bridge is not None:
        build_preprocessors(
            profile.matrix_bridge.preprocess,
            channel=Channel.MATRIX_BRIDGE,
            profile_name=name,
        )


def _resolve_matrix_bridge_secrets(name: str, profile: Profile) -> None:
    """Resolve an enabled bridge's four tokens, failing closed on any gap.

    A disabled block resolves nothing: nothing reads its tokens, and demanding
    them would make an operator provision secrets to write down a plan.
    """
    bridge = profile.matrix_bridge
    if bridge is None or not bridge.enabled:
        return
    bridge.bridge_token = _require_env(name, bridge.bridge_token_env, "matrix_bridge bridge token")
    bridge.ingress_token = _require_env(
        name, bridge.ingress_token_env, "matrix_bridge ingress token"
    )
    bridge.local.as_token = _require_env(name, bridge.local.as_token_env, "matrix_bridge as_token")
    bridge.local.hs_token = _require_env(name, bridge.local.hs_token_env, "matrix_bridge hs_token")


def _resolve_bearer_token(name: str, profile: Profile) -> None:
    """Resolve the profile's static bearer token, if it declares one.

    An OAuth-only profile has no `auth` block at all (0.15.0), and the Profile
    validator has already refused anything with no authentication whatsoever,
    so a missing block here means OAuth — not a misconfiguration to fail on.
    """
    if profile.auth is None:
        return
    profile.auth.bearer_token = _require_env(
        name,
        profile.auth.bearer_token_env,
        "bearer token",
    )


def _resolve_oauth_client_secret(name: str, profile: Profile) -> None:
    """Resolve a provisioned OAuth client's secret from the environment.

    OAuthConfig already refuses a half-declared client, so reaching here with a
    client_secret_env means client_id and the redirect URIs are present too.
    Fails closed on an unset var: a provisioned client whose secret resolved to
    empty would be stored with no secret, and the SDK's ClientAuthenticator
    rejects exactly that as misconfigured — better to say so at load.
    """
    oauth = profile.oauth
    if oauth is None or oauth.client_secret_env is None:
        return
    oauth.client_secret = _require_env(
        name,
        oauth.client_secret_env,
        "OAuth client secret",
    )


def _resolve_oauth_audience(name: str, profile: Profile) -> None:
    """Resolve a delegated profile's expected token audience.

    Fails closed on an unset var. An empty audience would leave the verifier
    accepting a token minted for ANY OAuth client, which is the one thing
    delegated mode must never do — better to refuse to start.

    Resolved as a plain str, not SecretStr: an OAuth client ID is not a secret,
    it is compared against the `aud` claim, and it appears in diagnostics when
    a token is refused. Wrapping it would make every comparison fail silently.
    """
    oauth = profile.oauth
    if oauth is None or oauth.audience_env is None:
        return
    oauth.audience = _require_env(
        name,
        oauth.audience_env,
        "OAuth audience",
    ).get_secret_value()


def _resolve_llm_key_secrets(name: str, profile: Profile) -> None:
    for provider_name, override in profile.llm_keys.items():
        if override.api_key.get_secret_value():
            continue
        if not override.api_key_env:
            raise ProfileConfigError(
                f"Profile {name!r} llm_keys.{provider_name}: must provide "
                f"either 'api_key' or 'api_key_env'"
            )
        key_value = read_secret_env(override.api_key_env)
        if not key_value:
            raise ProfileConfigError(
                f"Profile {name!r} llm_keys.{provider_name}: env var "
                f"{override.api_key_env} not set or empty"
            )
        override.api_key = SecretStr(key_value)


def _expand_backend_url(name: str, backend_name: str, url: str) -> str:
    """Expand ${VAR} in a backend URL's path and query only (#268).

    A token-in-URL backend keeps its credential in the environment, not in
    profiles.yaml. Logs print a backend as ``safe_url(url)``, which keeps the
    host, so a reference in the scheme, userinfo, host or port would log the
    secret: refuse it there.
    """
    context = f"Profile {name!r} backend {backend_name!r} url"
    first_ref = _ENV_REF_RE.search(url)
    if first_ref is None:
        return url
    parts = urlsplit(url)
    authority_end = len(f"{parts.scheme}://{parts.netloc}")
    if (
        not parts.scheme
        or not url.startswith(f"{parts.scheme}://")
        or (first_ref.start() < authority_end)
    ):
        raise ProfileConfigError(f"{context}: ${{VAR}} is allowed only in the path or query")
    expanded = _expand_env_refs(url, context=context)
    # Inserted verbatim, so a value must not restructure the URL: `&`, `#`,
    # `/` or `?` in a token would move it into another component.
    for match in _ENV_REF_RE.finditer(url):
        if not _URL_SAFE_VALUE_RE.fullmatch(read_secret_env(match.group(1))):
            raise ProfileConfigError(
                f"{context}: env var {match.group(1)} holds characters outside "
                "[A-Za-z0-9._~%-]; percent-encode it"
            )
    return expanded


def _expand_backend_env_refs(name: str, profile: Profile) -> None:
    for backend_name, backend in profile.backends.items():
        backend.url = _expand_backend_url(name, backend_name, backend.url)
        if backend.headers:
            backend.headers = {
                key: _expand_env_refs(
                    val,
                    context=f"Profile {name!r} backend {backend_name!r} header {key!r}",
                )
                for key, val in backend.headers.items()
            }


_ENV_FILE_SUFFIX = "_FILE"

#: Every env var a profile resolved a secret from, across the startup load and
#: every reload since. ``reload_profiles`` reads them again, so the startup
#: scrub (``gateway/envscrub.py``) must never pop one of these.
_profile_env_names: set[str] = set()
# Every name read_secret_env was asked for, recorded or not: the startup
# posture check asks which of them arrived in the environment (#268).
_secret_env_names: set[str] = set()


def profile_env_names() -> frozenset[str]:
    """The env var names profiles have resolved secrets from (see ``read_secret_env``)."""
    return frozenset(_profile_env_names)


def secret_env_names() -> frozenset[str]:
    """Every env var name a secret has been read from, by any caller."""
    return frozenset(_secret_env_names)


def _warn_on_loose_mode(path: Path, file_var: str) -> None:
    """Warn, never fail, when a secret file is group- or world-readable.

    Constitution Section X: a runtime warning, not a hard error. Refusing to
    start over a permission bit would brick a deploy for something the
    operator can fix in place while the service keeps running.
    """
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        # The env var NAME and the mode, never the path. An operator can
        # resolve the path from the name, and a log line that points at where
        # the secrets live is a small disclosure that travels to the
        # centralized collector and sits there for 90 days. CodeQL flags the
        # path form as clear-text logging of sensitive data, and on this one
        # it is right for the right reason.
        logger.warning(
            "%s names a secret file whose mode is %04o — more permissive than 0600",
            file_var,
            mode,
        )


def read_secret_env(env_var: str, *, record: bool = True) -> str:
    """Resolve a secret from ``FOO``, or from the file named by ``FOO_FILE``.

    The ``_FILE`` indirection is the preferred shape for container
    deployments — podman secrets, Kubernetes secret volumes, systemd
    ``LoadCredential=`` — because the value lands in a mode-0600 file instead
    of in ``/proc/<pid>/environ``, which anything that can inspect the
    container can read.

    ``_FILE`` takes precedence when both are set, per the crunchtools
    mcp-server profile. That direction is deliberate: a mounted secret is the
    explicit, deployment-time answer, and an env var inherited from a shell or
    a stale unit file must not quietly outrank it.

    Returns "" when neither is set, leaving "is this required?" to the caller.
    Raises only when the operator named a file we cannot use — a secret
    pointed at a missing file is a broken deployment, not an absent secret.

    ``record`` notes ``env_var`` as one a profile depends on, so the startup
    scrub leaves it for ``reload_profiles`` to read again. A caller reading a
    startup-only secret (the OAuth signing key) passes False.

    What comes back is held out of every log record (``logsafe.hold``). A
    setting that only shares the ``_FILE`` form, like the bridge's profile
    name, is read with ``read_env_or_file`` instead: holding it cut the name
    from every bridge log line (#344).
    """
    _secret_env_names.add(env_var)
    if record:
        _profile_env_names.add(env_var)
    return _held(read_env_or_file(env_var), env_var)


def read_env_or_file(env_var: str) -> str:
    """The value of ``FOO``, or the contents of the file ``FOO_FILE`` names,
    which wins. Not held and not counted as a secret: see ``read_secret_env``."""
    file_var = f"{env_var}{_ENV_FILE_SUFFIX}"
    path_value = os.environ.get(file_var, "").strip()
    if path_value:
        path = Path(path_value)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProfileConfigError(
                f"{file_var}: cannot read the secret file it names ({exc.strerror or exc})"
            ) from exc
        _warn_on_loose_mode(path, file_var)
        return raw.strip()
    return os.environ.get(env_var, "")


_short_secret_warned: set[str] = set()


def _held(value: str, env_var: str) -> str:
    """``value``, now one no log record can carry (``logsafe.hold``, #341).

    A secret too short to hold is said so once, by name: it cannot be told
    from ordinary text in a log line, which is also why it is no secret.
    """
    held = logsafe.hold(value, env_var, minimum=logsafe.MIN_DECLARED_CHARS)
    if value and not held and env_var not in _short_secret_warned:
        _short_secret_warned.add(env_var)
        logger.warning(
            "%s is under %d characters: too short to redact from logs, and too short a secret",
            env_var,
            logsafe.MIN_DECLARED_CHARS,
        )
    return value


def _require_env(name: str, env_var: str, what: str) -> SecretStr:
    """Read a required secret from the environment, failing closed if absent.

    Shared by every ingress that authenticates by a token-in-env: a missing
    or empty var is a fatal config error, not a silent None.
    """
    value = read_secret_env(env_var)
    if not value:
        raise ProfileConfigError(
            f"Profile {name!r}: {what} env var {env_var} (or "
            f"{env_var}{_ENV_FILE_SUFFIX}) not set or empty"
        )
    return SecretStr(value)


def _resolve_matrix_ingress_secrets(name: str, matrix_ingress: MatrixIngressConfig) -> None:
    decrypt = matrix_ingress.preprocess.decrypt
    if decrypt is not None and decrypt.enabled:
        decrypt.access_token = _require_env(
            name,
            decrypt.access_token_env,
            "matrix decrypt access token",
        )
        decrypt.recovery_key = _require_env(
            name,
            decrypt.recovery_key_env,
            "matrix decrypt recovery key",
        )
        # Decode now, at load, so a mistyped key is a refused start rather
        # than a silent inability to decrypt anything in production. The
        # parity byte in the format exists for exactly this check.
        from ..matrix.recovery_key import RecoveryKeyError, decode_recovery_key

        try:
            decode_recovery_key(decrypt.recovery_key.get_secret_value())
        except RecoveryKeyError as exc:
            raise ProfileConfigError(
                f"Profile {name!r}: {decrypt.recovery_key_env} is not a valid recovery key ({exc})"
            ) from exc


def _resolve_alert_ingress_secrets(name: str, alert_ingress: AlertIngressConfig) -> None:
    alert_ingress.token = _require_env(name, alert_ingress.token_env, "alert_ingress")

    if alert_ingress.forward_secret_env:
        fwd_secret = read_secret_env(alert_ingress.forward_secret_env)
        if not fwd_secret:
            raise ProfileConfigError(
                f"Profile {name!r}: alert_ingress forward_secret_env "
                f"{alert_ingress.forward_secret_env} not set or empty"
            )
        alert_ingress.forward_secret = SecretStr(fwd_secret)


def _check_judges(registry: dict[str, Profile]) -> None:
    """Warn about a profile with no key for the provider its L3 runs on.

    Each gateway ingress binds the calling profile (RT #1505), and
    ``resolve_profile_llm`` refuses to bill any key but the profile's own, so
    such a profile's L3 reports ``l3_unavailable`` and block refuses what it
    judges. Its internal tools always behaved that way; before RT #1505 its
    proxied responses ran unbound on the global key and hid it. A warning,
    not a load error: a config that never set ``llm_keys`` should learn why
    before it stops loading.
    """
    from .service import judge_of

    for name, profile in registry.items():
        provider, _model = judge_of(profile)
        if provider != "ollama" and provider not in profile.llm_keys:
            logger.warning(
                "profile %r judges with provider %r but has no llm_keys.%s: its L3 "
                "will report l3_unavailable; add the key, or set defense.provider "
                "to one it holds",
                name,
                provider,
                provider,
            )


def _check_operator(registry: dict[str, Profile]) -> None:
    """At most one operator, and it must be able to pay for its own work.

    The operator is the gateway's service identity (``service.py``, #138):
    centralized model calls run on its provider and its key. Two operators
    would make "whose identity" a matter of file order again, which is the
    thing #138 removed — so it is a load error, not a tiebreak.

    An operator with no key for its own provider does not fail loudly at call
    time: L3 reports ``l3_unavailable`` on every tool description, and under
    block every tool is quietly withheld from every profile. Refusing the
    file here keeps the running config instead (``reload_profiles``).
    """
    from .service import judge_of

    operators = sorted(name for name, p in registry.items() if p.role == "operator")
    if len(operators) > 1:
        raise ProfileConfigError(
            f"at most one profile may declare role: operator, found {len(operators)}: "
            f"{', '.join(operators)}"
        )
    if not operators:
        return
    operator = registry[operators[0]]
    provider, _model = judge_of(operator)
    if provider != "ollama" and provider not in operator.llm_keys:
        raise ProfileConfigError(
            f"operator profile {operator.name!r} runs the gateway's own model calls on "
            f"provider {provider!r} but has no llm_keys.{provider}; add the key, or set "
            f"defense.provider to one it holds"
        )


def matrix_other_agents(matrix: dict[str, Any]) -> frozenset[str]:
    """``matrix.other_agent_user_ids``: agents the gateway does not bridge (#264).

    Matrix IDs of agents that are not a profile here (Ashigaru, say), treated
    exactly like another bridged profile's ``public_user_id``: their events
    are dropped and no room holding one is relayed into. Absent is empty. A
    malformed list is fatal, and the error counts entries rather than
    echoing them.
    """
    raw = matrix.get("other_agent_user_ids", [])
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        raise ProfileConfigError("matrix.other_agent_user_ids must be a list of Matrix user IDs")
    bad = sum(1 for v in raw if not is_matrix_user_id(v, historical=True))
    if bad:
        raise ProfileConfigError(
            f"matrix.other_agent_user_ids: {bad} entries are not Matrix user IDs"
        )
    return frozenset(raw)


def _check_matrix_networks(registry: dict[str, Profile]) -> None:
    """No two profiles' ``matrix_ingress.source_networks`` overlap (#330).

    The caller's address is the only thing that picks its profile, so an
    address two profiles both claim would be one agent able to act as the
    other, whichever the proxy happened to try first.
    """
    seen: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for name, profile in sorted(registry.items()):
        if profile.matrix_ingress is None:
            continue
        for net in profile.matrix_ingress.source_networks:
            for other, prior in seen:
                if net.version == prior.version and net.overlaps(prior):
                    raise ProfileConfigError(
                        f"Profiles {other!r} and {name!r}: matrix_ingress.source_networks "
                        f"overlap ({prior} and {net}); one agent per network"
                    )
            seen.append((name, net))


def _check_egress_networks(registry: dict[str, Profile]) -> None:
    """No profile's ``client_egress.source_networks`` reach another's (#442).

    The same rule as ``_check_matrix_networks``, for the same reason: the
    address is what picks the profile. It is also held against the other
    profiles' Matrix networks, because one network is one agent whichever
    listener it calls. A profile may use one network for both of its own.
    """
    claims = [
        (name, block.source_networks)
        for name, profile in sorted(registry.items())
        for block in (profile.client_egress, profile.matrix_ingress)
        if block is not None
    ]
    for name, profile in sorted(registry.items()):
        if profile.client_egress is None:
            continue
        for net in profile.client_egress.source_networks:
            for other, prior_nets in claims:
                if other == name:
                    continue
                for prior in prior_nets:
                    if net.version == prior.version and net.overlaps(prior):
                        raise ProfileConfigError(
                            f"Profiles {other!r} and {name!r}: client_egress.source_networks "
                            f"overlap another profile's network ({prior} and {net}); "
                            "one agent per network"
                        )


def _load_git_remotes(section: Any, registry: dict[str, Profile]) -> dict[str, GitRemote]:
    """Parse ``git_remotes`` and hold every profile's ``git`` block to it (#453).

    Checked here, not where the route is registered, so a reload refuses the
    same file a restart would: a grant for a remote nobody configured would
    otherwise be a token loaded for an upstream that does not exist.

    Raises:
        ProfileConfigError: the section is not a mapping, a name or an entry
            does not validate, or a profile names a remote that is not here.
    """
    if section is None:
        section = {}
    if not isinstance(section, dict):
        raise ProfileConfigError("git_remotes must be a mapping of remote name to upstream")
    remotes: dict[str, GitRemote] = {}
    for name, body in section.items():
        if not isinstance(name, str) or not GIT_REMOTE_NAME_RE.match(name):
            raise ProfileConfigError("git_remotes: a remote name must match ^[a-z][a-z0-9-]*$")
        if not isinstance(body, dict):
            raise ProfileConfigError(f"git_remotes.{name}: must be a mapping")
        try:
            remotes[name] = GitRemote(**body)
        except ValidationError as exc:
            reasons = "; ".join(
                f"{'.'.join(map(str, e['loc'])) or 'entry'}: {e['msg']}" for e in exc.errors()
            )
            raise ProfileConfigError(f"git_remotes.{name}: {reasons}") from exc
    for profile_name, profile in sorted(registry.items()):
        for remote in profile.git:
            if remote not in remotes:
                raise ProfileConfigError(
                    f"Profile {profile_name!r} git names remote {remote!r}, "
                    "which is not a git_remotes entry"
                )
    return remotes


def load_profiles(path: Path | str) -> GatewayConfig:
    """Load gateway configuration from YAML.

    Returns a ``GatewayConfig`` with typed accessors for profiles,
    llm_providers, and matrix configuration sections.

    Raises:
        ProfileConfigError: file missing, YAML invalid, schema violated, or
            an env var named in `auth.bearer_token_env` is unset.
    """
    config_path = Path(path)
    if not config_path.is_file():
        raise ProfileConfigError(f"Profiles file not found: {config_path}")

    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileConfigError(f"Cannot read profiles file {config_path}: {exc}") from exc

    try:
        cfg_data: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ProfileConfigError(f"Invalid YAML in {config_path}: {exc}") from exc

    if not isinstance(cfg_data, dict):
        raise ProfileConfigError(f"Profiles file {config_path} must contain a top-level mapping")

    profiles_section = cfg_data.get("profiles")
    if not isinstance(profiles_section, dict) or not profiles_section:
        raise ProfileConfigError(
            f"Profiles file {config_path} must contain a non-empty 'profiles' mapping"
        )

    registry: dict[str, Profile] = {
        name: _build_profile(name, body) for name, body in profiles_section.items()
    }
    _check_operator(registry)
    _check_judges(registry)
    _check_matrix_networks(registry)
    _check_egress_networks(registry)
    git_remotes = _load_git_remotes(cfg_data.get("git_remotes"), registry)

    logger.info(
        "gateway: loaded %d profile(s): %s",
        len(registry),
        ", ".join(sorted(registry)),
    )

    llm_section = cfg_data.get("llm_providers", {})
    matrix_section = cfg_data.get("matrix", {})
    if isinstance(matrix_section, dict):
        matrix_other_agents(matrix_section)  # validated here, bound at startup
    gateway_section = cfg_data.get("gateway", {})
    if not isinstance(gateway_section, dict):
        gateway_section = {}

    return GatewayConfig(
        profiles=registry,
        llm_providers=llm_section if isinstance(llm_section, dict) else {},
        matrix=matrix_section if isinstance(matrix_section, dict) else {},
        git_remotes=git_remotes,
        session_ttl_seconds=float(gateway_section.get("session_ttl_seconds", 300.0)),
        max_sessions_per_profile=int(gateway_section.get("max_sessions_per_profile", 10)),
    )


@dataclass(frozen=True)
class ActiveConfig:
    """What the running gateway loaded, and what it wired at startup.

    ``config.profiles`` is the SAME dict object every route handler, the
    compression module and the circuit-breaker wiring were handed at startup,
    and each of them reads it per request. Mutating that dict in place is
    therefore the whole swap — nothing has to be re-registered. Replacing it
    with a new dict would leave every holder pointing at the old one, which is
    exactly the silent no-op this machinery exists to prevent.

    The remaining fields record what CANNOT be changed by a reload, because
    they were bound into closures when the routes were registered: the LLM
    provider set, and whether the alert, matrix and OAuth routes exist at all.
    A reload compares against them so it can say what it did not apply, instead
    of reporting success over a change that went nowhere. The client-egress
    listener is in this set too: it is a second socket, bound before serving,
    and only when some profile asked for it. OAuth is in this set
    because the provider and its authorization-server routes bind at startup —
    turning ``oauth.enabled`` on for a profile in the YAML and reloading cannot
    conjure a provider that boot did not build. The ``/git`` route (#453) is
    registered only when the file had a ``git_remotes`` section at startup;
    once it is, the remotes and every profile's ``git`` block are read per
    request and so do reload.
    """

    path: Path
    config: GatewayConfig
    llm_providers: dict[str, Any]
    alert_route_registered: bool
    matrix_route_registered: bool
    oauth_route_registered: bool
    egress_listener_configured: bool = False
    git_route_registered: bool = False


_active: ActiveConfig | None = None


def register_active_config(
    path: Path,
    config: GatewayConfig,
    llm_providers: dict[str, Any] | None = None,
    oauth_route_registered: bool = False,
) -> None:
    """Record the running configuration so it can be reloaded in place.

    Called once at startup, after the routes are registered, and again by
    each successful reload.
    """
    global _active
    _active = ActiveConfig(
        path=path,
        config=config,
        llm_providers=llm_providers if llm_providers is not None else {},
        alert_route_registered=any(p.alert_ingress is not None for p in config.profiles.values()),
        matrix_route_registered=bool(config.matrix.get("enabled")),
        oauth_route_registered=oauth_route_registered,
        # Bound before serving, and only when a profile asked for it (#442).
        egress_listener_configured=any(
            p.client_egress is not None for p in config.profiles.values()
        ),
        git_route_registered=bool(config.git_remotes),
    )


def get_active_config() -> ActiveConfig | None:
    """Return the running configuration, or None if the gateway is not up."""
    return _active


def replace_active_config(config: GatewayConfig) -> None:
    """Swap the scalar config after a reload, keeping the startup wiring facts.

    Raises:
        RuntimeError: no active config; a reload cannot precede startup.
    """
    global _active
    if _active is None:
        raise RuntimeError("replace_active_config called before register_active_config")
    _active = ActiveConfig(
        path=_active.path,
        config=config,
        llm_providers=_active.llm_providers,
        alert_route_registered=_active.alert_route_registered,
        matrix_route_registered=_active.matrix_route_registered,
        oauth_route_registered=_active.oauth_route_registered,
        egress_listener_configured=_active.egress_listener_configured,
        git_route_registered=_active.git_route_registered,
    )


def reset_active_config() -> None:
    """Forget the running configuration (for testing)."""
    global _active
    _active = None
