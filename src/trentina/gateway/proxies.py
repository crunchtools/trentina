"""``proxies:``, the one block that declares the perimeter (#535).

Top level, ``proxies:`` names instances, each of one type; under a profile, it
names that profile's grants, each on one instance::

    proxies:
      github: {type: http, upstream: https://api.github.com, credential: {...}}
      forge:  {type: git, upstream: https://github.com}
      claude: {type: llm, upstream: https://api.anthropic.com, auth_header: x-api-key}
      matrix: {type: matrix, upstream: https://matrix-client.matrix.org}
      egress: {type: connect}
      bench:  {type: forward, hosts: [aeb-fixture.test]}
    profiles:
      agent1:
        proxies:
          github: {token_env: GH, methods: [GET], paths: ["/repos/acme/*"]}
          egress: {source_networks: [10.0.0.0/24], hosts: [api.example.com]}
          bench:  {hosts: [aeb-fixture.test]}

This module only reads the spelling. A built-in type is normalized into the
field it had before (``egress_upstreams``, ``git_remotes``, ``llm_providers``,
``matrix``; a profile's ``egress_http``, ``git``, ``client_egress``), so every
rule that reads those — the approval page, an agent reload's holds, federation's
derivation — reads one home per fact whichever spelling the file used. Only the
types that had no block, ``forward`` and ``dist:name`` plugins, live in
``route_instances`` and a profile's ``route_grants``. The LLM keys and Matrix
callers stay where they are: ``llm_keys`` is the L3 judge's credential, which an
agent may rotate, and the bridge reads ``matrix_ingress``.

The blocks before ``proxies:`` still load, each with one deprecation warning,
and go at the next major. A file may not spell one kind both ways.
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from .errors import ProfileConfigError
from .profile import RouteInstance

logger = logging.getLogger(__name__)

#: An instance name: a URL segment and an audit column.
_INSTANCE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")

#: The built-in types that normalize into a block of their own.
_BUILT_IN = ("http", "git", "llm", "matrix", "connect")

#: The blocks before ``proxies:``, by the kind each declares.
_LEGACY_TOP = {"egress_upstreams": "http", "git_remotes": "git", "llm_providers": "llm"}
_LEGACY_PROFILE = {"egress_http": "http", "git": "git", "client_egress": "connect"}
#: The ``matrix:`` keys that declare the proxy; ``other_agent_user_ids`` alone
#: is the bridge's, not a proxy setting, and not a block to rewrite.
_MATRIX_PROXY_KEYS = frozenset({"enabled", "upstream"})

#: A profile key only this module writes.
_ROUTE_GRANTS = "route_grants"


@dataclass(frozen=True)
class Normalized:
    """The file, with ``proxies:`` read into the blocks the gateway reads."""

    document: dict[str, Any]
    route_instances: dict[str, RouteInstance] = field(default_factory=dict)
    #: The blocks still written in the spelling before ``proxies:``.
    older_spelling: tuple[str, ...] = ()


def _older_blocks(cfg: dict[str, Any], profiles: dict[str, Any]) -> dict[str, str]:
    """Each block written in the spelling before ``proxies:``, by the kind it
    declares, each warned about once; and a profile writing the key only this
    module writes is refused."""
    found = {key: kind for key, kind in _LEGACY_TOP.items() if key in cfg}
    matrix = cfg.get("matrix")
    if isinstance(matrix, dict) and _MATRIX_PROXY_KEYS & set(matrix):
        found["matrix"] = "matrix"
    for name, body in profiles.items():
        if not isinstance(body, dict):
            continue
        if _ROUTE_GRANTS in body:
            raise ProfileConfigError(f"profiles.{name}: {_ROUTE_GRANTS} is not a key; use proxies:")
        found |= {f"profiles.*.{key}": kind for key, kind in _LEGACY_PROFILE.items() if key in body}
    for key in sorted(found):
        logger.warning(
            "gateway: %s goes at the next major; write it under proxies: (one namespace, "
            "so two blocks' names that collide must be renamed)",
            key,
        )
    return found


def _instance(name: str, body: Any) -> tuple[str, dict[str, Any]]:
    """An instance's type and its other fields, or a refusal naming it."""
    if not _INSTANCE_NAME.match(name):
        raise ProfileConfigError(f"proxies: {name!r} is not an instance name ([a-z][a-z0-9-]*)")
    if not isinstance(body, dict) or not isinstance(body.get("type"), str):
        raise ProfileConfigError(f"proxies.{name}: a mapping with a type is required")
    fields = {k: v for k, v in body.items() if k != "type"}
    return body["type"], fields


def _place(out: dict[str, Any], name: str, kind: str, fields: dict[str, Any]) -> None:
    """Put one built-in instance where the gateway reads its kind."""
    if kind == "connect":
        if fields:
            raise ProfileConfigError(
                f"proxies.{name}: a connect instance takes no settings; its port is the "
                "gateway's --egress-port and each profile's grant names its hosts"
            )
        return
    if kind == "matrix":
        # Merged with a matrix: block that holds only the bridge's settings.
        out["matrix"] = {**out.get("matrix", {}), "enabled": True, **fields}
        return
    section = {"http": "egress_upstreams", "git": "git_remotes", "llm": "llm_providers"}[kind]
    out.setdefault(section, {})[name] = {"enabled": True, **fields} if kind == "llm" else fields


def _declare(
    out: dict[str, Any], declared: dict[str, Any]
) -> tuple[dict[str, str], dict[str, RouteInstance]]:
    """Read each top-level instance: a built-in into its block, a ``forward`` or
    ``dist:`` one into a ``RouteInstance``. Returns every instance's type, and
    the route instances."""
    types: dict[str, str] = {}
    instances: dict[str, RouteInstance] = {}
    for name, body in declared.items():
        kind, fields = _instance(name, body)
        if kind in ("matrix", "connect") and kind in types.values():
            # One homeserver and one CONNECT listener: the gateway binds one of each.
            raise ProfileConfigError(f"proxies.{name}: there is one {kind} instance")
        types[name] = kind
        if kind in _BUILT_IN:
            _place(out, name, kind, fields)
            continue
        try:
            instances[name] = RouteInstance(**body)
        except ValidationError as exc:
            reasons = "; ".join(e["msg"] for e in exc.errors())
            raise ProfileConfigError(f"proxies.{name}: {reasons}") from exc
    return types, instances


def _read_grants(out: dict[str, Any], types: dict[str, str]) -> None:
    """Read each profile's ``proxies:`` grants into the blocks it is read from."""
    profiles = out.get("profiles")
    for profile, body in (profiles or {}).items():
        grants = body.pop("proxies", None) if isinstance(body, dict) else None
        if not grants:
            continue
        if not isinstance(grants, dict):
            raise ProfileConfigError(f"profiles.{profile}.proxies: must be a mapping")
        for name, grant in grants.items():
            where = f"profiles.{profile}.proxies.{name}"
            kind = types.get(name)
            if kind is None:
                raise ProfileConfigError(f"{where}: names no instance")
            if kind in ("llm", "matrix"):
                home = "llm_keys" if kind == "llm" else "matrix_ingress"
                raise ProfileConfigError(f"{where}: a {kind} instance's grant is in {home}")
            if kind == "connect":
                body["client_egress"] = grant
            else:
                key = {"http": "egress_http", "git": "git"}.get(kind, _ROUTE_GRANTS)
                body.setdefault(key, {})[name] = grant


def normalize(cfg: dict[str, Any]) -> Normalized:
    """Read ``proxies:`` (top level and every profile's) into the blocks the
    gateway reads; warn once for each block still in the older spelling.

    Raises:
        ProfileConfigError: a malformed instance or grant, a grant naming no
            instance, a second matrix or connect instance, or one kind written
            in both spellings anywhere in the file.
    """
    section = cfg.get("profiles")
    profiles: dict[str, Any] = section if isinstance(section, dict) else {}
    legacy = _older_blocks(cfg, profiles)
    declared = cfg.get("proxies")
    if declared is None:
        if any(isinstance(b, dict) and "proxies" in b for b in profiles.values()):
            raise ProfileConfigError(
                "a profile's proxies: names instances, but there is no proxies:"
            )
        return Normalized(cfg, older_spelling=tuple(sorted(legacy)))
    if not isinstance(declared, dict):
        raise ProfileConfigError("proxies: must be a mapping of instance name to instance")
    out = copy.deepcopy({k: v for k, v in cfg.items() if k != "proxies"})
    types, instances = _declare(out, declared)
    _read_grants(out, types)
    if both := sorted(set(legacy.values()) & set(types.values())):
        raise ProfileConfigError(
            f"{', '.join(both)} written both under proxies: and in the older blocks; "
            "spell each kind one way"
        )
    return Normalized(out, instances, tuple(sorted(legacy)))
