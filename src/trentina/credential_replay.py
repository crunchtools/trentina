"""``trentina-credential-replay``: what would the credential guard refuse? (#862)

The guard refuses a ``tools/call`` whose arguments carry a credential the
backend's ``credentials_allowed`` does not allow. Turning it on blind refuses
whatever an agent already does legitimately, so this replays past calls first
and prints the ``credentials_allowed`` blocks that would have let them through.

The audit log cannot be replayed: ``gateway_calls`` stores no arguments. The
input is JSONL, one call per line, in any mix of:

1. ``{"profile": P, "backend": B, "tool": T, "arguments": {...}}``
2. ``{"profile": P, "name": SERVED_NAME, "arguments": {...}}``
3. a Claude Code session transcript line, whose ``tool_use`` blocks named
   ``mcp__<server>__<served>`` are calls (they carry no profile: ``--profile``).

Nothing printed is a credential value or an argument: only kinds, tool names
and counts.

``profiles.yaml`` is read for policy only (``credentials_allowed`` and
``short_names``), without ``load_profiles``: that refuses a file whose secret
env vars are unset, which is every machine but the gateway's. The cost is that
the rest of the file is not validated here; ``trentina`` itself does that.
Served short names resolve through the gateway database's ``tool_names`` table
(``--db``, default the gateway's), opened read-only.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import yaml

from .gateway.guards import refused_credentials
from .gateway.profile import Backend

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

Pair = tuple[str, str]  # (backend, tool)
_SEP = "__"


class ReplayError(Exception):
    """A usage or load error: exit 2."""


@dataclass
class Policy:
    """One profile, as far as replay needs it."""

    short_names: bool
    backends: dict[str, Backend]


@dataclass
class Call:
    """One past call, its profile possibly unknown, its target possibly a served name."""

    profile: str | None
    arguments: dict[str, Any]
    pair: Pair | None = None
    name: str | None = None


@dataclass
class ProfileReport:
    replayed: int = 0
    refused: int = 0
    unresolved: int = 0
    #: backend -> tool -> kind -> calls carrying it
    needs: dict[str, dict[str, Counter[str]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(Counter))
    )
    #: backend -> tool -> calls that would be refused
    tool_calls: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))


def load_policy(path: Path) -> dict[str, Policy]:
    """Each profile's ``credentials_allowed`` per backend and its ``short_names``."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReplayError(f"cannot read {path}: {_why(exc)}") from None
    profiles = document.get("profiles") if isinstance(document, dict) else None
    if not isinstance(profiles, dict) or not profiles:
        raise ReplayError(f"{path}: no 'profiles' mapping")
    out: dict[str, Policy] = {}
    for pname, body in profiles.items():
        backends = body.get("backends") if isinstance(body, dict) else None
        policy = Policy(
            short_names=bool(body.get("short_names", True)) if isinstance(body, dict) else True,
            backends={},
        )
        for bname, bbody in (backends if isinstance(backends, dict) else {}).items():
            allowed = bbody.get("credentials_allowed", {}) if isinstance(bbody, dict) else {}
            try:
                allowed = Backend.credentials_allowed_well_formed(allowed)
                policy.backends[str(bname)] = Backend.model_construct(credentials_allowed=allowed)
            except ValueError as exc:
                raise ReplayError(f"profiles.{pname}.backends.{bname}: {exc}") from None
            if not isinstance(allowed, dict):
                raise ReplayError(f"profiles.{pname}.backends.{bname}: bad credentials_allowed")
        out[str(pname)] = policy
    return out


def _transcript_calls(rec: dict[str, Any], prefix: str, profile: str | None) -> Iterator[Call]:
    message = rec.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if rec.get("type") != "assistant" or not isinstance(content, list):
        return
    for block in content:
        if not (isinstance(block, dict) and block.get("type") == "tool_use"):
            continue
        name, args = block.get("name"), block.get("input")
        if isinstance(name, str) and name.startswith(prefix) and isinstance(args, dict):
            yield Call(profile, args, name=name[len(prefix) :])


def _plain_call(rec: dict[str, Any], profile: str | None) -> list[Call] | None:
    """Shapes 1 and 2: a call with its arguments and a target or a served name."""
    args = rec.get("arguments")
    who = rec.get("profile", profile)
    if not isinstance(args, dict) or not (who is None or isinstance(who, str)):
        return None
    backend, tool, name = rec.get("backend"), rec.get("tool"), rec.get("name")
    if isinstance(backend, str) and isinstance(tool, str):
        return [Call(who, args, pair=(backend, tool))]
    return [Call(who, args, name=name)] if isinstance(name, str) else None


def parse_line(line: str, *, profile: str | None, server: str) -> list[Call] | None:
    """The calls on one line, or None when the line is none of the three shapes."""
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    if not isinstance(rec, dict):
        return None
    if rec.get("type") == "assistant":
        return list(_transcript_calls(rec, f"mcp__{server}{_SEP}", profile)) or None
    return _plain_call(rec, profile)


class Resolver:
    """Served name -> (backend, tool), as ``gateway.names.resolve_name`` does it.

    That reads ``tool_names`` through the gateway's writable singleton, which
    creates and migrates the database; this reads the same table read-only.
    """

    def __init__(self, policy: dict[str, Policy], db_path: str | None) -> None:
        self._policy = policy
        self._db_path = db_path
        self._issued: dict[str, dict[str, Pair]] = {}

    def _names(self, profile: str) -> dict[str, Pair]:
        if profile not in self._issued:
            names: dict[str, Pair] = {}
            if self._db_path:
                try:
                    db = sqlite3.connect(f"file:{quote(self._db_path)}?mode=ro", uri=True)
                    try:
                        rows = db.execute(
                            "SELECT issued, backend, tool FROM tool_names WHERE profile = ?",
                            (profile,),
                        ).fetchall()
                    finally:
                        db.close()
                    names = {r[0]: (r[1], r[2]) for r in rows}
                except sqlite3.Error as exc:
                    raise ReplayError(
                        f"cannot read tool_names from {self._db_path}: {_why(exc)}"
                    ) from None
            self._issued[profile] = names
        return self._issued[profile]

    def resolve(self, profile: str, name: str) -> Pair | None:
        policy = self._policy[profile]
        if not policy.short_names:
            backend, sep, tool = name.partition(_SEP)
            return (backend, tool) if sep and backend in policy.backends else None
        return self._names(profile).get(name)


def replay(
    calls: Iterable[Call],
    policy: dict[str, Policy],
    resolver: Resolver,
    *,
    current: bool,
) -> dict[str, ProfileReport]:
    """Evaluate every call; a call that needs nothing only counts as replayed."""
    reports: dict[str, ProfileReport] = {}
    open_backend = Backend.model_construct(credentials_allowed={})
    for call in calls:
        profile = call.profile or ""
        if profile not in reports:
            reports[profile] = ProfileReport()
        report = reports[profile]
        pair = call.pair
        if pair is None and call.name is not None and profile in policy:
            pair = resolver.resolve(profile, call.name)
        backend = policy[profile].backends.get(pair[0]) if pair and profile in policy else None
        if pair is None or backend is None:
            report.unresolved += 1
            continue
        report.replayed += 1
        kinds = refused_credentials(pair[1], call.arguments, backend if current else open_backend)
        if not kinds:
            continue
        report.refused += 1
        report.tool_calls[pair[0]][pair[1]] += 1
        for kind in kinds:
            report.needs[pair[0]][pair[1]][kind] += 1
    return reports


def render_yaml(reports: dict[str, ProfileReport]) -> str:
    """One pasteable block per profile; only kinds, tool names and counts."""
    out: list[str] = []
    for profile, r in sorted(reports.items()):
        label = profile or "(none)"
        out.append(
            f"# profile: {label}  ({r.replayed} calls replayed, "
            f"{r.refused} would be refused, {r.unresolved} unresolved)"
        )
        if r.needs:
            out.append("backends:")
        for backend, tools in sorted(r.needs.items()):
            out.append(f"  {backend}:")
            out.append("    credentials_allowed:")
            for tool, kinds in sorted(tools.items()):
                n = r.tool_calls[backend][tool]
                plural = "" if n == 1 else "s"
                listed = ", ".join(sorted(kinds))
                out.append(f"      {tool}: [{listed}]   # {n} call{plural}")
    return "\n".join(out)


def render_json(reports: dict[str, ProfileReport], skipped: int) -> str:
    doc = {
        "skipped": skipped,
        "profiles": {
            (p or ""): {
                "replayed": r.replayed,
                "refused": r.refused,
                "unresolved": r.unresolved,
                "needs": {
                    b: {t: dict(sorted(k.items())) for t, k in sorted(tools.items())}
                    for b, tools in sorted(r.needs.items())
                },
            }
            for p, r in sorted(reports.items())
        },
    }
    return json.dumps(doc, indent=2)


def read_calls(
    paths: list[str], *, profile: str | None, server: str, skipped: Counter[str]
) -> Iterator[Call]:
    """The calls in ``paths`` (``-`` is stdin), a line at a time, so a history of
    any length is replayed in the memory of one line. A line that is not a
    call, or names no profile, counts in ``skipped["lines"]``."""
    for path in paths:
        try:
            with (
                nullcontext(sys.stdin)
                if path == "-"
                else Path(path).open(encoding="utf-8", errors="replace") as lines
            ):
                for line in lines:
                    if not line.strip():
                        continue
                    found = parse_line(line, profile=profile, server=server)
                    if found is None or any(c.profile is None for c in found):
                        skipped["lines"] += 1
                    else:
                        yield from found
        except OSError as exc:
            raise ReplayError(f"cannot read {path}: {_why(exc)}") from None


def _why(exc: Exception) -> str:
    """Where and why a read failed, never the text read: a YAML problem can quote it."""
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:
        return f"{type(exc).__name__} at line {mark.line + 1}, column {mark.column + 1}"
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return f"{type(exc).__name__}: {exc}" if isinstance(exc, sqlite3.Error) else type(exc).__name__


def _check_profile(profile: str | None, policy: dict[str, Policy]) -> None:
    if profile and profile not in policy:
        raise ReplayError(f"--profile {profile!r} is not in the profiles file")


def _parser() -> argparse.ArgumentParser:
    """The command line; every input is a flag or a file, nothing from the environment."""
    parser = argparse.ArgumentParser(
        prog="trentina-credential-replay",
        description="Replay past tools/call arguments against credentials_allowed.",
    )
    parser.add_argument("files", nargs="+", help="JSONL of past calls; '-' is stdin")
    parser.add_argument("--profiles", required=True, help="the profiles.yaml to judge against")
    parser.add_argument("--profile", help="profile for lines that name none (transcripts)")
    parser.add_argument("--mcp-server", default="trentina", help="transcript server name")
    parser.add_argument(
        "--db", help="gateway database, read-only, to resolve short names (without it they do not)"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--current",
        dest="current",
        action="store_true",
        default=True,
        help="only what the current credentials_allowed would refuse (default)",
    )
    mode.add_argument(
        "--all", dest="current", action="store_false", help="ignore existing allowances"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def main(argv: list[str] | None = None) -> int:
    """``trentina-credential-replay``: 0 nothing would be refused, 1 something would, 2 usage."""
    args = _parser().parse_args(argv)

    try:
        policy = load_policy(Path(args.profiles))
        _check_profile(args.profile, policy)
        skipped: Counter[str] = Counter()
        calls = read_calls(
            args.files, profile=args.profile, server=args.mcp_server, skipped=skipped
        )
        reports = replay(calls, policy, Resolver(policy, args.db), current=args.current)
    except ReplayError as exc:
        print(f"trentina-credential-replay: {exc}", file=sys.stderr)
        return 2

    print(render_json(reports, skipped["lines"]) if args.json else render_yaml(reports))
    if skipped["lines"] and not args.json:
        print(f"# {skipped['lines']} line(s) skipped (not a call, or no profile)")
    return 1 if any(r.refused for r in reports.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
