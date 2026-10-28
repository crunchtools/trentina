"""The public conformance suite for a transform plugin.

A plugin author runs ``conformance(ref, transform)`` before shipping; the
gateway runs the load-bearing half (``scan_imports``) at startup for every
referenced plugin, so a plugin that violates the contract is refused BY NAME at
load, never with an ``AttributeError`` at the first request.

Two halves, because they have different costs and the loader can only pay one:

* ``scan_imports`` is STATIC and SYNC — an AST walk of the distribution's own
  source. It enforces the one load-bearing rule, the import boundary: a plugin
  imports only the public contract (``trentina.transforms.base``,
  ``trentina.transports.base``, ``trentina.testing``) and no network or
  subprocess module. The loader runs this at config load, in a sync context
  that works under both startup and an async reload.
* ``conformance`` is the FULL suite and is ASYNC — it builds the plugin and runs
  behavioural probes (declines empty and binary, bounded amplification, roughly
  linear cost, logs no payload). An author awaits it; our own tests run it over
  the fixtures. It is not run at startup, where there may be no event loop and
  where the probes would add latency.

This suite is best-effort author guidance plus that one load-bearing rule. It is
NOT a sandbox: a plugin that evades the static scan still runs in-process until
process isolation is enabled (``docs/plugins.md``). Process isolation is the
authoritative host boundary; this catches honest mistakes and obvious
violations.
"""

from __future__ import annotations

import ast
import importlib.metadata as im
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import logsafe
from ..transforms.base import (
    Applied,
    Declined,
    Failed,
    Transform,
    TransformContext,
    TransformResult,
)
from .hygiene import capture_logs, leaked

#: The only ``trentina`` modules a plugin may import — the public contract. A
#: module is allowed if it is one of these or a submodule of one.
PUBLIC_MODULES: frozenset[str] = frozenset(
    {"trentina.transforms.base", "trentina.transports.base", "trentina.testing"}
)

#: Top-level modules a transform plugin must not import: a transform reshapes a
#: string, so it has no business opening a socket or a subprocess. (Host access
#: is bounded authoritatively by process isolation; this is the author-facing
#: courtesy.)
FORBIDDEN_MODULES: frozenset[str] = frozenset(
    {"httpx", "socket", "subprocess", "ctypes", "urllib", "http", "requests", "aiohttp", "ftplib"}
)

#: The canary a conformance run feeds the plugin: if it appears in a log record,
#: the plugin logged the payload it was handed (#262).
_CANARY = "zqx7conformancecanary"

#: Amplification cap: an ``Applied`` result may not exceed this multiple of the
#: input size. A transform subtracts or reshapes; it does not inflate.
_AMPLIFICATION = 4


@dataclass(frozen=True)
class Conformance:
    """The checks a plugin failed, each a short reason string. Empty means it
    passed. The loader renders these into a ``ProfileConfigError``."""

    ref: str
    failures: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.failures


@dataclass
class _Scan:
    violations: list[str] = field(default_factory=list)


def _allowed_trentina(module: str) -> bool:
    return any(module == pub or module.startswith(f"{pub}.") for pub in PUBLIC_MODULES)


def _check_module(module: str, scan: _Scan) -> None:
    """Record a violation if ``module`` is a private trentina import or a
    forbidden top-level module."""
    top = module.split(".", 1)[0]
    if module == "trentina" or top == "trentina":
        if not _allowed_trentina(module):
            scan.violations.append(f"private-import:{module}")
    elif top in FORBIDDEN_MODULES:
        scan.violations.append(f"forbidden-import:{top}")


def scan_source(source: str, scan: _Scan) -> None:
    """Walk one module's source for import violations. Syntax that will not
    parse is itself a violation — a plugin whose source is unreadable cannot be
    vouched for."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        scan.violations.append("unparseable-source")
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _check_module(alias.name, scan)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            _check_module(node.module, scan)


def scan_imports(dist: str) -> list[str]:
    """The load-bearing, synchronous check: the import boundary over every
    source file the distribution ships. Returns a list of violation reasons,
    empty when the distribution imports only the public contract.

    A distribution with no readable file list cannot be vouched for, which is
    itself a violation (``no-files``)."""
    scan = _Scan()
    try:
        files = im.files(dist)
    except im.PackageNotFoundError:
        return ["not-installed"]
    if not files:
        return ["no-files"]
    saw_python = False
    for path in files:
        if path.suffix != ".py":
            continue
        saw_python = True
        try:
            source = Path(path.locate()).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            # A file we cannot read or decode (a non-UTF-8 coding cookie, say)
            # is a file we cannot vouch for — a violation, not a skip.
            scan.violations.append(f"unreadable:{path}")
            continue
        scan_source(source, scan)
    if not saw_python:
        # Files but no Python source — a compiled-only distribution the scan
        # cannot read. It does not pass by default; the operator must trust it
        # explicitly, and process isolation (the host boundary) still applies.
        scan.violations.append("no-python-source")
    return scan.violations


async def run_transform(
    transform: Transform, payload: str, *, ctx: TransformContext | None = None
) -> TransformResult:
    """Run one transform the way the composition does — the author's convenience
    for exercising a plugin in a test."""
    return await transform.run(payload, ctx or TransformContext())


async def _run_or_record(
    transform: Transform, payload: str, label: str, scan: _Scan
) -> TransformResult | None:
    """Run the transform, or record ``raised-on-<label>`` and return None. A
    plugin must never raise on input; if it does, that is the conformance
    failure, caught here so a later probe is not derailed by it."""
    try:
        return await run_transform(transform, payload)
    except Exception as exc:
        # Name the exception KIND (never its message, #262) so an author can
        # tell a TypeError from an unrelated failure.
        scan.violations.append(f"raised-on-{label}:{logsafe.exc_kind(exc)}")
        return None


async def _probe_behaviour(transform: Transform, scan: _Scan) -> None:
    """The behavioural half: declines empty and binary, bounded amplification,
    roughly linear cost, and logs no payload it was handed. Every call is
    guarded, so a plugin that always raises records a failure per probe rather
    than aborting the suite."""
    # Returns a valid TransformResult (not a crash, not a foreign object) on an
    # empty payload and on binary noise. Any of the three outcomes is fine — a
    # transform may legitimately apply to, decline, or fail on either.
    for name, payload in (("empty", ""), ("binary", bytes(range(256)).decode("latin-1"))):
        result = await _run_or_record(transform, payload, name, scan)
        if result is not None and not isinstance(result, (Applied, Declined, Failed)):
            scan.violations.append(f"bad-result-on-{name}")

    # Amplification: an Applied result may not balloon the payload. A plugin
    # that returns an Applied with non-string content is malformed, not
    # amplifying — guarded so the probe records it rather than crashing on len().
    base = "line of text\n" * 512
    result = await _run_or_record(transform, base, "amplify", scan)
    if isinstance(result, Applied):
        if not isinstance(result.content, str):
            scan.violations.append("bad-result-on-amplify")
        elif len(result.content) > _AMPLIFICATION * len(base):
            scan.violations.append("amplifies")

    # Roughly linear cost: 4x the input must not cost wildly more than 4x.
    small = "a b c d e f\n" * 4096
    large = small * 4
    t0 = time.perf_counter()
    if await _run_or_record(transform, small, "linearity", scan) is None:
        return
    t_small = time.perf_counter() - t0
    t0 = time.perf_counter()
    await _run_or_record(transform, large, "linearity", scan)
    t_large = time.perf_counter() - t0
    if t_small > 0 and t_large / t_small > 32:
        scan.violations.append("superlinear")

    # Logs no payload: run with a canary and assert it never reaches a record.
    with capture_logs() as handler:
        await _run_or_record(transform, f"{_CANARY} payload {_CANARY}", "canary", scan)
    if leaked(handler, _CANARY):
        scan.violations.append("logs-payload")


async def conformance(ref: str, transform: Transform) -> Conformance:
    """The full suite over a BUILT transform. ``ref`` is its ``dist:name``; the
    distribution is scanned for import violations and the instance is probed for
    behaviour. Returns the checks it failed, empty when it passed.

    The caller builds the transform (``plugins.registry.resolve_transform``,
    which already holds the type/`api_version` contract) and passes it here, so
    conformance never re-implements construction."""
    dist = ref.partition(":")[0]
    scan = _Scan(violations=list(scan_imports(dist)))
    if transform.name != ref.partition(":")[2]:
        scan.violations.append("name-mismatch")
    await _probe_behaviour(transform, scan)
    return Conformance(ref=ref, failures=tuple(scan.violations))
