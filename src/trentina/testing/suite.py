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
from typing import Any

from starlette.datastructures import Headers

from .. import logsafe
from ..modes import Mode
from ..transforms.base import (
    Applied,
    Declined,
    Failed,
    Transform,
    TransformContext,
    TransformResult,
)
from ..transports.base import (
    SPINE_REFUSALS,
    Admitted,
    Grant,
    Instance,
    RefusedError,
    Route,
    Wire,
)
from ..transports.registry import route_breaches
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

#: Modules a ROUTE plugin must not import, beyond a transform's. A route runs in
#: the gateway's process, with live request and response streams, so nothing
#: holds it but the contract (#535): it gets no socket, no file, no process, and
#: no way to read the gateway's own state. Each of these offers one of those —
#: a dialer, a file or process, or introspection that reaches the spine's
#: locals (the profile, a token) — and a route needs none of them.
ROUTE_FORBIDDEN_MODULES: frozenset[str] = FORBIDDEN_MODULES | frozenset(
    {
        "anyio", "trio", "httpcore", "h11", "h2", "websockets", "ssl", "multiprocessing",
        "importlib", "os", "sys", "builtins", "io", "codecs", "pathlib", "shutil",
        "tempfile", "pickle", "marshal", "shelve", "inspect", "gc", "ctypes", "mmap",
        "signal", "resource", "pty", "fcntl", "select", "selectors", "threading",
        "concurrent", "runpy", "code", "pdb", "types", "weakref", "atexit",
    }
)  # fmt: skip

#: Names a route plugin may not call or reach: the builtins that read files,
#: run strings as code or reach objects by name past an import scan.
ROUTE_FORBIDDEN_NAMES: frozenset[str] = frozenset(
    {
        "open", "exec", "eval", "compile", "__import__", "getattr", "setattr", "delattr",
        "globals", "locals", "vars", "breakpoint", "input", "memoryview", "__builtins__",
    }
)  # fmt: skip

#: Attributes a route plugin may not reach on any object: the dialers and
#: process launchers a permitted module (asyncio) still offers, and an event
#: loop's own.
ROUTE_FORBIDDEN_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "open_connection", "open_unix_connection", "start_server", "start_unix_server",
        "create_subprocess_exec", "create_subprocess_shell", "create_connection",
        "create_server", "create_datagram_endpoint", "create_unix_connection",
        "create_unix_server", "sock_connect", "sock_accept", "subprocess_exec",
        "subprocess_shell", "connect_read_pipe", "connect_write_pipe", "to_thread",
        "run_in_executor", "f_globals", "f_locals", "f_back", "gi_frame", "cr_frame",
        "tb_frame",
    }
)  # fmt: skip

#: Dunder attributes a route plugin may still use: what an ordinary class needs.
_ROUTE_DUNDERS: frozenset[str] = frozenset(
    {"__init__", "__name__", "__post_init__", "__eq__", "__hash__", "__repr__", "__str__"}
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


class _RouteScan(ast.NodeVisitor):
    """Every import, name and attribute in a route plugin's module, held to the
    route lists. Each ``visit_`` records what it finds and keeps walking."""

    def __init__(self, scan: _Scan) -> None:
        self.scan = scan

    def _module(self, module: str) -> None:
        top = module.split(".", 1)[0]
        if top in ROUTE_FORBIDDEN_MODULES:
            self.scan.violations.append(f"forbidden-import:{top}")
        elif top == "trentina" and not _allowed_trentina(module):
            self.scan.violations.append(f"private-import:{module}")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._module(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module is not None:
            self._module(node.module)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in ROUTE_FORBIDDEN_NAMES:
            self.scan.violations.append(f"forbidden-name:{node.id}")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        attr = node.attr
        if attr in ROUTE_FORBIDDEN_ATTRIBUTES:
            self.scan.violations.append(f"forbidden-attribute:{attr}")
        elif attr.startswith("__") and attr.endswith("__") and attr not in _ROUTE_DUNDERS:
            self.scan.violations.append(f"forbidden-dunder:{attr}")
        self.generic_visit(node)


def scan_route_source(source: str, scan: _Scan) -> None:
    """``scan_source`` for a route plugin: the stricter module list, and every
    forbidden name, attribute and dunder reached anywhere in the module."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        scan.violations.append("unparseable-source")
        return
    _RouteScan(scan).visit(tree)


def scan_imports(dist: str, *, route: bool = False) -> list[str]:
    """The load-bearing, synchronous check: the import boundary over every
    source file the distribution ships. Returns a list of violation reasons,
    empty when the distribution imports only the public contract.

    ``route`` holds it to the route lists (``scan_route_source``): a route
    plugin runs in the gateway's process, so it is held to far more.

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
        (scan_route_source if route else scan_source)(source, scan)
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


def _hostile_wire(route: Route[Any, Any]) -> Wire:
    """A request carrying the canary everywhere a caller chooses a value."""
    return Wire(
        method=route.methods[0] if route.methods else "GET",
        path=f"{_CANARY}/../{_CANARY}",
        raw_path=f"/{_CANARY}".encode(),
        query=f"{_CANARY}={_CANARY}",
        headers=Headers(raw=[(b"x-conformance", _CANARY.encode())]),
        peer=None,
    )


def _text(rendered: object) -> str:
    """A rendered refusal as text, whatever the route built it as."""
    body = getattr(rendered, "body", rendered)
    return body.decode("utf-8", "replace") if isinstance(body, bytes) else repr(body)


async def _probe_admit(route: Route[Any, Any], scan: _Scan) -> None:
    """``admit`` on a request it has no grant for answers ``Admitted`` or a
    refusal the route declared, and logs nothing the caller sent."""
    grant = Grant(frozenset(), frozenset(route.methods), Mode.BLOCK, {})
    instance = Instance("conformance", route.name, {}, {})
    with capture_logs() as handler:
        try:
            admitted = await route.admit(_hostile_wire(route), grant, instance)
        except Exception as exc:
            if not isinstance(exc, RefusedError):
                scan.violations.append(f"raised-on-admit:{logsafe.exc_kind(exc)}")
            elif exc.reason not in route.refusals and exc.reason not in SPINE_REFUSALS:
                scan.violations.append("undeclared-refusal")
        else:
            if not isinstance(admitted, Admitted):
                scan.violations.append("bad-result-on-admit")
    if leaked(handler, _CANARY):
        scan.violations.append("logs-payload")


def _probe_render(route: Route[Any, Any], scan: _Scan) -> None:
    """``render`` answers every refusal the spine or the route can raise, and
    never puts a refusal's ``detail`` — a caller's value — on the wire (#262)."""
    for reason, refusal in {**SPINE_REFUSALS, **route.refusals}.items():
        refused = RefusedError(
            reason, status=refusal.status, outcome=refusal.outcome, detail=_CANARY
        )
        try:
            rendered = route.render(refused)
        except Exception as exc:
            scan.violations.append(f"raised-on-render:{logsafe.exc_kind(exc)}")
            continue
        if _CANARY in _text(rendered):
            scan.violations.append("render-echoes-detail")


async def route_conformance(ref: str, route: Route[Any, Any]) -> Conformance:
    """The full suite over a BUILT route plugin, ``ref`` its ``dist:name``.

    The distribution is held to the route import lists, the route to the
    contract ``register_route`` enforces, ``admit`` to answering a request it
    has no grant for with a declared refusal, and ``render`` to answering every
    refusal without echoing a caller's value. Returns the checks it failed,
    empty when it passed. Nothing here dials: ``deliver`` reaches the network
    only through the spine, which the gateway's own tests hold.
    """
    dist, _, name = ref.partition(":")
    scan = _Scan(violations=list(scan_imports(dist, route=True)))
    scan.violations.extend(route_breaches(name, route))
    if isinstance(route, Route):
        await _probe_admit(route, scan)
        _probe_render(route, scan)
    return Conformance(ref=ref, failures=tuple(dict.fromkeys(scan.violations)))
