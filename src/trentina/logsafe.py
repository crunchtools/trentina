"""What a log line may carry (#262).

The gateway's log is readable by several agents through other backends'
journal and container-log tools, so a string a caller chose that reaches it
verbatim is a message board between agents, and one that outlives the
session. The rule: never log a string a caller chose — an agent, an OAuth or
HTTP client, a backend, a fetched page, a Matrix sender — nor an exception
whose message may carry one.

What may be logged: a profile name (server-configured), a tool name once it
resolved to a configured tool, ``exc_kind(exc)``, and for anything else
``redact_source(s)``, a fingerprint an operator correlates with the audit
database, which no tool can reach. ``tests/test_log_hygiene.py`` drives every
tool path with a canary at DEBUG and fails if the canary reaches a record,
and fails any ``logger.exception``, ``exc_info`` or bare exception argument
not marked ``# logsafe: ours`` with the reason its text is the server's own.

Third-party loggers that format request data themselves (uvicorn's access
log, httpx, httpcore) are held to the same rule by ``guard()`` and
``install()``, and so is library OAuth code (``fastmcp.server.auth``,
``mcp.server.auth``), whose every interpolated value is fingerprinted.

That rule is about what a call site may pass. The backstop (#341) is about
what a record may carry whoever built it: ``guard()``, run when the package
is imported, installs a ``LogRecord`` factory that every record from every
logger passes through before a handler sees it. A secret ``hold()`` knows is
replaced by the name of the variable it came from; text shaped like a
credential nobody registered is replaced by ``[REDACTED]``. A miss at a call
site, in a library, or in a traceback is then harmless rather than a leak.
``configure()`` is the one place a process sets up logging.
"""

from __future__ import annotations

import ast
import functools
import hashlib
import logging
import os
import re
import sys
import threading
import traceback
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote, urlsplit

from . import credential_shapes as _cred

#: HTTP methods written as they are; anything else is a caller's token.
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"})

#: First path segments that are routes of ours, kept readable in the access log.
_ROUTES = frozenset(
    {
        "gateway",
        "mcp",
        "health",
        "alert",
        "matrix",
        "llm",
        "_matrix",
        "authorize",
        "token",
        "register",
        "consent",
        "auth",
        ".well-known",
        "sse",
        "messages",
    }
)


def redact_source(s: object) -> str:
    """A fingerprint of ``s``: correlatable with the audit DB, unreadable in the log."""
    text = s if isinstance(s, str) else str(s)
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{digest[:12]} len={len(text)}"


def exc_kind(exc: BaseException) -> str:
    """The exception's class, never its message: messages embed URLs, paths
    and backend text. An HTTP status, when the exception carries one, is ours
    to log too."""
    status = getattr(exc, "status_code", None)
    return (
        f"{type(exc).__name__} status={status}" if isinstance(status, int) else type(exc).__name__
    )


def exc_where(exc: BaseException) -> str:
    """Where it was raised, as ``file:line in func`` frames: the traceback's
    code locations without the message a traceback would print."""
    frames = traceback.extract_tb(exc.__traceback__)[-4:]
    return " < ".join(
        f"{f.filename.rsplit('/', 1)[-1]}:{f.lineno} in {f.name}" for f in reversed(frames)
    )


def safe_address(host: object) -> str:
    """A peer address, fingerprinted. Even a real one is partly chosen: a
    client with an IPv6 /64 picks the low 64 bits per connection, and behind
    a trusted proxy uvicorn takes the host from ``X-Forwarded-For``. Equal
    fingerprints still group one client's lines."""
    text = str(host)
    return "unix" if text in {"", "None"} else redact_source(text)


def safe_url(url: object) -> str:
    """An operator-configured URL as ``scheme://host[:port]`` only. Backend
    URLs are ours, not a caller's, but some carry a credential in the path or
    query (a token-in-URL MCP server), and the journal is agent-readable."""
    try:
        parts = urlsplit(str(url))
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return redact_source(url)
    return f"{parts.scheme}://{host}{port}" if host else redact_source(url)


def safe_path(path: object) -> str:
    """A request path reduced to our route and a fingerprint of the rest."""
    text = str(path)
    first = text.lstrip("/").split("/", 1)[0].split("?", 1)[0]
    if text in {"/", "/health"}:
        return text
    head = f"/{first}" if first in _ROUTES else "/?"
    return f"{head}/… {redact_source(text)}"


class _AccessLogFilter(logging.Filter):
    """uvicorn.access: ``(client, method, path, http_version, status)``."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) == 5:
            client, method, path, version, status = args
            host, _, port = str(client).rpartition(":")
            record.args = (
                f"{safe_address(host)}:{port}" if host else safe_address(client),
                method if method in _METHODS else redact_source(method),
                safe_path(path),
                version,
                status,
            )
        return True


class _HttpxFilter(logging.Filter):
    """httpx: ``HTTP Request: %s %s "%s %d %s"``, method then URL. A fetched
    URL is the agent's."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 2:
            method = args[0] if args[0] in _METHODS else redact_source(args[0])
            record.args = (method, redact_source(args[1]), *args[2:])
        return True


#: A value held on the strength of its variable's NAME is not replaced below
#: this length: ``FOO_KEY=1`` is not a secret, and redacting every "1" or
#: "true" would shred the log and hide nothing.
MIN_HELD_CHARS = 8

#: A value ``read_secret_env`` declares a secret is held down to this length.
#: Shorter than that it cannot be told from ordinary text, so the loader
#: warns instead of pretending to redact it.
MIN_DECLARED_CHARS = 4

#: What a pattern match becomes. A held value becomes ``[REDACTED:<NAME>]``.
REDACTED = "[REDACTED]"

#: Environment names ``guard()`` holds the values of without being told.
_SECRET_NAME_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD")

#: The one log format, for the gateway and the bridge alike.
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

#: The level names ``configure`` accepts, all of which uvicorn's
#: ``Config(log_level=...)`` recognizes too. Deliberately a table and not
#: ``getattr(logging, name)``: that resolves any uppercase module attribute
#: (``NOTSET``, internals like ``_STYLES``), not just level constants.
LOG_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

# The credential-shape patterns live in ``credential_shapes``, the one table
# both this scrubber and the egress/``/llm`` request paths (#511) read. Each is
# a literal prefix followed by character classes that exclude the delimiter
# after them, so each is linear in the input (``tests/test_log_scrub.py`` holds
# them to it). The repeats are unbounded on purpose: a cap would print the tail
# of a long token.

_held_lock = threading.Lock()
#: The secrets as they were given, which is what makes one "already held".
_held_raw: set[str] = set()
#: Each form a secret can take in a line (itself, and percent-encoded with
#: uppercase hex) to the name it is held under. Nothing is ever dropped: a
#: key rotated out is not known to be revoked.
_held: dict[str, str] = {}
#: The same forms, longest first: a secret that contains another must win.
_held_forms: tuple[str, ...] = ()
#: The alternation of one ``_held_forms`` snapshot, and that snapshot;
#: compiled when a line first contains one of them.
_held_compiled: tuple[tuple[str, ...], re.Pattern[str]] | None = None

#: A percent-escape, whose two hex digits a writer may case either way:
#: ``%2f`` and ``%2F`` are the same byte to a server. ``_held`` is keyed on
#: the uppercase spelling, which ``_UPPER_ESCAPES(text)`` produces.
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_UPPER_ESCAPES = functools.partial(_PERCENT_ESCAPE.sub, lambda m: m.group(0).upper())


def _either_case(form: str) -> str:
    """A regex for ``form`` that takes its percent-escapes in any case."""
    out, last = [], 0
    for match in _PERCENT_ESCAPE.finditer(form):
        out.append(re.escape(form[last : match.start()]))
        out.append("%" + "".join(f"[{c.upper()}{c.lower()}]" for c in match.group(0)[1:]))
        last = match.end()
    out.append(re.escape(form[last:]))
    return "".join(out)


def hold(value: object, name: str, *, minimum: int = MIN_HELD_CHARS) -> bool:
    """Remember ``value`` as a secret: no log record carries it from here on.

    ``name`` is what replaces it, the variable it was read from: the
    operator's configuration, safe to print where the value is not.
    ``gateway.loader.read_secret_env`` calls this for every secret it
    returns, so a new secret that is read there needs nothing more.

    Returns False for a value under ``minimum`` characters, which is not
    held; the caller decides whether that is worth a warning.
    """
    global _held_forms
    text = value if isinstance(value, str) else str(value)
    text = text.strip()
    if len(text) < minimum:
        return False
    with _held_lock:
        if text not in _held_raw:
            _held_raw.add(text)
            for form in (_UPPER_ESCAPES(text), quote(text, safe="")):
                _held.setdefault(form, name)
            _held_forms = tuple(sorted(_held, key=len, reverse=True))
    return True


def _held_pattern(forms: tuple[str, ...]) -> re.Pattern[str]:
    """The alternation of exactly ``forms``, cached for that snapshot."""
    global _held_compiled
    compiled = _held_compiled
    if compiled is None or compiled[0] is not forms:
        compiled = (forms, re.compile("|".join(_either_case(v) for v in forms)))
        _held_compiled = compiled
    return compiled[1]


def _name_of(match: re.Match[str]) -> str:
    return f"[REDACTED:{_held.get(_UPPER_ESCAPES(match.group(0)), 'SECRET')}]"


def held_count() -> int:
    """How many secrets are held; a number for startup logs and tests."""
    return len(_held_raw)


def _forget_all() -> None:
    """Drop every held value. For tests only: production never un-holds."""
    global _held_forms, _held_compiled
    with _held_lock:
        _held_raw.clear()
        _held.clear()
        _held_forms = ()
        _held_compiled = None


def scrub(text: str) -> str:
    """``text`` with every held secret named and every credential shape cut."""
    forms = _held_forms
    # A substring test per value is C speed and the common answer is "none";
    # the alternation, which Python's engine walks per character, is built
    # and run only for a line that holds one.
    if forms:
        probe = _UPPER_ESCAPES(text) if "%" in text else text
        if any(form in probe for form in forms):
            text = _held_pattern(forms).sub(_name_of, text)
    # The shape pass is credential_shapes.redact, the one implementation the
    # request paths also use; this adds only the held-secret substitution above.
    return _cred.redact(text, REDACTED)


#: How far into nested containers a value is scrubbed with its shape kept.
_MAX_DEPTH = 6


def _scrub_arg(arg: object, depth: int = 0) -> object:
    """One value, with its type and shape kept wherever that is possible.

    A number stays a number and a format tuple keeps its length, which the
    httpx and access-log filters rely on; a mapping or a sequence is rebuilt
    with clean leaves, so a structured formatter still gets the structure.
    Anything else is replaced by its scrubbed text, and only when scrubbing
    changed that text.
    """
    if arg is None or isinstance(arg, (bool, int, float)):
        return arg
    if isinstance(arg, str):
        return scrub(arg)
    # Exact types only: a subclass may not rebuild from its own contents.
    if depth < _MAX_DEPTH:
        if type(arg) is dict:
            return {_scrub_arg(k, depth + 1): _scrub_arg(v, depth + 1) for k, v in arg.items()}
        if type(arg) is list:
            return [_scrub_arg(item, depth + 1) for item in arg]
        if type(arg) is tuple:
            return tuple(_scrub_arg(item, depth + 1) for item in arg)
    text = str(arg)
    cleaned = scrub(text)
    return arg if cleaned == text else cleaned


#: Loggers of library auth code, which interpolates what an OAuth client sent:
#: an unknown code, a refresh token's client, a resource indicator, an
#: exception or validation error that echoes the request (#343).
_LIBRARY_AUTH = ("fastmcp.server.auth", "mcp.server.auth")


def _is_library_auth(name: str) -> bool:
    return any(name == p or name.startswith(f"{p}.") for p in _LIBRARY_AUTH)


#: Each warmed library module's file to the string constants written in it.
#: Filled at startup by ``warm_library_literals``; a record never reads a file.
_library_literals: dict[str, frozenset[str]] = {}


def _read_literals(pathname: str) -> frozenset[str]:
    """The string constants written in ``pathname``, f-string pieces excluded.

    A message that is one of them was written by the library's author; any
    other message was assembled at run time (an f-string, a ``str(exc)``)
    and may hold anything.
    """
    try:
        with open(pathname, encoding="utf-8") as source:
            tree = ast.parse(source.read())
    except (OSError, SyntaxError, ValueError):
        return frozenset()
    inside = {
        id(child)
        for node in ast.walk(tree)
        if isinstance(node, ast.JoinedStr)
        for child in ast.walk(node)
    }
    return frozenset(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in inside
    )


def warm_library_literals() -> int:
    """Read the literals of every library auth module loaded so far.

    Called once the OAuth provider is built, before a request can arrive: a
    record is made on the caller's thread, which for the proxy is the event
    loop, so parsing a source file there would stall it. A module loaded
    after this is not warmed, and its messages are fingerprinted whole.
    Returns how many modules are warm.
    """
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if _is_library_auth(name) and path and path not in _library_literals:
            _library_literals[path] = _read_literals(path)
    return len(_library_literals)


def _fingerprint_value(arg: object) -> object:
    return arg if arg is None or isinstance(arg, (bool, int, float)) else redact_source(arg)


def _fingerprint_library(record: logging.LogRecord) -> None:
    """A library auth record with every interpolated value fingerprinted.

    Unlike ``scrub``, which cuts what LOOKS like a credential, this cuts
    everything the library did not write itself: a canary sent as a code is
    not credential-shaped, and the journal is agent-readable (#262).
    """
    literals = _library_literals.get(record.pathname, frozenset())
    if not (isinstance(record.msg, str) and record.msg in literals):
        record.msg, record.args = "%s", (redact_source(record.getMessage()),)
    elif isinstance(record.args, tuple):
        record.args = tuple(_fingerprint_value(a) for a in record.args)
    elif isinstance(record.args, Mapping):
        record.args = {k: _fingerprint_value(v) for k, v in record.args.items()}
    exc = record.exc_info[1] if record.exc_info else None
    if exc is not None:
        record.exc_text, record.exc_info = f"{exc_kind(exc)} at {exc_where(exc)}", None
    if record.stack_info:
        record.stack_info = scrub(record.stack_info)


def _scrub_record(record: logging.LogRecord) -> None:
    if _is_library_auth(record.name):
        _fingerprint_library(record)
        return
    args = record.args
    if not args and isinstance(record.msg, str):
        # No arguments: the message is the line, and one pass covers it.
        record.msg = scrub(record.msg)
    else:
        _scrub_formatted(record)
    exc = record.exc_info[1] if record.exc_info else None
    if exc is not None and _carries_secret(exc):
        text = "".join(traceback.format_exception(exc)).rstrip("\n")
        # Formatters print exc_text when it is set; with exc_info gone no
        # handler can re-render the original.
        record.exc_text, record.exc_info = scrub(text), None
    if record.stack_info:
        record.stack_info = scrub(record.stack_info)


#: Exceptions examined in one chain before it is treated as carrying a secret.
_MAX_CHAIN = 64


def _carries_secret(exc: BaseException) -> bool:
    """Whether a traceback of ``exc`` would print something ``scrub`` cuts.

    A traceback's frames are source lines, which hold no runtime value; what
    can carry a secret is each exception's own text, down the chain of causes
    and through a group's members. Reading only that keeps the common case to
    string work: rendering frames opens source files, and a logging call that
    did so for every exception would stall its caller.
    """
    seen: set[int] = set()
    pending = [exc]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        if len(seen) >= _MAX_CHAIN:
            return True
        seen.add(id(current))
        text = "".join(traceback.format_exception_only(current))
        if scrub(text) != text:
            return True
        pending.extend(e for e in (current.__cause__, current.__context__) if e is not None)
        pending.extend(getattr(current, "exceptions", ()))
    return False


def _scrub_formatted(record: logging.LogRecord) -> None:
    args = record.args
    if isinstance(args, tuple):
        record.args = tuple(_scrub_arg(a) for a in args)
    elif isinstance(args, Mapping):
        record.args = {k: _scrub_arg(v) for k, v in args.items()}
    # The whole line, as it will print: a secret assembled from the format
    # string and an argument ("?key=%s") is only visible here. The record is
    # left alone unless this finds something, so the filters downstream still
    # see the arguments they rewrite.
    rendered = record.getMessage()
    cleaned = scrub(rendered)
    if cleaned != rendered:
        record.msg, record.args = cleaned, None


class _Guard:
    """The record factory ``guard()`` installs: the previous one, then scrub."""

    def __init__(self, previous: Callable[..., logging.LogRecord]) -> None:
        self._previous = previous

    def __call__(self, *args: Any, **kwargs: Any) -> logging.LogRecord:
        record = self._previous(*args, **kwargs)
        try:
            _scrub_record(record)
        except Exception as exc:  # logsafe: ours — only the class is printed
            _withhold(record, exc)
        return record


def _guarding(factory: object) -> bool:
    return isinstance(factory, _Guard)


#: What a LogRecord carries by itself; anything else arrived through ``extra``.
_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
}

_stock_make_record = logging.Logger.makeRecord


def _withhold(record: logging.LogRecord, exc: Exception) -> None:
    """Replace a record that could not be scrubbed.

    A record that cannot be rendered (a format string and arguments that
    disagree, a value whose ``__str__`` raises) cannot be shown clean, and
    logging's own error path would print its raw arguments to stderr. What
    is passed on names the logger and the failure's class, nothing else.
    """
    record.msg = "logsafe: withheld an unformattable record from %s (%s)"
    record.args = (record.name, type(exc).__name__)
    record.exc_info = record.exc_text = record.stack_info = None
    for key in record.__dict__.keys() - _RECORD_ATTRS:
        record.__dict__[key] = REDACTED


def _make_record(self: logging.Logger, *args: Any, **kwargs: Any) -> logging.LogRecord:
    """``Logger.makeRecord``, then the ``extra`` fields.

    The stock method merges ``extra`` into the record AFTER the record
    factory returns, so the factory never sees those fields, and a formatter
    that prints one (a JSON formatter prints them all) would print it raw.
    """
    record = _stock_make_record(self, *args, **kwargs)
    try:
        for key in record.__dict__.keys() - _RECORD_ATTRS:
            record.__dict__[key] = _scrub_arg(record.__dict__[key])
    except Exception as exc:  # logsafe: ours — only the class is printed
        _withhold(record, exc)
    return record


def _hold_environment() -> None:
    """Hold what the environment calls a secret, for a process that never
    reaches our loaders: a harness importing the package, a benchmark."""
    for name, value in os.environ.items():
        if name.endswith(_SECRET_NAME_SUFFIXES):
            hold(value, name)


def guard() -> None:
    """Put the scrubbing factory and the request-data filters in place.

    Idempotent, and run at package import, so there is no process that
    imports Trentina and logs without it: the gateway, the bridge, a
    benchmark, someone else's harness.
    """
    previous = logging.getLogRecordFactory()
    if not _guarding(previous):
        logging.setLogRecordFactory(_Guard(previous))
    if logging.Logger.makeRecord is not _make_record:
        # setattr, because a method is not assignable to the type checker;
        # there is no hook after ``extra`` is merged, so the method is it.
        setattr(logging.Logger, "makeRecord", _make_record)  # noqa: B010
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _AccessLogFilter) for f in access.filters):
        access.addFilter(_AccessLogFilter())
    for name in ("httpx", "httpx2"):
        client_log = logging.getLogger(name)
        if not any(isinstance(f, _HttpxFilter) for f in client_log.filters):
            client_log.addFilter(_HttpxFilter())
    _hold_environment()


def _clamp(name: str, floor: int, level: int) -> None:
    logging.getLogger(name).setLevel(max(floor, level))


def install(level: int) -> None:
    """Hold the third-party loggers to the rule at any log level.

    httpcore's DEBUG names every host it connects to; the MCP SDK's and
    FastMCP's DEBUG echo whole JSON-RPC messages, arguments included;
    peewee's prints every statement with its parameters, which in the bridge
    are crypto-store rows. They stay at INFO or above however low the level
    goes: lowering it must not reopen the channel.
    """
    guard()
    _clamp("httpcore", logging.WARNING, level)
    for name in ("mcp", "fastmcp", "sse_starlette", "hpack", "h2", "peewee"):
        _clamp(name, logging.INFO, level)


def configure(level_env: str, *, default: str = "INFO") -> str:
    """Set up this process's logging; the only ``basicConfig`` in the package.

    ``level_env`` names the variable holding the level (``TRENTINA_LOG_LEVEL``
    for the gateway, ``BRIDGE_LOG_LEVEL`` for the bridge). Returns the
    resolved level name, always a key of ``LOG_LEVELS``: anything else falls
    back to ``default`` rather than crashing startup. The gateway forwards it
    to ``mcp.run(log_level=...)``, because uvicorn re-applies its own level to
    ``uvicorn.access``/``uvicorn.error`` after its dictConfig runs, so the
    root logger alone never quiets the access log. Without this call the root
    sits at WARNING and every ``logger.info`` is discarded.

    httpx tracks the level exactly, DEBUG included (#73). That is safe on two
    counts: no upstream takes a credential in its URL (the Gemini key rides
    the ``x-goog-api-key`` header), and a URL that did would be scrubbed here.
    """
    resolved = os.environ.get(level_env, default).strip().upper()
    if resolved not in LOG_LEVELS:
        resolved = default
    level = LOG_LEVELS[resolved]
    # basicConfig is a no-op once the root logger has a handler: a host that
    # configured logging first, or a library that logged on the root logger
    # (petit before 4.10.2, #344; tests/test_log_scrub.py holds every library
    # to not doing so). The level is ours either way; the format is the
    # host's if it set one.
    logging.basicConfig(level=level, format=LOG_FORMAT)
    logging.getLogger().setLevel(level)
    logging.getLogger("httpx").setLevel(level)
    install(level)
    return resolved
