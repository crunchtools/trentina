"""The log backstop (#341): no record carries a secret, whoever built it.

``tests/test_log_hygiene.py`` holds call sites to the #262 rule. This holds
the factory ``logsafe.guard()`` installs to its own: a secret that reaches a
record anyway (a library's logger, a traceback, a key in a URL) does not
print. The first test is the line that was reported: httpx's request log
with a Gemini key in the query string.

Every key-shaped value here is assembled at run time, so the file holds no
literal a secret scanner would stop on.
"""

from __future__ import annotations

import ast
import logging
import logging.config
import pathlib
import subprocess
import sys
import time
from collections.abc import Callable, Iterator

import httpx
import pytest
import uvicorn.config
from pydantic import SecretStr

from trentina import config as config_mod
from trentina import logsafe
from trentina.gateway import ingress_defense, loader
from trentina.gateway.profile import AuthConfig, Backend, Profile

#: A secret with no shape of its own, so only ``hold`` can know it.
SECRET = "hunter2-" + "zqv9" * 6
NAME = "TEST_UPSTREAM_CREDENTIAL"
MARK = f"[REDACTED:{NAME}]"

_SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "trentina"


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        # What a handler prints: the message, then exc_text / the traceback.
        self.lines.append(logging.Formatter(logsafe.LOG_FORMAT).format(record))


def _printed(logger_name: str, emit: Callable[[logging.Logger], object]) -> str:
    """Run ``emit(logger)`` and return every line a handler would print."""
    logger = logging.getLogger(logger_name)
    handler = _Capture()
    saved = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        emit(logger)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved)
    assert handler.lines, "nothing was logged"
    return "\n".join(handler.lines)


@pytest.mark.parametrize("known", [True, False], ids=["held", "pattern-only"])
@pytest.mark.parametrize("filtered", [True, False], ids=["httpx-filter", "no-filter"])
def test_the_reported_httpx_line_carries_no_key(
    monkeypatch: pytest.MonkeyPatch, known: bool, filtered: bool
) -> None:
    """``HTTP Request: POST …:generateContent?key=<key>`` at INFO. With the
    #262 filter or without it, with the key registered or not, it is gone."""
    if known:
        logsafe.hold(SECRET, NAME)
    if not filtered:
        monkeypatch.setattr(logging.getLogger("httpx"), "filters", [])
    url = httpx.URL(
        f"https://generativelanguage.googleapis.com/v1beta/models/m:generateContent?key={SECRET}"
    )
    out = _printed(
        "httpx",
        lambda log: log.info('HTTP Request: %s %s "%s %d %s"', "POST", url, "HTTP/1.1", 200, "OK"),
    )
    assert SECRET not in out
    assert '"HTTP/1.1 200 OK"' in out
    if not filtered:
        assert (MARK if known else f"?key={logsafe.REDACTED}") in out


class _Opaque:
    """An object whose text carries the secret, as a client or URL object does."""

    def __str__(self) -> str:
        return f"client<{SECRET}>"


def _log_failure(log: logging.Logger, message: str = f"upstream said no to {SECRET}") -> None:
    """A failure logged with its exception, as ``exc_info`` carries one."""
    log.warning("call failed", exc_info=ValueError(message))


#: A format with more slots than the call supplies, as a typo leaves one.
_TWO_SLOTS = "%d items for %s"


def _log_chained(log: logging.Logger) -> None:
    """The secret is two causes down; the exception logged does not name it."""
    inner = ValueError(f"401 for url https://x.example/v1 with {SECRET}")
    middle = RuntimeError("request failed")
    middle.__cause__ = inner
    outer = RuntimeError("tool call failed")
    outer.__context__ = middle
    log.warning("call failed", exc_info=outer)


def _log_grouped(log: logging.Logger) -> None:
    group = ExceptionGroup("two backends failed", [KeyError("x"), ValueError(SECRET)])
    log.warning("call failed", exc_info=group)


class _Unprintable:
    def __str__(self) -> str:
        raise RuntimeError(SECRET)


_CARRIERS = {
    "literal": lambda log: log.warning(f"using {SECRET} now"),
    "str-arg": lambda log: log.warning("using %s now", SECRET),
    "object-arg": lambda log: log.warning("using %s now", _Opaque()),
    "repr-of-container": lambda log: log.warning("headers=%r", {"x-api": SECRET}),
    "mapping-args": lambda log: log.warning("using %(cred)s now", {"cred": SECRET}),
    "format-plus-arg": lambda log: log.warning("GET /v1?key=%s", "opaque-value-1234"),
    "traceback": _log_failure,
    "traceback-cause": _log_chained,
    "traceback-group": _log_grouped,
}


@pytest.mark.parametrize("logger_name", ["trentina.x", "some.thirdparty.sdk"])
@pytest.mark.parametrize("carrier", sorted(_CARRIERS))
def test_a_secret_never_prints(logger_name: str, carrier: str) -> None:
    logsafe.hold(SECRET, NAME)
    out = _printed(logger_name, _CARRIERS[carrier])
    assert SECRET not in out
    assert "opaque-value-1234" not in out
    assert (logsafe.REDACTED if carrier == "format-plus-arg" else MARK) in out


def test_a_traceback_cannot_be_rendered_again() -> None:
    """A handler that formats ``exc_info`` itself must not get the original."""
    logsafe.hold(SECRET, NAME)
    records: list[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("trentina.x")
    handler = _Keep()
    logger.addHandler(handler)
    try:
        _log_failure(logger)
    finally:
        logger.removeHandler(handler)
    (record,) = records
    assert record.exc_info is None
    assert record.exc_text is not None
    assert MARK in record.exc_text
    assert "ValueError" in record.exc_text


def test_a_clean_traceback_keeps_its_exc_info() -> None:
    records: list[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("trentina.x")
    handler = _Keep()
    logger.addHandler(handler)
    try:
        _log_failure(logger, "nothing secret")
    finally:
        logger.removeHandler(handler)
    assert records[0].exc_info is not None


@pytest.mark.parametrize(
    "emit",
    [
        lambda log: log.warning(_TWO_SLOTS, SECRET),
        lambda log: log.warning("%(missing)s", {"cred": SECRET}),
        lambda log: log.warning("client %s", _Unprintable()),
    ],
    ids=["bad-format", "missing-key", "str-raises"],
)
def test_an_unformattable_record_is_withheld(emit: Callable[[logging.Logger], object]) -> None:
    """Logging's own error path prints the raw arguments to stderr. A record
    that cannot be rendered cannot be shown clean, so it is replaced."""
    logsafe.hold(SECRET, NAME)
    out = _printed("some.thirdparty.sdk", emit)
    assert SECRET not in out
    assert "withheld an unformattable record from some.thirdparty.sdk" in out


class _PrintsExtras(logging.Handler):
    """A formatter that prints ``extra`` fields, as a JSON formatter does."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(logging.Formatter("%(message)s %(cred)s %(ctx)s %(n)d").format(record))


@pytest.mark.parametrize("logger_name", ["trentina.x", "some.thirdparty.sdk"])
def test_an_extra_field_is_scrubbed(logger_name: str) -> None:
    """``extra`` is merged into the record after the record factory returns."""
    logsafe.hold(SECRET, NAME)
    logger = logging.getLogger(logger_name)
    handler = _PrintsExtras()
    logger.addHandler(handler)
    try:
        logger.warning("call", extra={"cred": SECRET, "ctx": {"token": SECRET}, "n": 7})
    finally:
        logger.removeHandler(handler)
    assert handler.lines == [f"call {MARK} {{'token': '{MARK}'}} 7"]


def test_an_unreadable_extra_field_is_cut() -> None:
    record = logging.getLogger("some.thirdparty.sdk").makeRecord(
        "some.thirdparty.sdk",
        logging.INFO,
        __file__,
        1,
        "m",
        (),
        None,
        extra={"cred": _Unprintable()},
    )
    assert record.__dict__["cred"] == logsafe.REDACTED
    assert "withheld an unformattable record" in record.getMessage()


def test_stack_info_is_scrubbed() -> None:
    logsafe.hold(SECRET, NAME)
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "msg", None, None)
    record.stack_info = f'File "x.py", line 1\n    call("{SECRET}")'
    logsafe._scrub_record(record)
    assert SECRET not in record.stack_info
    assert MARK in record.stack_info


def test_arguments_keep_their_shape_for_the_filters() -> None:
    """A number stays a number and the tuple keeps its length: the httpx and
    access-log filters read the arguments by position."""
    logsafe.hold(SECRET, NAME)
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "%s %d %s", (SECRET, 7, "ok"), None)
    logsafe._scrub_record(record)
    assert record.args == (MARK, 7, "ok")
    assert record.msg == "%s %d %s"


def test_the_percent_encoded_form_is_held_too() -> None:
    secret = "p@ss/word+with=reserved&chars"
    logsafe.hold(secret, NAME)
    encoded = httpx.URL("https://h.example/x", params={"q": secret}).query.decode()
    assert secret not in logsafe.scrub(f"GET /x?{encoded}")
    assert "p%40ss" not in logsafe.scrub("cred=p%40ss%2Fword%2Bwith%3Dreserved%26chars")


def test_a_short_value_is_not_held_on_its_name_alone() -> None:
    """``FOO_KEY=1`` is not a secret; replacing every ``true`` or ``8019``
    would shred the log and hide nothing."""
    for value in ("1", "true", "8019", "abc1234"):
        assert logsafe.hold(value, NAME) is False
    assert logsafe.held_count() == 0
    line = "config: port 8019 enabled=true abc1234"
    assert logsafe.scrub(line) == line


@pytest.mark.usefixtures("env_names")
def test_a_short_declared_secret_is_held(monkeypatch: pytest.MonkeyPatch) -> None:
    """What ``read_secret_env`` returns IS a secret, so the bar is lower."""
    monkeypatch.setenv("TEST_BACKEND_CRED", "s3cr")
    loader.read_secret_env("TEST_BACKEND_CRED")
    assert logsafe.scrub("auth s3cr refused") == "auth [REDACTED:TEST_BACKEND_CRED] refused"


@pytest.mark.usefixtures("env_names")
def test_a_secret_too_short_to_hold_is_said_so(monkeypatch: pytest.MonkeyPatch) -> None:
    """Three characters cannot be told from ordinary text. The operator is
    told which variable, once, and never the value."""
    monkeypatch.setenv("TEST_TINY_CRED", "zq9")
    monkeypatch.setattr(loader, "_short_secret_warned", set())
    out = _printed(loader.logger.name, lambda _: loader.read_secret_env("TEST_TINY_CRED"))
    assert "TEST_TINY_CRED is under 4 characters" in out
    assert "zq9" not in out
    assert logsafe.held_count() == 0
    again = _Capture()
    loader.logger.addHandler(again)
    try:
        loader.read_secret_env("TEST_TINY_CRED")
    finally:
        loader.logger.removeHandler(again)
    assert again.lines == []


@pytest.mark.parametrize(
    "written",
    [
        "tok%2Fwith%2Breserved%3Dchars%26more",
        "tok%2fwith%2breserved%3dchars%26more",
        "tok%2fwith%2Breserved%3Dchars%26more",
    ],
    ids=["upper", "lower", "mixed"],
)
def test_percent_escapes_are_held_in_any_case(written: str) -> None:
    """``%2f`` and ``%2F`` are the same byte to a server, and a client may
    write either, or both."""
    logsafe.hold("tok/with+reserved=chars&more", NAME)
    assert logsafe.scrub(f"GET /hook/{written}/x") == f"GET /hook/{MARK}/x"


def test_a_secret_that_spells_anothers_encoding_is_still_held() -> None:
    """``tok%2Fabcd`` is how ``tok/abcd`` encodes, and is a secret of its own:
    it gets its own encoded form, and neither hides the other."""
    logsafe.hold("tok/abcd", "FIRST")
    logsafe.hold("tok%2Fabcd", "SECOND")
    assert logsafe.held_count() == 2
    assert logsafe.scrub("x tok%252Fabcd y") == "x [REDACTED:SECOND] y"
    assert logsafe.scrub("x tok/abcd y") == "x [REDACTED:FIRST] y"


def test_a_structured_value_keeps_its_shape() -> None:
    """A JSON formatter is handed a mapping, not the text of one."""
    logsafe.hold(SECRET, NAME)
    value = {"token": SECRET, "n": 7, "tags": ["a", SECRET], "pair": (1, SECRET), "ok": True}
    assert logsafe._scrub_arg(value) == {
        "token": MARK,
        "n": 7,
        "tags": ["a", MARK],
        "pair": (1, MARK),
        "ok": True,
    }
    deep: object = SECRET
    for _ in range(logsafe._MAX_DEPTH + 3):
        deep = [deep]
    assert SECRET not in str(logsafe._scrub_arg(deep))


def test_many_held_secrets_stay_cheap() -> None:
    """A deployment holds a secret per profile, backend and provider. A line
    that carries none is a substring test per value, and nothing is compiled
    until a line carries one."""
    for index in range(500):
        logsafe.hold(f"held-secret-number-{index:04d}-{'q' * 24}", f"NAME_{index}")
    assert logsafe._held_compiled is None
    line = "gateway: call_tool failed backend=mail tool=read_mail err=BackendCallError status=502"
    start = time.perf_counter()
    for _ in range(2000):
        assert logsafe.scrub(line) == line
    assert time.perf_counter() - start < 2.0
    assert logsafe._held_compiled is None
    assert logsafe.scrub(f"x held-secret-number-0042-{'q' * 24}") == "x [REDACTED:NAME_42]"


def test_the_longer_secret_wins() -> None:
    logsafe.hold("shared-prefix-value", "SHORT")
    logsafe.hold("shared-prefix-value-and-more", "LONG")
    assert logsafe.scrub("x shared-prefix-value-and-more y") == "x [REDACTED:LONG] y"


@pytest.fixture
def env_names() -> Iterator[None]:
    """``read_secret_env`` records the names it is asked for; put them back."""
    secret, profile = set(loader._secret_env_names), set(loader._profile_env_names)
    try:
        yield
    finally:
        loader._secret_env_names.clear()
        loader._secret_env_names.update(secret)
        loader._profile_env_names.clear()
        loader._profile_env_names.update(profile)


@pytest.mark.usefixtures("env_names")
def test_read_secret_env_holds_what_it_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    """The name has no secret-looking suffix, so only the loader can know it."""
    monkeypatch.setenv("TEST_BACKEND_CRED", SECRET)
    assert loader.read_secret_env("TEST_BACKEND_CRED") == SECRET
    assert logsafe.scrub(f"x {SECRET}") == "x [REDACTED:TEST_BACKEND_CRED]"


@pytest.mark.usefixtures("env_names")
def test_read_secret_env_holds_a_file_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    path = tmp_path / "cred"
    path.write_text(SECRET + "\n", encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.delenv("TEST_BACKEND_CRED", raising=False)
    monkeypatch.setenv("TEST_BACKEND_CRED_FILE", str(path))
    assert loader.read_secret_env("TEST_BACKEND_CRED") == SECRET
    assert logsafe.scrub(f"x {SECRET}") == "x [REDACTED:TEST_BACKEND_CRED]"


def test_guard_holds_the_environments_secrets_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """A harness that imports the package and never calls a loader."""
    monkeypatch.setenv("HARNESS_API_KEY", SECRET)
    monkeypatch.setenv("HARNESS_KEY_FILE", "/run/secrets/a-long-path-not-a-secret")
    monkeypatch.setenv("CLASSIFIER_MAX_TOKENS", "3276800000")
    logsafe.guard()
    assert logsafe.scrub(SECRET) == "[REDACTED:HARNESS_API_KEY]"
    assert logsafe.scrub("/run/secrets/a-long-path-not-a-secret").startswith("/run/secrets")
    assert logsafe.scrub("cap 3276800000") == "cap 3276800000"


_TAIL = "Zq7" * 14  # 42 characters of key body

_ATTACKS = [
    ("query-key", f"POST https://h.example/v1/m:generate?key={_TAIL}", _TAIL),
    ("query-token", f"GET /sync?since=s1&access_token={_TAIL}&x=1", _TAIL),
    ("query-api-key", f"GET /v1?API_KEY={_TAIL}", _TAIL),
    ("bearer", f"headers: Authorization: Bearer {_TAIL}", _TAIL),
    ("basic", f"Authorization: Basic {_TAIL}==", _TAIL),
    ("userinfo", "connecting to https://svc:s3cretpass@db.example:5432/x", "s3cretpass"),
    ("openai-shape", "key " + "sk" + "-proj-" + _TAIL, _TAIL),
    ("anthropic-shape", "key " + "sk" + "-ant-api03-" + _TAIL, _TAIL),
    ("google-shape", "key " + "AI" + "za" + _TAIL[:35], _TAIL[:35]),
    ("google-oauth-shape", "tok " + "ya" + "29." + _TAIL, _TAIL),
    ("matrix-shape", "tok " + "sy" + "t_" + _TAIL, _TAIL),
    ("github-shape", "tok " + "gh" + "p_" + _TAIL, _TAIL),
    ("slack-shape", "tok " + "xo" + "xb-" + _TAIL, _TAIL),
    ("jwt-shape", "tok " + "ey" + "J" + _TAIL + "." + "ey" + "J" + _TAIL + "." + _TAIL, _TAIL),
    ("aws-access-key", "key " + "AK" + "IA" + "IOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    # The redactor consumes the body, not just the header: the key bytes go too.
    (
        "pem-private-key",
        "-----BE" + "GIN RSA PRIVATE KEY-----\nMIIsecretbody\n-----EN" + "D RSA PRIVATE KEY-----",
        "MIIsecretbody",
    ),
]

#: Lines this codebase and its neighbours really print. None may change.
_BENIGN = [
    "provider: initialized gemini (model=gemini-2.5-flash-lite, key=override)",
    "gateway: oauth ok profile=josui sub=1 email=a@example.com aud=x token=3fa9c1d2…",
    "perimeter: judgement failed for key=0a1b2c3d4e5f: TimeoutError at agent.py:10 in f",
    "GET /search?monkey=banana&turkey=1",
    "Bearer token authentication for gateway endpoints",
    'WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/x"',
    "matrix_proxy: registered /matrix/{path} → http://conduit:6167 for 2 profile(s): a, b",
    "bridge[josui]: joined @agent:matrix.example.org at https://matrix.example.org/_matrix",
    "transform: task-0123456789012345678901 risk-level=high desk-0123456789012345678901",
    "fetch: sha256:3fa9c1d2aaaa len=120 status=200",
    "eyJ is how a JWT starts; eyJhbGciOi alone is not one",
    "posture: GEMINI_API_KEY came from the environment; use the _FILE form",
    "note: AKIAEXAMPLE is too short to be an access key id",
    "doc: a PEM file opens with -----BEGIN PUBLIC KEY----- for the public half",
]


@pytest.mark.parametrize(
    ("line", "secret"), [a[1:] for a in _ATTACKS], ids=[a[0] for a in _ATTACKS]
)
def test_a_credential_shape_is_cut(line: str, secret: str) -> None:
    out = logsafe.scrub(line)
    assert secret not in out
    assert logsafe.REDACTED in out


@pytest.mark.parametrize("line", _BENIGN)
def test_an_ordinary_line_is_untouched(line: str) -> None:
    assert logsafe.scrub(line) == line


def test_a_held_name_survives_the_query_pattern() -> None:
    """``?key=[REDACTED:NAME]`` must not be flattened to ``[REDACTED]``."""
    logsafe.hold(SECRET, NAME)
    assert logsafe.scrub(f"GET /v1?key={SECRET}&x=1") == f"GET /v1?key={MARK}&x=1"


_HOSTILE = [
    "?key=",
    "&token=a",
    "Bearer ",
    "Bearer" + " " * 64,
    "://a:",
    "://a:b",
    "sk-",
    "eyJ",
    "eyJaaaaaaaa.",
    "eyJaaaaaaaa.eyJaaaaaaaa.",
    "ya29.",
    "xoxb-",
    "AKIA",
    "-----BEGIN ",
    "-----BEGIN A PRIVATE KEY-----",  # the PEM redactor's body loop
    "%2f",
    "%2",
]


@pytest.mark.parametrize("unit", _HOSTILE)
def test_scrub_stays_linear(unit: str) -> None:
    """The log is fed by callers; a pattern that rescans is a way to stall it."""
    logsafe.hold(SECRET, NAME)
    for text in (unit * (1_000_000 // len(unit)), unit + "a" * 1_000_000):
        start = time.perf_counter()
        logsafe.scrub(text)
        assert time.perf_counter() - start < 2.0


@pytest.fixture
def logging_state() -> Iterator[None]:
    names = ("", "httpx", "httpcore", "mcp", "fastmcp", "peewee", "uvicorn", "uvicorn.access")
    saved = {
        n: (
            logging.getLogger(n).level,
            list(logging.getLogger(n).handlers),
            logging.getLogger(n).propagate,
        )
        for n in (*names, "uvicorn.error")
    }
    try:
        yield
    finally:
        for name, (level, handlers, propagate) in saved.items():
            log = logging.getLogger(name)
            log.setLevel(level)
            log.handlers[:] = handlers
            log.propagate = propagate


def test_the_package_guards_on_import() -> None:
    assert logsafe._guarding(logging.getLogRecordFactory())


@pytest.mark.usefixtures("logging_state")
def test_the_guard_survives_configure_and_uvicorns_dictconfig(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "debug")
    assert logsafe.configure("TRENTINA_LOG_LEVEL") == "DEBUG"
    logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)
    assert logsafe._guarding(logging.getLogRecordFactory())
    access = logging.getLogger("uvicorn.access")
    assert any(isinstance(f, logsafe._AccessLogFilter) for f in access.filters)
    assert any(isinstance(f, logsafe._HttpxFilter) for f in logging.getLogger("httpx").filters)


def test_guard_is_idempotent() -> None:
    before = logging.getLogRecordFactory()
    logsafe.guard()
    logsafe.guard()
    assert logging.getLogRecordFactory() is before
    assert logging.Logger.makeRecord is logsafe._make_record
    assert logsafe._stock_make_record is not logsafe._make_record
    assert sum(isinstance(f, logsafe._HttpxFilter) for f in logging.getLogger("httpx").filters) == 1


@pytest.mark.parametrize(
    ("asked", "default", "resolved"),
    [
        ("warning", "INFO", "WARNING"),
        ("nonsense", "WARNING", "WARNING"),
        ("NOTSET", "INFO", "INFO"),
        ("_STYLES", "INFO", "INFO"),
    ],
)
@pytest.mark.usefixtures("logging_state")
def test_configure_resolves_a_level_or_falls_back(
    monkeypatch: pytest.MonkeyPatch, asked: str, default: str, resolved: str
) -> None:
    monkeypatch.setenv("BRIDGE_LOG_LEVEL", asked)
    assert logsafe.configure("BRIDGE_LOG_LEVEL", default=default) == resolved


@pytest.mark.usefixtures("logging_state")
def test_configure_uses_the_default_when_the_variable_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BRIDGE_LOG_LEVEL", raising=False)
    assert logsafe.configure("BRIDGE_LOG_LEVEL", default="WARNING") == "WARNING"


@pytest.mark.usefixtures("logging_state")
def test_configure_sets_the_root_level_when_the_root_has_a_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``basicConfig`` is a no-op here (pytest's handlers are on the root),
    so the level has to be set directly or the host's stays in effect."""
    assert logging.getLogger().handlers
    monkeypatch.setenv("BRIDGE_LOG_LEVEL", "debug")
    assert logsafe.configure("BRIDGE_LOG_LEVEL", default="WARNING") == "DEBUG"
    assert logging.getLogger().level == logging.DEBUG


#: Imports the bridge and drives petit, then prints the root logger's handlers.
_ROOT_PROBE = """
import logging
import trentina.bridge.main
from petit import analyze_text
analyze_text("\\n".join(f"host app[{i}]: request {i} done in {i}ms" for i in range(200)))
print(len(logging.getLogger().handlers))
"""


def test_no_library_gives_the_root_logger_a_handler() -> None:
    """``configure``'s basicConfig is a no-op once the root logger has a
    handler. petit before 4.10.2 gave it one by logging on the root logger,
    and the bridge then logged at WARNING in the default format (#344). A
    fresh process, because pytest's own capture handlers sit on the root."""
    probe = subprocess.run(
        [sys.executable, "-c", _ROOT_PROBE], capture_output=True, text=True, check=True
    )
    assert probe.stdout.strip() == "0", probe.stderr


@pytest.mark.usefixtures("env_names")
def test_a_setting_read_like_a_secret_is_not_held(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bridge's profile name takes the ``_FILE`` form and is no secret:
    holding it cut it from every bridge log line (#344)."""
    monkeypatch.setenv("BRIDGE_PROFILE", "takeda-profile")
    assert loader.read_env_or_file("BRIDGE_PROFILE") == "takeda-profile"
    assert logsafe.held_count() == 0
    assert "BRIDGE_PROFILE" not in loader.secret_env_names()
    line = "bridge[takeda-profile]: resumed"
    assert logsafe.scrub(line) == line


@pytest.mark.usefixtures("env_names")
def test_bridge_settings_hold_the_secrets_and_not_the_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from trentina.bridge.settings import BridgeSettings

    for name, value in {
        "BRIDGE_PROFILE": "takeda-profile",
        "BRIDGE_USER_ID": "@agent:matrix.example.org",
        "BRIDGE_GATEWAY_URL": "http://gateway.internal:8019",
        "BRIDGE_ALLOWED_INVITERS": "@owner:matrix.example.org",
        "BRIDGE_PICKLE_KEY": "pickle-" + "k" * 24,
        "BRIDGE_INGRESS_TOKEN": "ingress-" + "t" * 24,
        "BRIDGE_TOKEN": "bridge-" + "t" * 24,
        "BRIDGE_PASSWORD": "password-" + "p" * 24,
    }.items():
        monkeypatch.setenv(name, value)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    monkeypatch.delenv("BRIDGE_ACCESS_TOKEN", raising=False)
    monkeypatch.setattr("trentina.bridge.settings.private_url", lambda value: value.rstrip("/"))
    settings = BridgeSettings.from_env()
    assert (
        logsafe.scrub(f"bridge[{settings.profile}]: resumed") == "bridge[takeda-profile]: resumed"
    )
    for held in ("pickle_key", "ingress_token", "bridge_token", "password", "user_id"):
        assert logsafe.scrub(f"x {getattr(settings, held)} y").startswith("x [REDACTED:BRIDGE_")
    assert "gateway.internal" not in logsafe.scrub(f"posting to {settings.gateway_url}/bridge")


def test_install_clamps_peewee() -> None:
    """peewee's DEBUG prints each statement with its parameters: in the
    bridge, rows of the crypto store."""
    logsafe.install(logging.DEBUG)
    assert not logging.getLogger("peewee").isEnabledFor(logging.DEBUG)


_SETUP_CALLS = {"basicConfig", "dictConfig", "fileConfig", "setLogRecordFactory"}


def test_only_logsafe_configures_logging() -> None:
    """A second ``basicConfig`` is a process that logs with its own format
    and, before #341, without the filters. A second record factory would
    replace the guard."""
    found = []
    for path in sorted(_SRC.rglob("*.py")):
        if path.name == "logsafe.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found += [
            f"{path.relative_to(_SRC)}:{node.lineno}: {node.func.attr}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _SETUP_CALLS
        ]
    assert not found, "logging is configured outside logsafe:\n" + "\n".join(found)


_PASTED = "pasted-into-the-wrong-variable-0042"


def test_a_misset_boolean_does_not_print_its_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRENTINA_TEST_FLAG", _PASTED)
    out = _printed(
        config_mod.logger.name, lambda _: config_mod.bool_env("TRENTINA_TEST_FLAG", True)
    )
    assert _PASTED not in out
    assert "TRENTINA_TEST_FLAG" in out


def test_a_misset_integer_does_not_print_its_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRENTINA_TEST_COUNT", _PASTED)
    out = _printed(config_mod.logger.name, lambda _: config_mod.int_env("TRENTINA_TEST_COUNT", 4))
    assert _PASTED not in out
    assert "TRENTINA_TEST_COUNT" in out


def test_a_bad_override_does_not_print_its_value(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = Profile(
        short_names=False,
        name="testp",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={"b": Backend(url="http://b:8000/mcp", tools_allow=["*"])},
    )
    profile.auth.bearer_token = SecretStr("testp-token")
    monkeypatch.setenv(ingress_defense._OVERRIDE_ENV, _PASTED)
    out = _printed(ingress_defense.logger.name, lambda _: ingress_defense.effective_mode(profile))
    assert _PASTED not in out
    assert ingress_defense._OVERRIDE_ENV in out


@pytest.mark.parametrize(
    "url",
    [
        "https://hooks.example.com/services/T000/B000/" + _TAIL,
        "https://hooks.example.com/alert?token=" + _TAIL,
        "https://user:" + _TAIL + "@hooks.example.com/alert",
    ],
)
def test_safe_url_drops_what_a_webhook_url_hides(url: str) -> None:
    assert logsafe.safe_url(url) == "https://hooks.example.com"
