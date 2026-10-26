"""Configuration for trentina."""

from __future__ import annotations

import functools
import json
import logging
import os
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse

from pydantic import SecretStr

from .logsafe import redact_source

logger = logging.getLogger(__name__)

_config: Config | None = None

DEFAULT_PROVIDER = "gemini"
DEFAULT_MODEL = "gemini-3.5-flash-lite"
DEFAULT_SEARCH_MODEL = "google/gemini-3.5-flash-lite"
DEFAULT_CLASSIFIER_THRESHOLD = 0.5
"""The cut for a model directory with no ``trentina-model.json`` (#350).

A baked model's manifest carries its own threshold, and
``CLASSIFIER_THRESHOLD`` overrides either."""

CLASSIFIER_MODELS_DIR = "/models"
DEFAULT_CLASSIFIER_MODEL = "prompt-injection-guard-small-ct"
"""The L2 model the image selects by name (#350): Horizon-Labs'
prompt-injection-guard-small fine-tuned on benign tool replies (#17), the
one model it ships (#362). Any other model is a directory named by
``CLASSIFIER_MODEL_PATH``."""

DEFAULT_CLASSIFIER_MAX_TOKENS = 32_768
"""L2's CPU budget per payload, ~74 sliding windows at stride 446.

A DoS guard, not a model limit: the classifier's window is 512 tokens and
``classify()`` slides it across everything it is given. One of the two
inputs to ``Config.admission_tokens``."""

DEFAULT_QUARANTINE_CONTEXT_TOKENS = 1_000_000
"""What the L3 model can read in one call. Gemini 2.5 Flash-Lite's window;
set it lower for a smaller provider (Ollama's default model reads 32k). The
other input to ``Config.admission_tokens``."""

DEFAULT_PART_TOKENS = 12_000
"""The size a paged response's parts aim for, in L2's tokens (#340).

A part is the largest thing that reliably beats the client's 60 s: at
0.7 ms a token on production CPU, 12K is about 9 s of L2, and measured end
to end a 32 to 64 KB response ran 13.5 s at the median and 29 s at the 95th
percentile. Part size does not change the total L2 work, and every extra
part costs an L3 call and an agent turn, so smaller is not cheaper. 0 turns
paging off."""

PART_WHOLE_RATIO = (4, 3)
"""A response up to this multiple of ``DEFAULT_PART_TOKENS`` is delivered
whole: 16K tokens with the default. One just over the target is not worth a
second call."""

PART_LEAD_TOKENS = 64
"""Tokens of the part before that a part is judged behind: L2's guard band
(``classifier.GUARD_TOKENS``; a test holds the two equal). Reserved out of
the admission cap so a part and its lead-in are always admitted together."""

PART_SLACK = 10
"""A cut may move back one part in this many to land on a line break
(``paging.BOUNDARY_SLACK``), which makes the part after it that much larger."""

DEFAULT_MAX_PARTS = 16
"""The most parts one response is cut into: 192K tokens with the default
size. Over it the response is refused as over the admission cap, as before."""

DEFAULT_PART_TTL_SECONDS = 600
"""How long a paged response is held without a part of it being read."""

MIN_PART_TTL_SECONDS = 30
"""The shortest hold a setting may ask for: under it an agent cannot read
part 1 and ask for part 2 before the rest is gone."""

DEFAULT_BLOCKLIST_TTL_DAYS = 30
"""Days a block refusal keeps its source on the calling profile's blocklist."""

DEFAULT_CLASSIFIER_THREADS = 4
"""ONNX intra-op threads. Its own default is one per core with a spin-wait,
which lets a single inference saturate the host.

Set this to match the container's CPU allocation. Threads beyond that just
contend for the same quota and make scans slower — measured on host01
(6 vCPU) against a 9,100-token article:

    --cpus=2, threads=2   39.2s
    --cpus=2, threads=4   44.5s   <- contention, worse than half the threads
    --cpus=6, threads=6   28.0s
    --cpus=4, threads=4   23.2s   <- deployed
"""
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5:0.5b"
SUPPORTED_PROVIDERS = ("gemini", "openai", "anthropic", "ollama", "openrouter")


def classifier_settings() -> tuple[float | None, str, str]:
    """``(threshold override, model name, model directory)`` for L2 (#350).

    An unset ``CLASSIFIER_THRESHOLD`` is None: the loaded model's manifest
    decides, and ``classifier.model_info()`` reports the threshold in force.
    ``CLASSIFIER_MODEL`` names a model under ``CLASSIFIER_MODELS_DIR``;
    ``CLASSIFIER_MODEL_PATH`` wins over it, since that is how an operator
    tries a model the image does not ship.
    """
    threshold_raw = os.environ.get("CLASSIFIER_THRESHOLD", "").strip()
    threshold = float(threshold_raw) if threshold_raw else None
    name = os.environ.get("CLASSIFIER_MODEL", "").strip() or DEFAULT_CLASSIFIER_MODEL
    if "/" in name or name in (".", ".."):
        from .errors import ConfigError

        raise ConfigError(
            f"CLASSIFIER_MODEL names a model under {CLASSIFIER_MODELS_DIR}; "
            "use CLASSIFIER_MODEL_PATH for a directory"
        )
    path = os.environ.get("CLASSIFIER_MODEL_PATH", "").strip() or f"{CLASSIFIER_MODELS_DIR}/{name}"
    return threshold, name, path


def bool_env(name: str, default: bool) -> bool:
    """Read a true/false environment variable; anything unrecognised is the default.

    A typo in a security opt-out must not silently open it, so only an
    explicit false-ish value turns a default-true setting off.
    """
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    if raw:
        # The value is not printed: a key pasted into the wrong variable
        # would be (#341). Its fingerprint and length tell a typo from that.
        logger.warning(
            "config: %s (%s) is not a boolean — using %s", name, redact_source(raw), default
        )
    return default


def part_settings() -> tuple[int, int, int]:
    """``TRENTINA_PART_TOKENS``, ``TRENTINA_MAX_PARTS`` and
    ``TRENTINA_PART_TTL_SECONDS`` (#340): the part size a paged response aims
    for (0 turns paging off), the most parts one is cut into, and the seconds
    one is held unread."""
    return (
        int_env("TRENTINA_PART_TOKENS", DEFAULT_PART_TOKENS, minimum=0),
        int_env("TRENTINA_MAX_PARTS", DEFAULT_MAX_PARTS, minimum=2),
        int_env(
            "TRENTINA_PART_TTL_SECONDS", DEFAULT_PART_TTL_SECONDS, minimum=MIN_PART_TTL_SECONDS
        ),
    )


def int_env(name: str, default: int, *, minimum: int | None = None) -> int:
    """Read an integer environment variable, recovering from a bad value.

    A typo in a tuning knob must not stop the gateway from starting: it takes
    the documented default, says which variable it could not read, and
    continues. The name is in the message because the alternative — a silent
    fallback — looks identical to the value having been applied.

    ``minimum`` clamps rather than rejects, for knobs where a small value is
    meaningful but a tiny one is pathological (a one-second sweep interval,
    say). Clamping keeps the operator's intent, which was "make it small".

    Every caller's variable belongs in README.md's environment table.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default if minimum is None else max(minimum, default)
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "config: %s (%s) is not an integer — using %d",
            name,
            redact_source(raw),
            default,
        )
        return default if minimum is None else max(minimum, default)
    return value if minimum is None else max(minimum, value)


DEFAULT_PROVIDER_FALLBACK: list[str] = []

#: Named for OpenRouter's prompt-injection guardrail actions (#200), which is
#: the vocabulary most people arriving here already know.
MODE_NAMES = ("block", "flag", "redact")


def canonical_mode(name: str) -> str:
    """``name`` stripped and lower-cased.

    ``warn``/``clean``, the pre-0.35.0 spellings of flag and redact, were
    mapped here for one minor and dropped at 0.36.0 as announced; they are
    now unknown modes like any other word.
    """
    return name.strip().lower()


def _mode_policy_env() -> tuple[str, tuple[str, ...]]:
    """``TRENTINA_MODE`` and ``TRENTINA_MODES``, refused at startup when wrong.

    Refused rather than defaulted, unlike the tuning knobs: a typo in a
    security policy that quietly fell back would look exactly like the
    policy having been applied.
    """
    from .errors import ConfigError

    default = canonical_mode(os.environ.get("TRENTINA_MODE", "")) or "block"
    raw = os.environ.get("TRENTINA_MODES", "")
    allowed = tuple(dict.fromkeys(canonical_mode(m) for m in raw.split(",") if m.strip()))
    allowed = allowed or (default,)
    for name in (default, *allowed):
        if name not in MODE_NAMES:
            raise ConfigError(f"unknown trentina mode {name!r}: use {', '.join(MODE_NAMES)}")
    if default == "redact":
        raise ConfigError("TRENTINA_MODE cannot be redact: a default carries no extraction prompt")
    if default not in allowed:
        raise ConfigError(f"TRENTINA_MODE {default!r} must be in TRENTINA_MODES {list(allowed)}")
    return default, allowed


def _read_roots_env() -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """``TRENTINA_READ_ROOTS``: the directories read_tool and dir_tool may reach (#261).

    ``os.pathsep``-separated. Returned twice: resolved, so a root reached
    through a symlinked directory compares against resolved targets; and as
    written (normalized), for confinement's check on the path as the agent
    spelled it, which runs before anything is resolved (#263).
    A relative entry is refused at startup: it would be relative to whatever
    directory the process happened to start in.
    """
    from .errors import ConfigError

    roots = []
    written = []
    for entry in os.environ.get("TRENTINA_READ_ROOTS", "").split(os.pathsep):
        if not entry.strip():
            continue
        if not os.path.isabs(entry.strip()):
            raise ConfigError(f"TRENTINA_READ_ROOTS entry {entry!r} is not an absolute path")
        roots.append(Path(entry.strip()).resolve())
        written.append(Path(os.path.normpath(entry.strip())))
    return tuple(roots), tuple(written)


REASONING_EFFORTS = ("minimal", "low", "medium", "high")
"""How long a reasoning judge may think (OpenRouter's ``reasoning.effort``).
Unset, the model's own default applies: Gemini 3.8 Flash then takes 6 to 17
seconds a call, against a median of six at ``minimal`` (docs/benchmark.md)."""


def _reasoning_effort() -> str | None:
    """``QUARANTINE_REASONING_EFFORT``, or None when it is unset or empty."""
    effort = os.environ.get("QUARANTINE_REASONING_EFFORT") or None
    if effort not in (None, *REASONING_EFFORTS):
        from .errors import ConfigError

        raise ConfigError(
            f"QUARANTINE_REASONING_EFFORT must be one of {', '.join(REASONING_EFFORTS)}"
        )
    return effort


class Config:
    """Trentina configuration from environment variables.

    L3 (the Q-Agent) needs a key for its provider: TRENTINA_MODEL_PROVIDER
    and the matching *_API_KEY standalone, a profile's llm_keys behind the
    gateway. L1 and L2 work without one.
    """

    def __init__(self) -> None:
        self.provider: str = os.environ.get(
            "TRENTINA_MODEL_PROVIDER",
            DEFAULT_PROVIDER,
        )

        # Each takes a _FILE form, which wins (#268): a key in the environment
        # stays readable at /proc/self/environ whatever envscrub pops later.
        from .gateway.loader import read_secret_env

        raw_key = read_secret_env("GEMINI_API_KEY", record=False)
        self.api_key: SecretStr = SecretStr(raw_key) if raw_key else SecretStr("")
        self.openai_api_key: str = read_secret_env("OPENAI_API_KEY", record=False)
        self.anthropic_api_key: str = read_secret_env("ANTHROPIC_API_KEY", record=False)
        self.openrouter_api_key = SecretStr(read_secret_env("OPENROUTER_API_KEY", record=False))
        self.ollama_base_url: str = os.environ.get(
            "OLLAMA_BASE_URL",
            DEFAULT_OLLAMA_BASE_URL,
        )
        self.ollama_model: str = os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)

        self.model: str = os.environ.get("QUARANTINE_MODEL", DEFAULT_MODEL)
        self.reasoning_effort: str | None = _reasoning_effort()
        self.search_model: str = os.environ.get("QUARANTINE_SEARCH_MODEL", DEFAULT_SEARCH_MODEL)
        if "QUARANTINE_FALLBACK" in os.environ:
            from .errors import ConfigError

            # Gone as of 0.31.0, and refused rather than ignored: it only ever
            # governed clean_*, defaulted to failing OPEN, and an operator who
            # still sets it believes a knob exists that no longer does.
            raise ConfigError(
                "QUARANTINE_FALLBACK no longer exists (0.31.0). block and clean "
                "now refuse when a layer cannot run; set TRENTINA_REQUIRE_L3=false "
                "(or TRENTINA_REQUIRE_L2=false) to deliver with a warning instead."
            )
        # Constitution-level default: block and clean need a verdict from
        # every layer. False turns that layer's ABSENCE into a warning; it
        # never excuses a partial scan and never stops a layer that can run.
        self.require_l2: bool = bool_env("TRENTINA_REQUIRE_L2", True)
        self.require_l3: bool = bool_env("TRENTINA_REQUIRE_L3", True)
        # Both are fail-closed switches turned off, so they say so at startup
        # the way the egress escape hatch below does (#298). Silence here let
        # a stale env file deliver unjudged content with nobody the wiser.
        for layer, required in (("L2", self.require_l2), ("L3", self.require_l3)):
            if not required:
                logger.warning(
                    "[WARNING] TRENTINA_REQUIRE_%s is off: block and redact deliver "
                    "with a warning when %s is unavailable instead of refusing. "
                    "Unset it unless this deployment runs without %s on purpose.",
                    layer,
                    layer,
                    layer,
                )
        # The egress guard's one escape hatch (#260): lets fetch reach a
        # non-global address. Scheme, port and redirect rules still hold.
        self.fetch_allow_private: bool = bool_env("TRENTINA_FETCH_ALLOW_PRIVATE", False)
        if self.fetch_allow_private:
            logger.warning(
                "[WARNING] TRENTINA_FETCH_ALLOW_PRIVATE is on: fetch can reach loopback, "
                "private and link-local addresses, including this host's other services. "
                "Unset it unless a trusted internal site must be fetched."
            )
        # The mode policy when no gateway profile is bound (#193): the agent of
        # a standalone server may pass trentina_mode, but only from this set,
        # and an omitted one is TRENTINA_MODE. Both default to block, so an
        # injection cannot argue a standalone server into warn either.
        self.default_mode, self.allowed_modes = _mode_policy_env()
        if "QUARANTINE_MAX_CONTENT" in os.environ:
            from .errors import ConfigError

            # Gone as of 0.43.0 (#225), and refused rather than ignored: a
            # character cap beside a token cap was two units governing one
            # question, and an operator who still sets it believes it applies.
            raise ConfigError(
                "QUARANTINE_MAX_CONTENT no longer exists (0.43.0). Content is "
                "admitted on its token count: CLASSIFIER_MAX_TOKENS for L2's "
                "budget, QUARANTINE_CONTEXT_TOKENS for L3's context window."
            )
        self.l3_context_tokens: int = int_env(
            "QUARANTINE_CONTEXT_TOKENS", DEFAULT_QUARANTINE_CONTEXT_TOKENS, minimum=1
        )

        fallback_raw = os.environ.get("TRENTINA_PROVIDER_FALLBACK", "")
        fallback_list = [p.strip() for p in fallback_raw.split(",") if p.strip()]
        for p in fallback_list:
            if p not in SUPPORTED_PROVIDERS:
                from .errors import ConfigError

                raise ConfigError(
                    f"Unknown fallback provider {p!r}. Supported: {SUPPORTED_PROVIDERS}"
                )
        self.provider_fallback: list[str] = fallback_list

        # The threshold override (None: the model's own), the name, the dir.
        self.classifier_threshold, self.classifier_model, self.classifier_model_path = (
            classifier_settings()
        )
        self.classifier_max_tokens: int = int(
            os.environ.get("CLASSIFIER_MAX_TOKENS", str(DEFAULT_CLASSIFIER_MAX_TOKENS))
        )
        self.classifier_threads: int = int(
            os.environ.get("CLASSIFIER_THREADS", str(DEFAULT_CLASSIFIER_THREADS))
        )

        home_db = str(Path.home() / ".local" / "share" / "trentina" / "trentina.db")
        self.db_path: str = os.environ.get("QUARANTINE_DB", home_db)

        # The perimeter's own store, deliberately a SEPARATE database file
        # rather than another table next to the blocklist. On today's
        # single-uid deployment that buys no isolation — both files belong
        # to the same process — but it is what makes a later move to a real
        # database able to give the two a different owner and a different
        # code path. Cheap now, impossible to retrofit once callers assume
        # one connection.
        self.perimeter_db_path: str = os.environ.get(
            "TRENTINA_PERIMETER_DB",
            str(Path(self.db_path).parent / "perimeter.db"),
        )

        self.read_roots: tuple[Path, ...]
        self.read_roots_written: tuple[Path, ...]
        self.read_roots, self.read_roots_written = _read_roots_env()
        # How long a block refusal keeps its source on the blocklist (#263).
        # Rows never expired before, which made the table a dead drop.
        self.blocklist_ttl_days: int = int_env(
            "TRENTINA_BLOCKLIST_TTL_DAYS", DEFAULT_BLOCKLIST_TTL_DAYS, minimum=1
        )

        trust_config_path = os.environ.get(
            "QUARANTINE_TRUST_CONFIG",
            str(Path.home() / ".config" / "mcp-env" / "trentina-trust.json"),
        )
        self.trust_config_path: str = trust_config_path
        try:
            with open(trust_config_path) as fh:
                self._trust_config: dict[str, list[str] | str] = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            self._trust_config = {
                "trusted_domains": [],
                "trusted_paths": [],
                "default_trust": "untrusted",
            }

    @property
    def admission_tokens(self) -> int:
        """The one cap (#225): the most tokens a payload may carry and be judged.

        ``min(L2 CPU budget, L3 context)``, so raising either alone lets the
        other take over instead of reintroducing a second cap in a second
        unit. ``CLASSIFIER_MAX_TOKENS=0`` removes L2's budget, never L3's.
        Content at or under it is read WHOLE by every layer: nothing
        admitted is sliced.
        """
        budgets = [self.l3_context_tokens]
        if self.classifier_max_tokens > 0:
            budgets.append(self.classifier_max_tokens)
        return min(budgets)

    @functools.cached_property
    def _parts(self) -> tuple[int, int, int]:
        return part_settings()

    @property
    def part_tokens(self) -> int:
        """``TRENTINA_PART_TOKENS``: the size a paged response's parts aim for; 0 is off."""
        return self._parts[0]

    @property
    def max_parts(self) -> int:
        """``TRENTINA_MAX_PARTS``: the most parts one response is cut into."""
        return self._parts[1]

    @property
    def part_ttl_seconds(self) -> int:
        """``TRENTINA_PART_TTL_SECONDS``: how long a paged response is held unread."""
        return self._parts[2]

    @property
    def part_target_tokens(self) -> int:
        """The size parts aim for; 0 when paging is off, by setting or because
        the admission cap is too small to hold a part and its lead-in.

        Never so large that a part cannot be admitted: a part may run a
        tenth over its target when the cut before it moved back to a line
        break, and it is judged behind ``PART_LEAD_TOKENS`` of the part
        before. Both are reserved out of the admission cap.
        """
        room = (self.admission_tokens - PART_LEAD_TOKENS) * PART_SLACK // (PART_SLACK + 1)
        # No room for a part behind its lead-in: nothing is cut, and the cap
        # refuses what it always refused.
        return max(min(self.part_tokens, room), 0)

    @property
    def whole_tokens(self) -> int:
        """The most tokens a response may carry and still be delivered whole (#340).

        ``PART_WHOLE_RATIO`` times the part size, never over the admission
        cap. With paging off it is the admission cap, as before.
        """
        if self.part_target_tokens <= 0:
            return self.admission_tokens
        above, below = PART_WHOLE_RATIO
        return min(self.part_target_tokens * above // below, self.admission_tokens)

    @property
    def paged_tokens(self) -> int:
        """The most tokens a response may carry and be delivered at all.

        ``max_parts`` parts at the part size when paging is on, and the
        admission cap when it is off or would be the larger.
        """
        return max(self.part_target_tokens * self.max_parts, self.admission_tokens)

    @property
    def has_api_key(self) -> bool:
        """Whether a Gemini key is set. Only Gemini's; see ``has_llm``."""
        return bool(self.api_key.get_secret_value())

    def provider_key(self, provider: str) -> str:
        """The global env key for *provider*; empty when unset or keyless."""
        keys = {
            "gemini": self.api_key.get_secret_value(),
            "openai": self.openai_api_key,
            "anthropic": self.anthropic_api_key,
            "openrouter": self.openrouter_api_key.get_secret_value(),
        }
        return keys.get(provider, "")

    @property
    def has_llm(self) -> bool:
        """Whether a standalone model call has somewhere to go.

        The global provider or any configured fallback, each either ollama
        (keyless) or holding its key: the same chain the calls walk.
        ``has_api_key`` answered this until 0.41.0 and only ever knew about
        Gemini, so a gateway judging on OpenRouter looked like it had no L3.
        """
        return any(
            name == "ollama" or bool(self.provider_key(name))
            for name in (self.provider, *self.provider_fallback)
        )

    def is_trusted_domain(self, url: str) -> bool:
        """Check if a URL's domain is in the trust allowlist."""
        trusted_domains = self._trust_config.get("trusted_domains", [])
        if not isinstance(trusted_domains, list):
            return False
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            return any(domain == td or domain.endswith(f".{td}") for td in trusted_domains)
        except ValueError:
            return False

    def is_trusted_path(self, file_path: str) -> bool:
        """Check if a file path matches the trust allowlist."""
        trusted_paths = self._trust_config.get("trusted_paths", [])
        if not isinstance(trusted_paths, list):
            return False
        return any(fnmatch(file_path, pattern) for pattern in trusted_paths)

    def ensure_db_dir(self) -> None:
        """Create the database directory if it does not exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def ensure_perimeter_db_dir(self) -> None:
        """Create the perimeter database directory if it does not exist."""
        Path(self.perimeter_db_path).parent.mkdir(parents=True, exist_ok=True)


def get_config() -> Config:
    """Get or create the singleton configuration."""
    global _config
    if _config is None:
        _config = Config()
    return _config
