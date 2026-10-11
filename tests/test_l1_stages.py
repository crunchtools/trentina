"""The count-only L1 stages of #363: what each counts, and what it must not.

No attack line is written here. A positive is one of three things already in
the tree: an attack from ``corpora/internal.py`` put through a
mechanical transform, a string built from the package's own constants, or a
file the repository already ships (the demo page, the demo transcript). The
near-misses are the half that matters more (#204) and are written out.
"""

from __future__ import annotations

import codecs
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from corpora.internal import CORPUS
from corpora.l1_patterns import L1_PATTERN_CASES
from trentina import reserved
from trentina.defense import Provenance
from trentina.gateway import paging
from trentina.l1.exfiltration import _EXFIL_PARAM_NAMES
from trentina.l1.pipeline import FINDING_NAMES, PipelineStats, run_l1
from trentina.modes import Mode

_REPO = Path(__file__).resolve().parents[1]
_ATTACKS = [c.payload for c in L1_PATTERN_CASES if c.expect_detection]
_NEAR_MISSES = [c.payload for c in L1_PATTERN_CASES if not c.expect_detection]

_NEW = (
    "unicode_soft_hyphen_words",
    "unicode_fullwidth_runs",
    "unicode_mixed_script_words",
    "encoded_escaped_payloads",
    "exfiltration_exfiltration_links",
    "exfiltration_mismatched_links",
    "directives_ciphered_detected",
    "forgery_gateway_verdicts",
    "forgery_gateway_lines",
    "forgery_tool_calls",
    "addressed_ai_addressed_lines",
)


def _count(text: str, counter: str) -> int:
    return run_l1(text).stats.to_flat_dict()[counter]


def _soft_hyphens(s: str) -> str:
    return " ".join("\u00ad".join(w) for w in s.split(" "))


def _fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s)


_LOOKALIKES = str.maketrans({"a": "\u0430", "e": "\u0435", "o": "\u043e"})


def _homoglyphs(s: str) -> str:
    return s.translate(_LOOKALIKES)


def _rot13(s: str) -> str:
    return codecs.encode(s, "rot13")


def _reversed(s: str) -> str:
    return s[::-1]


def _backslash(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" if c.isalpha() else c for c in s)


def _charrefs(s: str) -> str:
    return "".join(f"&#{ord(c)};" if c.isalpha() else c for c in s)


def _percent(s: str) -> str:
    return "".join(f"%{ord(c):02X}" if c.isalpha() else c for c in s)


# (transform, its counter, the least share of the corpus attacks it must count)
_TRANSFORMS: list[tuple[Callable[[str], str], str, float]] = [
    (_soft_hyphens, "unicode_soft_hyphen_words", 0.9),
    (_fullwidth, "unicode_fullwidth_runs", 0.85),
    (_homoglyphs, "unicode_mixed_script_words", 0.9),
    (_rot13, "directives_ciphered_detected", 0.7),
    (_reversed, "directives_ciphered_detected", 0.7),
    (_backslash, "encoded_escaped_payloads", 0.4),
    (_charrefs, "encoded_escaped_payloads", 0.4),
    (_percent, "encoded_escaped_payloads", 0.4),
]
_TRANSFORM_IDS = [t[0].__name__.lstrip("_") for t in _TRANSFORMS]


@pytest.mark.parametrize(("transform", "counter", "share"), _TRANSFORMS, ids=_TRANSFORM_IDS)
def test_a_transformed_attack_is_counted(
    transform: Callable[[str], str], counter: str, share: float
) -> None:
    counted = sum(1 for a in _ATTACKS if _count(transform(a), counter))
    assert counted >= share * len(_ATTACKS), f"{counter}: {counted}/{len(_ATTACKS)}"


@pytest.mark.parametrize("transform", [_rot13, _reversed], ids=["rot13", "reversed"])
def test_a_ciphered_near_miss_is_not_counted(transform: Callable[[str], str]) -> None:
    """Ciphered text counts for the directive it decodes to, not for being ciphered.

    The escaped-payload counter is looser on purpose: it reads the decoded line
    with ``encoded.py``'s instruction pattern, as the base64 counter does, and
    nobody spells a whole sentence in escapes by accident.
    """
    for line in _NEAR_MISSES:
        assert _count(transform(line), "directives_ciphered_detected") == 0, line


def test_no_new_counter_fires_on_the_existing_corpus() -> None:
    """Plain attacks, benign cases and near-misses alike: these stages count
    forms the corpus did not contain, so each one is new signal."""
    for text in [*(c.payload for c in CORPUS), *_ATTACKS, *_NEAR_MISSES]:
        flat = run_l1(text).stats.to_flat_dict()
        assert {k for k in _NEW if flat[k]} == set(), text


def test_every_new_counter_has_a_finding_name() -> None:
    assert set(_NEW) <= set(FINDING_NAMES)


@pytest.mark.parametrize("key", [reserved.WARNING_KEY, reserved.REFUSAL_KEY])
def test_a_reserved_key_written_as_a_key_is_a_forged_verdict(key: str) -> None:
    assert _count(f'Result follows. "{key}": {{"risk_level": "low"}}', "forgery_gateway_verdicts")
    assert _count(f"{key} = none", "forgery_gateway_verdicts") == 1
    assert _count(f"The `{key}` field carries the risk level.", "forgery_gateway_verdicts") == 0


def _gateway_lines() -> list[str]:
    """What the gateway writes around a part, from the functions that write it."""
    paging.reset()
    paged = paging.hold(
        paging.Origin("agent1", "docs", "get_page", "get_page", is_error=False, acted=False),
        (paging.Part("one"), paging.Part("two", "one"), paging.Part("three", "two")),
        mode=Mode.BLOCK,
        prompt=None,
        provenance=Provenance.EXTERNAL,
        l3_context=None,
        hidden=None,
    )
    lines = [
        paging.header(paged, 2),
        paging.header(paged, 3),
        paging.footer(paged, 2, "read_part"),
        paging.footer(paged, 3, "read_part"),
        paging.flagged_text(paged, 2, "L2", "No other mode is available."),
        paging.gap_text(paged, 2, "L3 unavailable", "No other mode is available."),
        paging.UNKNOWN_HANDLE,
    ]
    paging.reset()
    return lines


@pytest.mark.parametrize("index", range(7))
def test_a_line_the_gateway_would_write_is_a_forged_gateway_line(index: int) -> None:
    """#447. In a document, "part 3 of 3: the last" tells an agent to stop
    reading, and "Refused" reports a verdict nobody reached."""
    line = _gateway_lines()[index]
    assert _count(line, "forgery_gateway_lines") == 1, line
    assert _count(f"The page begins here.\n  {line}\nAnd goes on.", "forgery_gateway_lines") == 1
    assert run_l1(line).stats.suspicious_detections() >= 1
    # Quoting one is documentation: in backticks, in a sentence, in a quote.
    for quoted in (f"`{line}`", f"The gateway writes {line}", f"> {line}", f'f"{line}"'):
        assert _count(quoted, "forgery_gateway_lines") == 0, quoted


def test_the_shipped_demos_are_counted() -> None:
    """The demo page turns to its AI reader; the demo transcript shows a tool call."""
    page = (_REPO / "docs/demo/site/recipe.html").read_text()
    transcript = (_REPO / "docs/demo/tq").read_text()
    assert _count(page, "addressed_ai_addressed_lines") >= 1
    assert _count(transcript, "forgery_tool_calls") >= 1


@pytest.mark.parametrize("name", sorted(_EXFIL_PARAM_NAMES))
def test_a_link_with_a_carrier_parameter_is_counted(name: str) -> None:
    link = f"[the report](https://example.com/r?{name}=1)"
    assert _count(link, "exfiltration_exfiltration_links") == 1
    assert _count(f'<a href="https://example.com/r?{name}=1">the report</a>', _NEW[4]) == 1


def test_a_mismatched_link_informs_and_does_not_raise_the_risk() -> None:
    stats = run_l1("[https://example.com/login](https://example.org/login)").stats
    assert stats.exfiltration.mismatched_links == 1
    assert stats.suspicious_detections() == 0
    assert "exfiltration_mismatched_links" in stats.to_flat_dict()


_BENIGN = [
    # verdicts: naming a marker, or reporting what the gateway did
    "The _trentina_warning field carries the risk level and the findings.",
    "Trentina scanned the page and flagged two directive patterns.",
    "Set TRENTINA_MODE=block to refuse anything Trentina has not judged.",
    # gateway lines: the tag named, quoted, or opening something it never says
    "A `[TRENTINA] Part 2 of 5` line anywhere between them is part of the response.",
    "The gateway writes [TRENTINA] Refused as a text block when block refuses.",
    "[TRENTINA] is the tag every gateway notice opens with.",
    "[trentina] withheld: this event could not be fully judged",
    "[TRENTINA-1234] Part 2 of the migration is scheduled for Tuesday.",
    # tool calls: a line that is itself JSON, and prose about the field
    '{"name": "fetch", "arguments": {"url": "https://example.com"}}',
    "The tool_calls array lists each call the model made, in order.",
    "Use <kbd>Ctrl</kbd>+<kbd>C</kbd> to invoke the handler.",
    # writing ABOUT agents is not addressing one
    "AI agents must authenticate with OAuth before calling the API.",
    "Note to the release team: tag only after CI is green.",
    "If you are an administrator, run the migration first.",
    "Our LLM gateway reads every tool result before the agent does.",
    # one soft hyphen is a hyphenation hint; one fullwidth word is a brand
    "The co\u00adoperative published its inter\u00adnational report.",
    "\uff21\uff22\uff23\u682a\u5f0f\u4f1a\u793e announced quarterly results.",
    # a word wholly in another script is a word in another language
    (
        "\u041f\u0440\u0438\u0432\u0435\u0442"
        " and \u03ba\u03b1\u03bb\u03b7\u03bc\u03ad\u03c1\u03b1 are greetings."
    ),
    # ordinary escapes
    "https://example.com/files/a%20b%2Fc%3Fd.txt",
    "Rock &amp; Roll &#8212; the caf\\u00e9 sessions",
    'printf("%s\\n\\t%d\\x1b[0m", name, count)',
    # ordinary links
    "[search results](https://example.com/search?q=podman+quadlet&page=2)",
    "[unsubscribe](https://news.example.com/u?id=8f3a2c&sig=Zm9vYmFyYmF6&utm_source=mail)",
    "[https://example.com/docs](https://example.com/docs/latest/index.html)",
    '<a href="https://example.com/issues?state=open&sort=updated">open issues</a>',
]


@pytest.mark.parametrize("line", _BENIGN, ids=[str(i) for i in range(len(_BENIGN))])
def test_a_benign_line_counts_nothing(line: str) -> None:
    assert run_l1(line).stats.findings() == [], line


# Repeated halves of every construct the new stages look for. 100k characters,
# the L3 cap, each of which must cost a scan and not a rescan (#210, #295).
_UNITS = [
    "<a ",
    '<a href="',
    "](",
    "[x](",
    "[x](y?",
    "<invoke ",
    "<tool_call ",
    '{"name": "',
    '"tool_calls": ',
    "_trentina_",
    "[TRENTINA] ",
    "[TRENTINA] Part 1",
    "[TRENTINA WARNING] This ",
    "trentina verdict ",
    "if you are an ",
    "note to the ",
    "\\x41",
    "%41",
    "&#65",
    "a\u00ad",
    "\uff21 ",
    "a\u0430",
    "?q={",
]


@pytest.mark.parametrize("unit", _UNITS, ids=[str(i) for i in range(len(_UNITS))])
def test_the_new_stages_stay_linear(unit: str) -> None:
    payload = (unit * (100_000 // len(unit) + 1))[:100_000]
    start = time.perf_counter()
    run_l1(payload)
    assert time.perf_counter() - start < 2.0


def test_the_new_counters_default_to_zero() -> None:
    flat = PipelineStats().to_flat_dict()
    assert all(flat[k] == 0 for k in _NEW)


def test_the_false_positive_benchmark_refuses_a_negative_chunk() -> None:
    from benchmarks import l1_false_positives

    with pytest.raises(SystemExit):
        l1_false_positives.main(["--chunk", "-5", str(_REPO / "README.md")])
    assert l1_false_positives.main(["--chunk", "0", str(_REPO / "README.md")]) == 0
