"""L1: the deterministic pipeline. It counts, and its counts brief L3.

FORMAT-AGNOSTIC since 0.28.0. There is one entry point and it scans what it
is handed. The ``looks_like_html`` dispatch that used to choose between an
HTML pipeline and a text pipeline is gone: it matched a leading ``<!DOCTYPE``
or ``<html>``, so an HTML FRAGMENT took the text path, and identical bytes
received two different security behaviours depending on their first few
characters. Conversion now belongs to ``preprocess/html.py``, which declines
on what it cannot parse instead of asking whether anything "is HTML", and
hidden-markup fingerprints are counted by an ordinary stage that runs on
every payload. See ``l1/hidden.py`` for the two tiers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..unpack.stats import UnpackStats
from .addressed import AddressedStats, detect_addressed
from .delimiters import DelimiterStats, normalize_delimiters
from .directives import DirectiveStats, strip_directives
from .encoded import EncodedStats, normalize_encoded
from .exfiltration import ExfiltrationStats, strip_exfiltration
from .forgery import ForgeryStats, detect_forgery
from .hidden import HiddenStats, detect_hidden_markup
from .shadows import ShadowStats
from .unicode import UnicodeStats, normalize_unicode

FINDING_NAMES: dict[str, str] = {
    "hidden_elements": "elements hidden from view",
    "hidden_off_screen": "elements positioned off screen",
    "hidden_same_color": "text coloured like its background",
    "hidden_latex_invisible": "LaTeX coloured invisible",
    "unicode_zero_width_chars": "zero-width characters inside words",
    "unicode_control_chars": "control characters",
    "unicode_bidi_overrides": "bidirectional overrides",
    "unicode_unicode_tags": "Unicode tag characters",
    "unicode_variation_selectors": "variation-selector runs",
    "unicode_soft_hyphen_words": "words spelled out with soft hyphens between letters",
    "unicode_fullwidth_runs": "runs of words in fullwidth Latin letters",
    "unicode_mixed_script_words": "Latin words with Cyrillic or Greek lookalike letters",
    "encoded_base64_payloads": "base64 payloads that decode to text",
    "encoded_hex_payloads": "hex payloads that decode to text",
    "encoded_data_uris": "text data URIs",
    "encoded_escaped_payloads": (
        "lines whose percent, backslash or character-reference escapes hide an instruction word"
    ),
    "exfiltration_exfiltration_urls": "image URLs that could exfiltrate data",
    "exfiltration_exfiltration_links": "links whose query is built to be filled in with data",
    "exfiltration_mismatched_links": "links showing one site's URL and going to another",
    "delimiters_llm_delimiters": "LLM chat delimiters",
    "delimiters_custom_patterns": "profile-defined delimiter patterns",
    "directives_directives_detected": "lines matching a known injection directive",
    "directives_evasions_detected": "lines matching one once scrambled, misspelled or spaced out",
    "directives_ciphered_detected": "lines matching one once read in ROT13 or backwards",
    "forgery_gateway_verdicts": "lines impersonating this gateway's verdict on the content",
    "forgery_gateway_lines": "lines written to look like this gateway's own notices",
    "forgery_tool_calls": "tool calls written into the content",
    "addressed_ai_addressed_lines": "lines addressed to an AI reading the content",
    "shadows_files": "Python files shadowing the standard library",
    "shadows_obfuscated": "of those, files with obfuscated code",
    "unpacked_text_decoded": "encoded spans decoded to text for you to read",
    "unpacked_binary_labelled": "binary spans replaced by a label naming their type",
    "unpacked_binary_unread": "of those, images, PDFs or archives no layer could read",
    "unpacked_archives_opened": "archives or office files opened, their files read below",
    "unpacked_images_read": "images whose text was read by OCR; OCR can misread",
}
"""What L3's briefing calls each ``PipelineStats.to_flat_dict`` counter.

Every counter has an entry; a test fails a new one that does not, so a new L1
stage cannot go unmentioned to L3."""


@dataclass
class PipelineStats:
    """Combined statistics from all L1 stages."""

    hidden: HiddenStats = field(default_factory=HiddenStats)
    unicode: UnicodeStats = field(default_factory=UnicodeStats)
    encoded: EncodedStats = field(default_factory=EncodedStats)
    exfiltration: ExfiltrationStats = field(default_factory=ExfiltrationStats)
    delimiters: DelimiterStats = field(default_factory=DelimiterStats)
    directives: DirectiveStats = field(default_factory=DirectiveStats)
    forgery: ForgeryStats = field(default_factory=ForgeryStats)
    addressed: AddressedStats = field(default_factory=AddressedStats)
    shadows: ShadowStats = field(default_factory=ShadowStats)
    unpacked: UnpackStats = field(default_factory=UnpackStats)
    """Set by ``defense.defend`` from the unpack stage, not by a stage here.
    Informational, so ``suspicious_detections`` leaves it out."""

    def to_flat_dict(self) -> dict[str, int]:
        """Flatten all stats into a single dict for serialization."""
        flat: dict[str, int] = {}
        named_sections = [
            ("hidden", asdict(self.hidden)),
            ("unicode", asdict(self.unicode)),
            ("encoded", asdict(self.encoded)),
            ("exfiltration", asdict(self.exfiltration)),
            ("delimiters", asdict(self.delimiters)),
            ("directives", asdict(self.directives)),
            ("forgery", asdict(self.forgery)),
            ("addressed", asdict(self.addressed)),
            ("shadows", asdict(self.shadows)),
            ("unpacked", asdict(self.unpacked)),
        ]
        for section_name, section_dict in named_sections:
            for key, value in section_dict.items():
                flat[f"{section_name}_{key}"] = value
        return flat

    def findings(self) -> list[str]:
        """Each non-zero counter as ``"<what>: <n>"``, in ``FINDING_NAMES`` order.

        How L1 hands L3 what it found (the Layer contract: findings, never
        inputs). The words come from ``FINDING_NAMES`` alone, never from the
        payload, so nothing here can carry an attacker's text to the judge.
        """
        flat = self.to_flat_dict()
        return [f"{name}: {flat[key]}" for key, name in FINDING_NAMES.items() if flat.get(key)]

    def total_detections(self) -> int:
        """Total detections across all stages (informational).

        Most stages excise what they detect; the directives stage only
        counts. Either way a detection is a detection for risk purposes.
        """
        return sum(self.to_flat_dict().values())

    def suspicious_detections(self) -> int:
        """Count only genuinely suspicious detections for risk scoring.

        Only categories that signal an actual attack vector count: hidden
        elements, off-screen positioning, same-color text, unicode
        manipulation, encoded payloads, exfiltration URLs and fill-in links,
        LLM delimiters, directive injection, forged verdicts, gateway lines
        and tool calls,
        and text addressed to an AI. A link whose text and target disagree is
        not one: mail trackers do that on every message.

        Normal HTML hygiene (comments, scripts, styles, meta, noscript) is
        expected on any website and never counted here. Those counters left
        ``PipelineStats`` entirely in 0.28.0 and live in the converter's
        sidecar, which is the only place that still strips them.
        """
        return int(
            self.hidden.elements
            + self.hidden.off_screen
            + self.hidden.same_color
            + self.hidden.latex_invisible
            + sum(asdict(self.unicode).values())
            + sum(asdict(self.encoded).values())
            + self.exfiltration.exfiltration_urls
            + self.exfiltration.exfiltration_links
            + sum(asdict(self.delimiters).values())
            + sum(asdict(self.directives).values())
            + sum(asdict(self.forgery).values())
            + sum(asdict(self.addressed).values())
            + self.shadows.files
            + self.shadows.obfuscated
        )

    def risk_level(self) -> str:
        """Classify risk based on suspicious detection counts.

        A stdlib shadow is critical on its own; see ``ShadowStats``.
        """
        if self.shadows.files:
            return "critical"
        return risk_level_for_count(self.suspicious_detections())


def risk_level_for_count(suspicious: int) -> str:
    """Classify risk from a raw suspicious-detection count.

    Shared with callers that aggregate detections across multiple
    ``PipelineStats`` instances (e.g. alert ingress scanning several JSON
    fields) and can't hand back a single ``PipelineStats`` to call
    ``risk_level()`` on.
    """
    if suspicious == 0:
        return "low"
    if suspicious <= 3:
        return "medium"
    if suspicious <= 10:
        return "high"
    return "critical"


@dataclass
class PipelineResult:
    """Result from the L1 pipeline: the caller's text and what L1 counted in it.

    ``content`` is WHAT THE AGENT RECEIVES — the caller's text, unmodified. L1
    never strips: excising lines or tokens destroyed exactly the content an
    ops agent exists to read (a CVE ticket discusses attacks in the words
    attacks use), and it destroyed the evidence before the smarter layers
    could judge it. Disposition belongs to the profile's enforcement mode
    and the Q-Agent, not to a regex.

    L1 hands on COUNTS and nothing else (#360). To match through obfuscation
    its stages work on a normalized copy, but that copy never leaves
    ``_run_stages``: until 0.57.1 it was returned as ``l2_input`` and redact's
    extraction turn read it, which made L1 a cleansing layer for one consumer.

    The owner's rule (2026-09-13): what the agent receives is byte-identical
    to what entered the perimeter, or nothing at all.
    """

    content: str
    stats: PipelineStats
    input_size: int
    output_size: int


def _run_stages(content: str, stats: PipelineStats) -> PipelineResult:
    """Apply every stage and assemble the result.

    There is ONE path now. It used to be two — one entered after HTML had
    been converted to Markdown, one for everything else — and keeping them
    from drifting was a standing chore. The dispatch that chose between them
    was also wrong often enough to matter (see the module docstring), so the
    fix was to delete the fork rather than to guard it.

    The delivery text passes through untouched. Each stage reads the copy the
    one before it normalized, so a directive split by zero-width characters
    still matches; the copy is dropped when the last stage has counted (#360).
    ``detect_hidden_markup`` transforms nothing and runs FIRST, because it is
    the only stage that reads markup and the later stages rewrite the very
    characters it looks for.
    """
    working, stats.hidden = detect_hidden_markup(content)
    working, stats.unicode = normalize_unicode(working)
    working, stats.encoded = normalize_encoded(working)
    working, stats.exfiltration = strip_exfiltration(working)
    working, stats.delimiters = normalize_delimiters(working)
    _, stats.directives = strip_directives(working)
    stats.forgery = detect_forgery(working)
    stats.addressed = detect_addressed(working)

    size = len(content.encode("utf-8"))
    return PipelineResult(
        content=content,
        stats=stats,
        input_size=size,
        output_size=size,
    )


def run_l1(text: str) -> PipelineResult:
    """Run the pipeline on whatever the caller was handed.

    The only entry point. It makes no judgement about the payload's format:
    a stage that cares about markup looks for markup, and finds none in text
    that has none.
    """
    return _run_stages(text, PipelineStats())
