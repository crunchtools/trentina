"""Stage 6: Directive detection — count visible LLM instruction patterns.

Detects lines containing common prompt injection directives: instruction
overrides, privileged-mode requests, prompt extraction, role manipulation,
jailbreaks, safety bypasses and spoofed role tags. Operates on visible text,
complementing the invisible-character stripping (unicode stage) and
special-token stripping (delimiter stage).

Where the patterns come from (#201): OpenRouter's published prompt-injection
guardrail, which is derived from the OWASP LLM Prompt Injection Prevention
Cheat Sheet. They see a great deal of injection traffic, and their list is
field experience. Names follow theirs, so a detection here can be looked up
there. ``l1/evasion.py`` adds their evasion handling (scrambles, typos,
character spacing) on top of the exact patterns.

This stage DETECTS and does not modify. It used to remove the whole line
around a match, which destroyed exactly the content an ops agent exists to
read: a CVE ticket, a Nagios alert, or a security mail *discusses* attacks
in the same words attacks use, and a one-line Jira description containing
"ignore previous instructions" came back as an empty string — silently, with
L2 and L3 left judging the void. Every other stage excises a precise token
(a zero-width character, an encoded blob, a delimiter); this one amputated
prose. Now the count feeds the L1 risk verdict and the sidecar, and the
mode — not this stage — decides whether flagged content reaches the agent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .evasion import collapsed_spacing, corrected_line, scrambled_with_company

_I = re.IGNORECASE
_TARGETS = r"(?:instructions?|rules?|guidelines?|constraints?|directives?)"
_POSSESSIVE = r"(?:your?|yoru|yuor|the|my|its|his|her|our|their)"
_SYSTEM = r"(?:system|systme|sysetm|systemp?)"

# Each pattern with the literals it cannot match without: at least one of
# them is in every string it matches, lower-case once ``_fold`` has run. The
# rarest required word, not the first: `show_prompt` keys on `prompt`, since
# `show` would let nearly every line through (#709).
_TABLE: list[tuple[str, str, int, tuple[str, ...]]] = [
    # -- instruction override
    (
        "ignore_previous_instructions",
        r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:(?:safety|security|system|"
        r"operational|internal|core|original|initial|existing|given|stated|"
        r"provided|defined|specified|established)\s+)?" + _TARGETS,
        _I,
        ("ignore",),
    ),
    ("ignore_all_instructions", r"ignore\s+all\s+instructions", _I, ("ignore",)),
    (
        "disregard_instructions",
        r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+" + _TARGETS,
        _I,
        ("disregard",),
    ),
    (
        "forget_instructions",
        r"forget\s+(?:all\s+)?(?:previous|prior|above)\s+" + _TARGETS,
        _I,
        ("forget",),
    ),
    # Also "new instruction is to ...", which OpenRouter's colon-only form misses.
    ("new_instructions", r"new\s+instructions?(?::|\s+(?:is|are)\s+to\b)", _I, ("instruction",)),
    (
        "do_not_follow",
        r"do\s+not\s+follow\s+(?:the\s+)?(?:system|developer|previous|original)",
        _I,
        ("follow",),
    ),
    (
        "supersede_instructions",
        r"supersedes?\s+(?:all\s+)?(?:prior|previous)\s+" + _TARGETS,
        _I,
        ("supersede",),
    ),
    (
        "void_instructions",
        (
            r"(?:previous|prior)\s+instructions?\s+(?:are|is)\s+"
            r"(?:void|invalid|null|obsolete|cancelled|revoked)"
        ),
        _I,
        ("instruction",),
    ),
    # -- developer / admin mode
    ("developer_mode", r"you\s+are\s+now\s+(?:in\s+)?developer\s+mode", _I, ("developer",)),
    ("enter_special_mode", r"enter\s+(?:developer|admin|debug|maintenance)\s+mode", _I, ("enter",)),
    (
        "activate_special_mode",
        r"activate\s+(?:developer|admin|debug|jailbreak)\s+mode",
        _I,
        ("activate",),
    ),
    # -- system override
    ("system_override", r"\bsystem\s+override\b", _I, ("override",)),
    ("override_instructions", r"override\s+(?:your\s+)?" + _TARGETS, _I, ("override",)),
    # -- prompt extraction
    (
        "reveal_prompt",
        r"reveal\s+(?:" + _POSSESSIVE + r"\s+)?(?:(?:full|hidden|complete|internal|"
        r"secret|original|entire|exact|actual|real)\s+){0,2}(?:" + _SYSTEM + r"\s+)?prompt\b",
        _I,
        ("reveal",),
    ),
    (
        "show_prompt",
        r"show\s+(?:me\s+)?" + _POSSESSIVE + r"\s+(?:" + _SYSTEM + r"\s+)?prompt\b",
        _I,
        ("prompt",),
    ),
    # `the` as well as `your`: OWASP's own test case asks "what were the
    # exact instructions you were given", which OpenRouter's form misses.
    (
        "what_instructions",
        r"what\s+(?:are|were)\s+(?:your\s+|the\s+)?(?:exact\s+)?instructions",
        _I,
        ("instructions",),
    ),
    (
        "repeat_instructions",
        r"repeat\s+(?:the\s+)?(?:text|instructions?)\s+(?:above|before)",
        _I,
        ("repeat",),
    ),
    (
        "output_prompt",
        r"output\s+(?:your\s+)?(?:initial|original|system)\s+(?:prompt|instructions?)",
        _I,
        ("output",),
    ),
    ("system_prompt_label", r"system\s+prompt\s*:", _I, ("prompt",)),
    # -- role manipulation
    (
        "remove_restrictions",
        r"you\s+are\s+no\s+longer\s+(?:bound|restricted|limited)",
        _I,
        ("longer",),
    ),
    ("act_unbound", r"act\s+as\s+if\s+(?:you(?:'re|\s+are)\s+)?not\s+bound", _I, ("bound",)),
    (
        "pretend_different",
        r"pretend\s+(?:you(?:'re|\s+are)\s+)?(?:a\s+)?different\s+(?:ai|assistant|model)",
        _I,
        ("pretend",),
    ),
    # Replaced the bare `you are now a\b` (#201), which fired on "you are
    # now a member of the group". A hijack needs its malicious modifier.
    (
        "identity_hijack",
        (
            r"you\s+are\s+now\s+(?:(?:a|an)\s+)?\w+.{0,40}(?:without\s+(?:any\s+)?restrict|"
            r"ignor\w*\s+(?:all|any|every|prev)|bypass|unrestrict|unlimit|obey\s+only|"
            r"no\s+(?:rules|limits|restrict|boundari))"
        ),
        _I,
        ("now",),
    ),
    ("new_role", r"your\s+new\s+role\s+is\b", _I, ("role",)),
    ("as_an_ai_you_must", r"as\s+an\s+ai\s*,?\s+you\s+must", _I, ("must",)),
    # -- DAN / jailbreak. DAN is case-sensitive: "dan" is a name.
    # Bounded, unlike OpenRouter's `.*`: a line of repeated "DAN " made
    # that rescan the rest of the line from every DAN (#210).
    ("dan_jailbreak", r"\bDAN\b.{0,300}?\b[Dd]o\s+[Aa]nything\s+[Nn]ow\b", 0, ("nything",)),
    ("jailbreak_mode", r"jailbreak(?:ed)?\s+(?:mode|prompt)", _I, ("jailbreak",)),
    # -- safety bypass
    (
        # `override` and `settings` beyond OpenRouter's, for OWASP's
        # "override your security settings". The qualifier is still
        # required, so "override your settings" in a config guide is not.
        "bypass_safety",
        (
            r"(?:bypass|override)\s+(?:your\s+)?(?:safety|security|content|ethical)\s+"
            r"(?:filters?|measures?|guidelines?|restrictions?|settings?)"
        ),
        _I,
        ("bypass", "override"),
    ),
    (
        "disable_safety",
        r"disable\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|measures?)",
        _I,
        ("disable",),
    ),
    (
        "ignore_safety",
        (
            r"(?:ignore|disregard)\s+(?:all\s+)?(?:your\s+)?(?:safety|security|ethical|content)\s+"
            r"(?:guidelines?|rules?|restrictions?|measures?|filters?|polic(?:y|ies)|protocols?)"
        ),
        _I,
        ("ignore", "disregard"),
    ),
    # -- tag injection and role spoofing
    ("system_tag_injection", r"<\s*(?:/\s*)?system\s*/?>", _I, ("system",)),
    (
        # Narrower than OpenRouter's, which fires on the `<tool>` in
        # `<backend>__<tool>` and every usage line that names one: an
        # opening tag must start the line, and a closing or self-closing
        # one counts anywhere, since no placeholder is written that way.
        "role_tag_injection",
        (
            r"^\s*<\s*(?:assistant|developer|tool|function)\s*/?>"
            r"|<\s*/\s*(?:assistant|developer|tool|function)\s*>"
            r"|<\s*(?:assistant|developer|tool|function)\s*/>"
        ),
        _I,
        ("assistant", "developer", "tool", "function"),
    ),
    (
        "bracketed_role_spoofing",
        r"\[\s*(?:System\s*Message|System|Assistant|Internal)\s*\]",
        _I,
        ("system", "assistant", "internal"),
    ),
    # Capital S only, unlike OpenRouter's: `system: ` opens ordinary log
    # and config lines, and an impersonated system turn is written the
    # way the real one is.
    ("system_prefix_spoofing", r"^\s*System:\s+", 0, ("system:",)),
    # -- command execution
    ("execute_the_following", r"execute\s+the\s+following", _I, ("execute",)),
    ("run_this_command", r"run\s+this\s+command", _I, ("command",)),
]

#: Every exact pattern, by OpenRouter's name. A line matching any of them is
#: one detection, however many match.
PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(regex, flags) for name, regex, flags, _ in _TABLE
}

#: What each pattern needs present before it is worth running.
LITERALS: dict[str, tuple[str, ...]] = {name: literals for name, _, _, literals in _TABLE}

# The patterns grouped under each literal, so a line is searched once per
# literal however many patterns share it.
_GATES: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = tuple(
    (literal, tuple(PATTERNS[n] for n, needs in LITERALS.items() if literal in needs))
    for literal in dict.fromkeys(lit for needs in LITERALS.values() for lit in needs)
)

# The four characters `re.IGNORECASE` matches to an ASCII letter that
# `str.lower` leaves alone (dotted and dotless I, Kelvin, long s): without
# them `\u0130gnore previous instructions` is a match the gate would wave
# through. Found by trying every code point; `tests/test_l1_directives.py`
# tries them again.
_FOLD = str.maketrans({"\u0130": "i", "\u0131": "i", "\u212a": "k", "\u017f": "s"})

_PREFIX_PATTERNS = re.compile(
    r"^\s*(?:IMPORTANT|INSTRUCTION|OVERRIDE|ADMIN)\s*:",
    re.IGNORECASE,
)

# `]` closing one line and a role label opening the next: `...]\n[system]:`.
# The only pattern that needs the previous line, so it is checked in the loop.
_ROLE_LABEL = re.compile(r"^\s*\[?(?:system|assistant|user)\]?:", re.IGNORECASE)

# A line break a reader sees as a WRAP: Markdown's hard break (two-plus
# trailing blanks or a backslash before the newline, markdownify's `<br>`) and
# a raw `<br>`. Per-line scanning let `ignore<br>previous instructions` evade
# every multi-word pattern (#179); a blank line stays a separate unit. The
# lookbehind starts a blank run's match at its FIRST blank only: without it a
# run with no newline after it was rescanned from every position, and 40k tabs
# took 15 s (#295).
SOFT_BREAK = re.compile(
    r"(?<![ \t])[ \t]{2,}\r?\n|\\\r?\n|<br\b[^<>]*>[ \t]*(?:\r?\n)?", re.IGNORECASE
)


@dataclass
class DirectiveStats:
    """Statistics from directive detection.

    The two are disjoint: ``evasions_detected`` counts the lines that matched
    only once ``l1/evasion.py`` undid a scramble, a typo or character
    spacing, and is not in ``directives_detected``. Both feed risk, which sums
    every field. A line in ROT13 or written backwards reaches this stage
    already read back by ``unpack/letters.py`` (#744), so it counts as a
    plain directive; until then this stage read both itself (#363).
    """

    directives_detected: int = 0
    evasions_detected: int = 0


def matches_exact(line: str) -> bool:
    """Whether ``line`` matches the prefix rule or any exact pattern.

    A pattern runs only when one of its literals is in ``line``. The gate
    reads the string it is handed, so every caller's form of the line (as it
    arrived, collapsed, corrected, ciphered) is gated on its own words and
    never on another form's (#709; #710 gated on the line as it arrived and
    missed every misspelled keyword). The regex still decides each match.
    """
    if _PREFIX_PATTERNS.search(line):
        return True
    folded = line.translate(_FOLD).lower()
    return any(
        literal in folded and any(p.search(line) for p in patterns) for literal, patterns in _GATES
    )


def _matches_every_pattern(line: str) -> bool:
    """``matches_exact`` without the gate: what the gate must agree with."""
    return bool(_PREFIX_PATTERNS.search(line)) or any(p.search(line) for p in PATTERNS.values())


def _matches_evasion(line: str) -> bool:
    """Whether ``line`` is an injection once its evasion is undone."""
    if scrambled_with_company(line):
        return True
    collapsed = collapsed_spacing(line)
    if collapsed is not None and matches_exact(collapsed):
        return True
    for candidate in (line, collapsed):
        if candidate is None:
            continue
        corrected = corrected_line(candidate)
        if corrected is not None and matches_exact(corrected):
            return True
    return False


def strip_directives(text: str) -> tuple[str, DirectiveStats]:
    """Count lines containing LLM directive patterns; return text unchanged.

    One detection per line, however many patterns hit it — the unit of
    suspicion is the hostile line, and counting each pattern would let a
    single line inflate the risk score on its own. A soft break joins its
    two halves into one line for the scan (see ``SOFT_BREAK``).
    """
    stats = DirectiveStats()

    previous = ""
    for line in SOFT_BREAK.sub(" ", text).split("\n"):
        if matches_exact(line) or (previous.rstrip().endswith("]") and _ROLE_LABEL.search(line)):
            stats.directives_detected += 1
        elif _matches_evasion(line):
            stats.evasions_detected += 1
        previous = line

    return text, stats
