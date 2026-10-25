"""Hidden-markup fingerprints — the tier-2 backstop, format-agnostic.

Conversion to Markdown (``transforms/html.py``) is tier 1 and removes this
attack class rather than detecting it: Markdown has no ``style`` attribute, no
``display:none``, no foreground/background pair. Once a payload has been
converted, hidden content is not expressible — the category is absent, not
mitigated.

This stage catches the payloads conversion never saw: the agent asked for raw
bytes, the converter declined, or the text merely embeds markup without being
a document. It makes no decision about whether a payload "is HTML", because
there is no such decision to get wrong. It assumes any payload MAY carry
markup, scans for the fingerprints that hide content, and counts them.

Until 0.28.0 this ran only behind a ``looks_like_html`` sniffer keyed on a
leading ``<!DOCTYPE`` or ``<html>``. An HTML FRAGMENT — the shape most MCP
tool output actually carries — matched neither, so it was never checked at
all: a same-colour span in one scored ``low`` and was delivered intact, while
the identical bytes with a doctype in front scored ``medium`` and were
stripped. Same payload, two security behaviours, chosen by the first few
characters. Removing the sniffer is what this module is for.

COUNTS ONLY; the L2 input passes through untouched. The hidden text's WORDS
are exactly what L2 should still read — what this stage adds is the
structural signal that those words were not meant to be seen, which is the
part no amount of reading the text can recover.

The predicate table lives here and ``transforms/html.py`` imports it, so the
converter that STRIPS an element and the stage that COUNTS one decide by one
rule. Two hand-maintained copies of a detection table is the bug ``jsonwalk``
was written to end (#167).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

RGB_BYTE_MASK = 0xFF

# Detections counted per scan before it stops. Far above the >10 that already
# saturates `risk_level_for_count` at "critical", so the cap can only cost
# precision in a count that is already maxed out. It caps DETECTIONS, not
# attributes scanned: a cap on attributes let a page push its hidden element
# past the cap with harmless ones (#179). The scan is linear either way.
_MAX_DETECTIONS = 5_000


@dataclass
class HiddenStats:
    """Counts of content-hiding fingerprints.

    All four are SUSPICIOUS and feed ``PipelineStats.suspicious_detections``,
    flattening to ``hidden_elements``, ``hidden_off_screen``,
    ``hidden_same_color`` and ``hidden_latex_invisible``. The last is OWASP's
    ``$\\color{white}{\\text{...}}$``: markup of another kind, rendered by
    KaTeX or MathJax in ink the colour of the page.
    The tag-hygiene counters that used to sit beside them (``script_tags``,
    ``style_tags``, ``meta_tags``, ``noscript_tags``, ``html_comments``) moved
    to the converter's sidecar in 0.28.0: they were never suspicious, they
    never fed risk, and counting them here only made the dataclass look like
    it was about HTML rather than about hiding.
    """

    elements: int = field(default=0)
    off_screen: int = field(default=0)
    same_color: int = field(default=0)
    latex_invisible: int = field(default=0)

    def __add__(self, other: HiddenStats) -> HiddenStats:
        """Counts over two texts, e.g. the blocks of one response."""
        return HiddenStats(
            self.elements + other.elements,
            self.off_screen + other.off_screen,
            self.same_color + other.same_color,
            self.latex_invisible + other.latex_invisible,
        )

    def at_least(self, other: HiddenStats) -> HiddenStats:
        """The larger count of each kind: two views of overlapping text, neither complete."""
        return HiddenStats(
            max(self.elements, other.elements),
            max(self.off_screen, other.off_screen),
            max(self.same_color, other.same_color),
            max(self.latex_invisible, other.latex_invisible),
        )


_NAMED_COLORS: dict[str, str] = {
    "white": "#ffffff",
    "black": "#000000",
    "red": "#ff0000",
    "green": "#008000",
    "blue": "#0000ff",
    "yellow": "#ffff00",
    "cyan": "#00ffff",
    "magenta": "#ff00ff",
    "gray": "#808080",
    "grey": "#808080",
    "silver": "#c0c0c0",
    "maroon": "#800000",
    "olive": "#808000",
    "lime": "#00ff00",
    "aqua": "#00ffff",
    "teal": "#008080",
    "navy": "#000080",
    "fuchsia": "#ff00ff",
    "purple": "#800080",
    "orange": "#ffa500",
}

_HIDDEN_STYLE_PATTERNS = (
    "display:none",
    "display: none",
    "visibility:hidden",
    "visibility: hidden",
    "opacity:0",
    "opacity: 0",
)

_OFFSCREEN_PATTERNS = (
    "clip:rect(0",
    "clip: rect(0",
    "clip-path:inset(100",
    "clip-path: inset(100",
    "font-size:0",
    "font-size: 0",
)

_POSITION_PATTERNS = (
    "position:absolute",
    "position: absolute",
    "position:fixed",
    "position: fixed",
)

_NEGATIVE_OFFSET_PATTERNS = (
    "left:-",
    "left: -",
    "top:-",
    "top: -",
)

# `style="..."`, `style='...'` or unquoted `style=display:none`. Every
# alternative is a single negated class, which cannot backtrack
# catastrophically on hostile input.
_ATTR_VALUE = r"""\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>=`]+))"""
_STYLE_ATTR_RE = re.compile(r"style" + _ATTR_VALUE, re.IGNORECASE)

# The bare `hidden` boolean attribute: `<div hidden>`, `<div hidden="">`,
# `<div hidden/>`. Requires a preceding tag open so the English word "hidden"
# in prose does not count. `[^<>]`, not `[^>]`: with no `>` ahead, the
# latter rescanned the rest of the payload from every `<`, and 60k characters
# of `<div ` took seconds (#210). A tag body holds no `<` either.
_HIDDEN_ATTR_RE = re.compile(r"<[a-zA-Z][^<>]*?\shidden(?=[\s/>=])", re.IGNORECASE)

# `\color{white}`, `\textcolor{#fff}`, `\color{transparent}`, `\phantom{`.
# White is assumed to be the page: that is the case the attack relies on, and
# a dark page makes the same text visible, which is not what anyone hides.
_LATEX_INVISIBLE_RE = re.compile(
    r"\\(?:(?:text)?color\s*\{\s*(?:white|\#?fff(?:fff)?|transparent)\s*\}"
    r"|[hv]?phantom\s*\{)",
    re.IGNORECASE,
)

# `<style>` blocks and `class="..."` attributes, for hiding done by a class
# rule rather than an inline style (#179). The block is found by its opening
# tag and closed with `str.find`-style searches in `_style_blocks`, never with
# one lazy `.*?` regex: that rescans to the end from every unclosed `<style`.
_STYLE_OPEN_RE = re.compile(r"<style\b[^<>]*>", re.IGNORECASE)
_STYLE_CLOSE_RE = re.compile(r"</style\s*>", re.IGNORECASE)
_CLASS_ATTR_RE = re.compile(r"(?<![\w-])class" + _ATTR_VALUE, re.IGNORECASE)
# A comment, or a string, whose close is optional: an unclosed comment runs to
# the end and an unclosed string to the line end, as in CSS. Every match
# consumes what it scanned, so one pass is linear on hostile input.
_CSS_NOISE_RE = re.compile(
    r"""/\*.*?(?:\*/|\Z)|"(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?""",
    re.DOTALL,
)
# `\\6f ` (hex, then one optional whitespace, CRLF counting as one) or `\\x`
# (a literal character).
_CSS_ESCAPE_RE = re.compile(r"\\(?:([0-9a-fA-F]{1,6})(?:\r\n|[ \t\n\r\f])?|(.))", re.DOTALL)
_MAX_CODE_POINT = 0x10FFFF
_SURROGATES = range(0xD800, 0xE000)
# An escaped ASCII character that is not an identifier character (`.a\\,b`
# names the class `a,b`) is parked here while the selector is split, so it
# cannot act as syntax, and restored once the class name is extracted.
_PARKED = 0xF0000
_PARKED_RE = re.compile("[\U000f0000-\U000f007f]")
_CLASS_NAME_RE = re.compile(r"\.([\w\-\U000f0000-\U000f007f]+)")
# `:not(...)` names the classes an element must NOT have, so its contents go.
# The other functional pseudo-classes are unwrapped: `:is(.h)` styles `.h`.
_NOT_RE = re.compile(r":not\([^()]*\)", re.IGNORECASE)
_FUNCTIONAL_RE = re.compile(r":(?:is|where|matches|-webkit-any|-moz-any|any)\(", re.IGNORECASE)
# A selector's subject is its last compound: `.menu .tip` styles `.tip`.
_COMBINATOR_RE = re.compile(r"[\s>+~()]+")
_HTML_COMMENT_RE = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
# The properties the predicates above read; a class rule keeps no others.
_READ_PROPERTIES = frozenset(
    {
        "display",
        "visibility",
        "opacity",
        "clip",
        "clip-path",
        "font-size",
        "position",
        "left",
        "top",
        "text-indent",
        "color",
        "background",
        "background-color",
    }
)
# Every substring a predicate looks for; a class keeps the ones it has.
_TRIGGERS = (
    _HIDDEN_STYLE_PATTERNS + _OFFSCREEN_PATTERNS + _POSITION_PATTERNS + _NEGATIVE_OFFSET_PATTERNS
)
# Colours kept per class and property, most recent first out. Past this a
# class has been padded; the browser shows the last value, which is kept.
_MAX_COLORS = 8

_COLOR_RE = re.compile(r"(?:^|;)\s*color\s*:\s*([^;!]+)")
_BACKGROUND_RE = re.compile(r"(?:^|;)\s*background(?:-color)?\s*:\s*([^;!]+)")


def normalize_color(value: str) -> str | None:
    """Normalize a CSS color value to lowercase hex, or None if unparseable."""
    val = value.strip().lower()

    if val in _NAMED_COLORS:
        return _NAMED_COLORS[val]

    hex3 = re.match(r"^#([0-9a-f])([0-9a-f])([0-9a-f])$", val)
    if hex3:
        return f"#{hex3.group(1) * 2}{hex3.group(2) * 2}{hex3.group(3) * 2}"

    if re.match(r"^#[0-9a-f]{6}$", val):
        return val

    rgb = re.match(r"^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", val)
    if rgb:
        r_hex = int(rgb.group(1)) & RGB_BYTE_MASK
        g_hex = int(rgb.group(2)) & RGB_BYTE_MASK
        b_hex = int(rgb.group(3)) & RGB_BYTE_MASK
        return f"#{r_hex:02x}{g_hex:02x}{b_hex:02x}"

    return None


def style_is_hidden(style_lower: str) -> bool:
    """Inline style that hides the element outright."""
    return any(p in style_lower for p in _HIDDEN_STYLE_PATTERNS)


def style_is_off_screen(style_lower: str) -> bool:
    """Inline style that moves the element out of the viewport."""
    if "text-indent" in style_lower and "-999" in style_lower:
        return True

    has_position = any(p in style_lower for p in _POSITION_PATTERNS)
    has_negative = any(p in style_lower for p in _NEGATIVE_OFFSET_PATTERNS)
    if has_position and has_negative:
        return True

    return any(p in style_lower for p in _OFFSCREEN_PATTERNS)


def style_has_same_color(style_lower: str) -> bool:
    """Foreground colour equal to background colour — text written in ink the
    colour of the paper.

    Any foreground against any background, not the first of each: a style
    that sets a colour twice is judged on both (#179).
    """
    fgs = {normalize_color(m.group(1)) for m in _COLOR_RE.finditer(style_lower)}
    bgs = {normalize_color(m.group(1)) for m in _BACKGROUND_RE.finditer(style_lower)}
    return bool((fgs & bgs) - {None})


def classify_style(style_lower: str) -> str | None:
    """Which hiding CONCEPT a style attribute matches: ``hidden``,
    ``off_screen``, ``same_color``, or None.

    Concepts rather than field names, so the two callers can name their own
    fields for their own audiences — the risk score wants terse keys, the
    operator sidecar wants descriptive ones — while precedence and patterns
    stay in one place. The checks are ordered and the first match wins, which
    is what the converter's per-element ``break`` has always done.

    CSS escapes are decoded first, so `display:n\\6f ne` is `display:none`
    here as it is in the browser.
    """
    if "\\" in style_lower:
        style_lower = _unescape_css(style_lower).lower()
    if style_is_hidden(style_lower):
        return "hidden"
    if style_is_off_screen(style_lower):
        return "off_screen"
    if style_has_same_color(style_lower):
        return "same_color"
    return None


def _unescape_css(css: str, *, park: bool = False) -> str:
    """Decode CSS escapes: `n\\6f ne` is `none` to a browser, and must be to
    the predicates. An out-of-range code point becomes U+FFFD, as in CSS.

    With `park`, an escape that decodes to ASCII punctuation is moved to
    ``_PARKED`` instead, so it stays part of an identifier and never reads
    as selector syntax.
    """

    def _char(match: re.Match[str]) -> str:
        if match.group(2) is not None:
            char = match.group(2)
        else:
            code = int(match.group(1), 16)
            valid = 0 < code <= _MAX_CODE_POINT and code not in _SURROGATES
            char = chr(code) if valid else "\ufffd"
        if park and char.isascii() and not (char.isalnum() or char in "-_"):
            return chr(_PARKED + ord(char))
        return char

    return _CSS_ESCAPE_RE.sub(_char, css)


def _selector_classes(head: str) -> list[str]:
    """The classes a selector list styles: each subject's, escapes decoded.

    Escapes are decoded before the split, with any that decode to ASCII
    punctuation parked outside the syntax, so `.\\68 ` is `.h` and `.a\\,b`
    is one class, not a selector list. Parentheses left by an unwrapped
    `:is(` read as combinators; a comma inside one splits the list early,
    which only ever adds a class.
    """
    selectors = _unescape_css(head, park=True)
    selectors = _FUNCTIONAL_RE.sub("", _NOT_RE.sub("", selectors))
    names = []
    for selector in selectors.split(","):
        subject = _COMBINATOR_RE.split(selector.strip(" \t\n()"))[-1].split(":")[0]
        names += [
            _PARKED_RE.sub(lambda m: chr(ord(m.group(0)) - _PARKED), name)
            for name in _CLASS_NAME_RE.findall(subject)
        ]
    return names


def _style_blocks(text: str) -> list[str]:
    """The contents of every closed `<style>` block, in linear time."""
    blocks: list[str] = []
    pos = 0
    while opened := _STYLE_OPEN_RE.search(text, pos):
        closed = _STYLE_CLOSE_RE.search(text, opened.end())
        if closed is None:
            break
        blocks.append(text[opened.end() : closed.start()])
        pos = closed.end()
    return blocks


@dataclass
class ClassStyle:
    """What one class's rules can contribute to a hiding predicate.

    Only the trigger substrings and the colours, never the declarations
    themselves, so its size is bounded however many rules name the class.
    ``triggers`` holds the predicate substrings its declarations contained;
    ``colors`` and ``backgrounds`` the normalized hex values, oldest first,
    at most ``_MAX_COLORS`` each.
    """

    triggers: set[str] = field(default_factory=set)
    colors: dict[str, None] = field(default_factory=dict)
    backgrounds: dict[str, None] = field(default_factory=dict)

    def add(self, prop: str, value: str) -> None:
        """Keep what one lowercased declaration can contribute."""
        declaration = f"{prop}:{value}"
        self.triggers.update(t for t in _TRIGGERS if t in declaration)
        if prop == "text-indent" and "-999" in value:
            self.triggers.add("text-indent:-999")
        if prop in {"color", "background", "background-color"}:
            colors = self.colors if prop == "color" else self.backgrounds
            hex_color = normalize_color(value.partition("!")[0])
            if hex_color is not None:
                colors.pop(hex_color, None)
                colors[hex_color] = None
                if len(colors) > _MAX_COLORS:
                    del colors[next(iter(colors))]

    def merge(self, other: ClassStyle) -> None:
        """Fold another rule's summary in, `other`'s colours most recent."""
        self.triggers |= other.triggers
        for mine, theirs in ((self.colors, other.colors), (self.backgrounds, other.backgrounds)):
            for color in theirs:
                mine.pop(color, None)
                mine[color] = None
            while len(mine) > _MAX_COLORS:
                del mine[next(iter(mine))]

    def style(self) -> str:
        """The summary as a style string for ``classify_style``."""
        parts = sorted(self.triggers)
        parts += [f"color:{c}" for c in self.colors]
        parts += [f"background:{c}" for c in self.backgrounds]
        return "; ".join(parts)


ClassRules = dict[str, ClassStyle]


def class_declarations(text: str) -> ClassRules:
    """What the class rules in `text`'s `<style>` blocks can hide.

    `text` is markup, whole or fragment. The result maps each class name to
    its ``ClassStyle`` summary; ``class_style`` turns an element's classes
    into one style string.

    `<div class="h">` hidden by `.h{display:none}` carries no inline style,
    so the inline predicates never saw it: the converter delivered its text
    in full and this stage counted nothing (#179). ``class_style`` turns
    these into a style string for the same predicates as an inline style.

    Not a CSS engine, and deliberately not trying to be one. A hiding
    declaration anywhere counts: a later rule, a more specific one, an
    inline style or `@media` that would show the element again is ignored,
    and a rule applies to every class in its selector's subject up to the
    first pseudo-class, so `.menu .tip:hover` styles `.tip` (see
    ``_selector_classes`` for `:is`, `:not` and escapes). Resolving the
    cascade instead would let a page un-hide an element on paper while the
    browser keeps it hidden. Every shortcut errs toward calling something
    hidden, which costs the converter visible text and the risk score a
    count; the other direction delivers an invisible payload unmarked.
    External stylesheets are out of reach.
    """
    rules: ClassRules = {}
    # A `<style>` inside an HTML comment applies to nothing.
    for block in _style_blocks(_HTML_COMMENT_RE.sub("", text)):
        # Split on `}` rather than matching `sel { decl }` with one regex:
        # linear on unbalanced input, and an `@media x {` prefix lands in the
        # selector's head, where `rpartition` discards it.
        # Comments dropped and string contents blanked first, so neither can
        # hide a `{`, `}` or `;` from the split.
        skeleton = _CSS_NOISE_RE.sub(lambda m: "" if m.group(0).startswith("/*") else '""', block)
        for chunk in skeleton.split("}"):
            head, brace, body = chunk.rpartition("{")
            if not brace:
                continue
            # Summarised once, then merged per class: the summary is bounded,
            # so a rule with thousands of selectors and declarations costs
            # their sum, not their product.
            rule = ClassStyle()
            for declaration in _unescape_css(body).lower().split(";"):
                prop, colon, value = declaration.partition(":")
                if colon and prop.strip() in _READ_PROPERTIES:
                    rule.add(prop.strip(), value.strip())
            if not (rule.triggers or rule.colors or rule.backgrounds):
                continue
            for name in _selector_classes(head.rpartition("{")[2]):
                if name not in rules:
                    rules[name] = ClassStyle()
                rules[name].merge(rule)
    return rules


def class_style(class_attr: str | list[str], rules: ClassRules) -> str:
    """The style an element's classes give it, for ``classify_style``."""
    names = class_attr.split() if isinstance(class_attr, str) else class_attr
    return "; ".join(rules[n].style() for n in dict.fromkeys(names) if n in rules)


def detect_hidden_markup(text: str) -> tuple[str, HiddenStats]:
    """Count content-hiding fingerprints in whatever we were handed.

    Returns the text unchanged. This is a counting stage, not a stripping one
    — see the module docstring for why the hidden words must survive into the
    L2 input.
    """
    stats = HiddenStats()
    concept_field = {
        "hidden": "elements",
        "off_screen": "off_screen",
        "same_color": "same_color",
    }

    found = 0
    for match in _STYLE_ATTR_RE.finditer(text):
        # Character references decoded, as the browser does: `&#100;isplay`.
        style = html.unescape(match.group(1) or match.group(2) or match.group(3) or "").lower()
        if not style:
            continue
        concept = classify_style(style)
        if concept is not None:
            name = concept_field[concept]
            setattr(stats, name, getattr(stats, name) + 1)
            found += 1
            if found >= _MAX_DETECTIONS:
                break

    # Attribute by attribute, with no parse, so a class and an inline style on
    # one tag are judged apart; the converter, which parses, joins them.
    declarations = class_declarations(text)
    if declarations:
        found = 0
        for match in _CLASS_ATTR_RE.finditer(text):
            classes = html.unescape(match.group(1) or match.group(2) or match.group(3) or "")
            concept = classify_style(class_style(classes, declarations))
            if concept is not None:
                name = concept_field[concept]
                setattr(stats, name, getattr(stats, name) + 1)
                found += 1
                if found >= _MAX_DETECTIONS:
                    break

    stats.elements += len(_HIDDEN_ATTR_RE.findall(text))
    stats.latex_invisible = len(_LATEX_INVISIBLE_RE.findall(text))
    return text, stats
