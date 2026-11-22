"""A secret token is found encoded, reversed or in part, and only then (#864)."""

from __future__ import annotations

import base64
import json
import secrets
from urllib.parse import quote

import pytest

from trentina.token_variants import FRAGMENT_MIN, TokenMatcher, matcher_for

HONEYTOKEN = "AK" + "IAQ7HONEYTOKEN4X2BQ9ZLMN3VWRP8"
CANARY = f"CANARY-{secrets.token_hex(16)}"


def _b64(raw: bytes, *, urlsafe: bool, pad: int = 0, tail: int = 0) -> str:
    """``raw`` base64-encoded after ``pad`` and before ``tail`` bytes of something else."""
    neighbours = b"\xfb\xff\xfe"
    data = neighbours[:pad] + raw + neighbours[:tail]
    out = base64.urlsafe_b64encode(data) if urlsafe else base64.b64encode(data)
    return out.decode().rstrip("=")


def _forms(token: str) -> dict[str, str]:
    raw = token.encode()
    forms = {
        "exact": token,
        "reversed": token[::-1],
        "hex": raw.hex(),
        "HEX": raw.hex().upper(),
        "percent": "".join(f"%{b:02x}" for b in raw),
        "PERCENT": "".join(f"%{b:02X}" for b in raw),
        "quoted": quote(token, safe=""),
    }
    for pad in range(3):
        for tail in range(3):
            forms[f"b64-{pad}-{tail}"] = _b64(raw, urlsafe=False, pad=pad, tail=tail)
            forms[f"b64url-{pad}-{tail}"] = _b64(raw, urlsafe=True, pad=pad, tail=tail)
    return forms


@pytest.mark.parametrize("token", [HONEYTOKEN, CANARY], ids=["honeytoken", "canary"])
def test_every_form_is_found(token: str) -> None:
    matcher = TokenMatcher([token])
    for name, form in _forms(token).items():
        text = json.dumps({"arguments": {"body": f"x {form} y"}})
        assert matcher.found(text) == [token], name


def test_base64_is_found_without_its_fragments() -> None:
    # A token with no 16-character fragment (a short one) still shows through
    # base64 at every alignment, so it is the base64 core that matched.
    short = "AK" + "IAQ7HONEYTOKEN4X2B"
    matcher = TokenMatcher([short])
    for pad in range(3):
        for tail in range(3):
            blob = _b64(short.encode(), urlsafe=False, pad=pad, tail=tail)
            assert matcher.found(blob) == [short], (pad, tail)


def test_percent_and_unicode_escapes_in_the_haystack_are_decoded() -> None:
    matcher = TokenMatcher([HONEYTOKEN])
    escaped = "".join(f"\\u{ord(c):04x}" for c in HONEYTOKEN)
    assert matcher.found(escaped) == [HONEYTOKEN]
    assert matcher.found(quote(HONEYTOKEN, safe="")) == [HONEYTOKEN]


def test_a_sixteen_character_fragment_hits() -> None:
    fragment = HONEYTOKEN[7 : 7 + FRAGMENT_MIN]
    assert len(fragment) == FRAGMENT_MIN
    assert TokenMatcher([HONEYTOKEN]).found(f"see {fragment} here") == [HONEYTOKEN]
    assert TokenMatcher([CANARY]).found(CANARY[-FRAGMENT_MIN:]) == [CANARY]


def test_a_fifteen_character_fragment_does_not_hit() -> None:
    fragment = HONEYTOKEN[7 : 7 + FRAGMENT_MIN - 1]
    assert TokenMatcher([HONEYTOKEN]).found(f"see {fragment} here") == []


def test_a_short_token_is_matched_whole_never_in_part() -> None:
    short = "AK" + "IAQ7HONEYTOKEN4X2B"
    assert len(short) < 2 * FRAGMENT_MIN
    matcher = TokenMatcher([short])
    assert matcher.found(f"the key is {short}") == [short]
    assert matcher.found(short[:FRAGMENT_MIN]) == []
    assert matcher.found(short[4:]) == []


# Outside the base64 and hex alphabets, so only an encoded form could match.
@pytest.mark.parametrize("token", ["~", "~!", "~!@#$", "~!@#$^&"])
def test_an_encoded_form_shorter_than_a_fragment_is_not_matched(token: str) -> None:
    """A one-byte token's base64 core is one character, and its hex two: neither
    may turn ordinary text into a trip. The token itself still matches."""
    matcher = TokenMatcher([token])
    ordinary = "".join(chr(c) for c in range(0x21, 0x7F) if chr(c) not in token)
    assert matcher.found(ordinary + base64.b64encode(b"\0\0" + token.encode()).decode()) == []
    assert matcher.found(ordinary + token.encode().hex()) == []
    assert matcher.found(f"x{token}x") == [token]


def test_an_ordinary_tool_argument_is_not_a_hit() -> None:
    matcher = TokenMatcher([HONEYTOKEN, CANARY])
    sent = {
        "name": "create_ticket",
        "arguments": {
            "title": "Rotate the access keys on the billing account",
            "body": "AKIA prefixes are documented; see CANARY handling in the runbook. " * 3,
            "id": secrets.token_hex(16),
            "blob": base64.b64encode(b"nothing secret in this attachment at all").decode(),
        },
    }
    assert matcher.found(json.dumps(sent)) == []


def test_each_token_in_a_set_is_reported_on_its_own() -> None:
    other = "ghp_ZXCVBNMASDFGHJKLQWERTYUIOP123456"
    matcher = TokenMatcher([HONEYTOKEN, other])
    assert matcher.found(HONEYTOKEN[::-1]) == [HONEYTOKEN]
    assert matcher.found(f"{other[:20]} {HONEYTOKEN}") == sorted([HONEYTOKEN, other])


def test_the_matcher_for_a_token_set_is_built_once() -> None:
    assert matcher_for(frozenset({HONEYTOKEN})) is matcher_for(frozenset({HONEYTOKEN}))


def test_an_empty_token_set_finds_nothing() -> None:
    assert TokenMatcher([""]).found("anything at all") == []
