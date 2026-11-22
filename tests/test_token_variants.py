"""A secret token is found encoded, reversed or in part, and only then (#864)."""

from __future__ import annotations

import base64
import json
import random
import secrets
from urllib.parse import quote

import pytest

from trentina.token_variants import FRAGMENT_MIN, TokenMatcher, matcher_for

HONEYTOKEN = "AK" + "IAQ7HONEYTOKEN4X2BQ9ZLMN3VWRP8"
CANARY = "CANARY-" + "3f9a1c07be52d8e46a0b9c71e2d5f348"


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


def _rand(seed: int, length: int, alphabet: str) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
URLSAFE = ALNUM + "-_"
JWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"


def _jwt(seed: int) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"sub": _rand(seed, 12, ALNUM)}).encode())
    return ".".join([JWT_HEADER, payload.decode().rstrip("="), _rand(seed + 1, 43, URLSAFE)])


def test_a_jwt_matches_in_part_by_its_signature_alone() -> None:
    honey = _jwt(1)
    other = _jwt(2)
    matcher = TokenMatcher([honey])
    assert matcher.found(other) == []
    assert matcher.found(JWT_HEADER) == []
    assert matcher.found(JWT_HEADER + ".eyJzdWIi") == []  # header and a few chars of anything
    # Another token's payload opening the same way is not a piece of this one.
    payload = honey.split(".")[1]
    assert matcher.found(payload[:FRAGMENT_MIN]) == []
    signature = honey.rsplit(".", 1)[1]
    assert matcher.found(f"sig={signature[10 : 10 + FRAGMENT_MIN]}") == [honey]
    assert matcher.found(honey) == [honey]


def _openssh_key(seed: int, *, cipher: bytes = b"none") -> tuple[str, int, int]:
    """An unencrypted ed25519 OpenSSH key and the base64 span of its seed."""
    rng = random.Random(seed)

    def string(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    pub = rng.randbytes(32)
    check = rng.randbytes(4)
    private = (
        check
        + check
        + string(b"ssh-ed25519")
        + string(pub)
        + string(rng.randbytes(32) + pub)
        + string(b"ci@example.test")
    )
    private += bytes(range(1, 8 - len(private) % 8 + 1)) if len(private) % 8 else b""
    raw = (
        b"openssh-key-v1\0"
        + string(cipher)
        + string(b"none")
        + string(b"")
        + (1).to_bytes(4, "big")
        + string(string(b"ssh-ed25519") + string(pub))
        + string(private)
    )
    seed_at = (
        raw.index(private) + 8 + 4 + 11 + 4 + 32 + 4 + 4
    )  # check words, type, pub, seed length
    body = base64.b64encode(raw).decode()
    lines = [body[i : i + 70] for i in range(0, len(body), 70)]
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    return pem, seed_at, body


def test_an_openssh_key_matches_by_its_random_body_never_by_armour_or_framing() -> None:
    pem, seed_at, body = _openssh_key(7)
    other, _, other_body = _openssh_key(8)
    matcher = TokenMatcher([pem])
    assert matcher.found(other) == []
    assert matcher.found("-----BEGIN OPENSSH PRIVATE KEY-----") == []
    assert (
        matcher.found(
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx"
        )
        == []
    )
    assert matcher.found(other_body[:70]) == []
    # The key type and public half are in every key's private section too.
    assert matcher.found(body[: 4 * 25]) == []
    start = (seed_at * 8 + 5) // 6 + 1
    if start // 70 != (start + FRAGMENT_MIN - 1) // 70:
        start = (start // 70 + 1) * 70
    assert matcher.found(f"leak {body[start : start + FRAGMENT_MIN]}") == [pem]
    assert matcher.found(pem) == [pem]


def test_an_encrypted_openssh_key_is_all_secret_after_its_head() -> None:
    pem, _, body = _openssh_key(9, cipher=b"aes256-ctr")
    matcher = TokenMatcher([pem])
    assert matcher.found(body[150:166]) == [pem]
    assert matcher.found("-----BEGIN OPENSSH PRIVATE KEY-----\n") == []


@pytest.mark.parametrize(
    "prefix",
    [
        "gh" + "p_",
        "sk" + "-proj-",
        "sk" + "-ant-api03-",
        "github" + "_pat_",
        "AK" + "IA",
        "xox" + "b-",
    ],
)
def test_a_vendor_prefix_is_not_part_of_a_fragment(prefix: str) -> None:
    body = _rand(11, 40, ALNUM)
    token = prefix + body
    matcher = TokenMatcher([token])
    assert (
        matcher.found(prefix + body[: FRAGMENT_MIN - len(prefix) + 1][: FRAGMENT_MIN - len(prefix)])
        == []
    )
    assert matcher.found(prefix + _rand(12, 40, ALNUM)) == []
    assert matcher.found(f"{prefix}{body[:12]} and more") == []
    assert matcher.found(body[3 : 3 + FRAGMENT_MIN]) == [token]


def test_a_token_with_no_known_prefix_still_fragments_from_its_first_character() -> None:
    token = _rand(13, 40, ALNUM)
    assert TokenMatcher([token]).found(token[:FRAGMENT_MIN]) == [token]


@pytest.mark.parametrize("run", ["A" * FRAGMENT_MIN, "0000111100001111", "ab" * 8, "a1" * 8])
def test_a_low_entropy_window_never_forms_a_fragment(run: str) -> None:
    token = _rand(14, 12, ALNUM) + run + _rand(15, 12, ALNUM)
    matcher = TokenMatcher([token])
    assert matcher.found(run) == []
    assert matcher.found(f"x{run}x") == []
    # The random stretch beside it still counts.
    assert matcher.found(_rand(14, 12, ALNUM)) == []
    assert matcher.found(token) == [token]
    tail = token[-FRAGMENT_MIN:]
    assert matcher.found(tail) == [token]


def _wrapped(blob: str, eol: str, width: int = 76) -> str:
    return eol.join(blob[i : i + width] for i in range(0, len(blob), width))


def test_base64_wrapped_by_line_breaks_is_found() -> None:
    raw = random.Random(21).randbytes(90) + HONEYTOKEN.encode() + random.Random(22).randbytes(90)
    blob = base64.b64encode(raw).decode()
    assert len(blob) > 76 * 2
    matcher = TokenMatcher([HONEYTOKEN])
    assert matcher.found(blob) == [HONEYTOKEN]
    assert matcher.found(_wrapped(blob, "\n")) == [HONEYTOKEN]
    assert matcher.found(_wrapped(blob, "\r\n")) == [HONEYTOKEN]
    escaped = json.dumps({"attachment": _wrapped(blob, "\n")})
    assert "\\n" in escaped
    assert matcher.found(escaped) == [HONEYTOKEN]
    assert matcher.found(json.dumps({"attachment": _wrapped(blob, "\r\n")})) == [HONEYTOKEN]
    # Mid-run breaks of an urlsafe blob too.
    assert matcher.found(_wrapped(blob.replace("+", "-").replace("/", "_"), "\n", 20)) == [
        HONEYTOKEN
    ]


def test_line_breaks_do_not_turn_ordinary_text_into_a_hit() -> None:
    matcher = TokenMatcher([HONEYTOKEN])
    text = "\n".join(base64.b64encode(random.Random(i).randbytes(60)).decode() for i in range(50))
    assert matcher.found(text) == []


def test_a_token_under_the_fragment_length_is_matched_whole_and_in_encodings_only() -> None:
    # 31 characters is the longest token with no fragments.
    token = "AK" + "IAQ7HONEYTOKEN4X2BQ9ZLMN3VWRP"
    assert len(token) == 2 * FRAGMENT_MIN - 1
    matcher = TokenMatcher([token])
    assert matcher.found(token) == [token]
    assert matcher.found(token[::-1]) == [token]
    assert matcher.found(token.encode().hex()) == [token]
    assert matcher.found(token[:FRAGMENT_MIN]) == []
    assert matcher.found(token[-FRAGMENT_MIN:]) == []
    assert matcher.found(token[5 : 5 + 20]) == []


@pytest.mark.parametrize(
    ("length", "form"),
    [(8, "hex"), (6, "percent"), (12, "base64")],
)
def test_the_shortest_token_with_each_encoded_form(length: int, form: str) -> None:
    token = _rand(31, length, ALNUM)
    raw = token.encode()
    encoded = {
        "hex": raw.hex(),
        "percent": "".join(f"%{b:02x}" for b in raw),
        "base64": base64.b64encode(raw).decode(),
    }[form]
    assert len(encoded) >= FRAGMENT_MIN
    assert TokenMatcher([token]).found(encoded) == [token]
    shorter = _rand(32, length - 1, ALNUM)
    one_short = {
        "hex": shorter.encode().hex(),
        "percent": "".join(f"%{b:02x}" for b in shorter.encode()),
        "base64": base64.b64encode(shorter.encode()).decode(),
    }[form]
    if form == "hex":  # a percent form decodes to the token itself
        assert TokenMatcher([shorter]).found(one_short) == []


def _rsa_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def test_a_der_pem_key_matches_by_its_body_never_by_armour_or_der_head() -> None:
    honey, other = _rsa_pem(), _rsa_pem()
    matcher = TokenMatcher([honey])
    other_lines = other.splitlines()
    # Another key's armour line and its DER head (the start of its body).
    assert matcher.found(other_lines[0] + "\n" + other_lines[1]) == []
    assert matcher.found(other) == []
    body = "".join(honey.splitlines()[1:-1])
    assert matcher.found(body[600:680]) == [honey]


def test_a_long_token_searches_a_bounded_number_of_blocks() -> None:
    from trentina.token_variants import MAX_BLOCKS

    honey = _rsa_pem()
    matcher = TokenMatcher([honey])
    assert len(matcher._blocks[honey]) <= MAX_BLOCKS
    body = "".join(honey.splitlines()[1:-1])
    # Any piece longer than the spacing of the kept blocks covers one of them.
    span = len(honey) // MAX_BLOCKS + 2 * FRAGMENT_MIN
    # From past the public modulus and exponent, which are never a piece of it.
    for start in range(450, len(body) - span, 97):
        assert matcher.found(body[start : start + span]) == [honey], start


def _openssh(kind: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if kind == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()


@pytest.mark.parametrize("kind", ["rsa", "ecdsa"])
def test_an_openssh_key_of_another_type_matches_by_its_private_half(kind: str) -> None:
    honey, other = _openssh(kind), _openssh(kind)
    matcher = TokenMatcher([honey])
    assert matcher.found(other) == []
    body = "".join(honey.splitlines()[1:-1])
    # The tail of the body is private-key material, never the public half.
    tail = body[-120:-40]
    assert matcher.found(tail) == [honey]


@pytest.mark.parametrize("cut", [40, 120, 300])
def test_a_truncated_or_malformed_openssh_body_falls_back_without_raising(cut: int) -> None:
    lines = _openssh("rsa").splitlines()
    body = "".join(lines[1:-1])[:cut] + "!!"
    broken = "\n".join([lines[0], body, lines[-1]])
    matcher = TokenMatcher([broken])
    assert matcher.found(broken) == [broken]
    assert matcher.found("unrelated text " * 20) == []


def _rsa_key(shape: str) -> tuple[str, str, bytes, str]:
    """A fresh RSA 2048 key as a PEM in ``shape`` (``pkcs8`` or ``pkcs1``), with
    its OpenSSH public line, its SubjectPublicKeyInfo PEM and the bare base64
    of its DER modulus."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_format = (
        serialization.PrivateFormat.PKCS8
        if shape == "pkcs8"
        else serialization.PrivateFormat.TraditionalOpenSSL
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM, private_format, serialization.NoEncryption()
    ).decode()
    public = key.public_key()
    openssh = public.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    spki = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    modulus = public.public_numbers().n.to_bytes(256, "big")
    return pem, openssh, spki, base64.b64encode(modulus).decode()


@pytest.mark.parametrize("shape", ["pkcs8", "pkcs1"])
def test_the_public_half_of_an_rsa_private_key_is_not_a_hit(shape: str) -> None:
    for _ in range(10):
        pem, openssh, spki, modulus = _rsa_key(shape)
        matcher = TokenMatcher([pem])
        assert matcher.found(openssh) == []
        assert matcher.found(spki) == []
        assert matcher.found(modulus) == []
        assert matcher.found(json.dumps({"pub": spki, "ssh": openssh})) == []
        # The private half still is: d, p, q, dP, dQ and qInv follow n and e.
        body = "".join(pem.splitlines()[1:-1])
        private = body[len(body) // 3 : len(body) // 3 + 80]
        assert matcher.found(private) == [pem]
        assert matcher.found(body[-100:-20]) == [pem]


def _der(tag: int, content: bytes) -> bytes:
    size = len(content)
    head = bytes([size]) if size < 0x80 else bytes([0x82]) + size.to_bytes(2, "big")
    return bytes([tag]) + head + content


def test_the_private_fields_of_a_der_key_are_found_through_long_form_lengths() -> None:
    from trentina.token_variants import _der_secret

    fields = [_der(0x02, bytes([i]) * (200 if i == 3 else 4)) for i in range(9)]
    pkcs1 = _der(0x30, b"".join(fields))
    marked = _der_secret(pkcs1)
    assert sum(marked) == 200 + 4 * 5
    algorithm = _der(0x30, _der(0x06, b"\x2a\x86\x48") + _der(0x05, b""))
    pkcs8 = _der(0x30, _der(0x02, b"\0") + algorithm + _der(0x04, pkcs1))
    assert sum(_der_secret(pkcs8)) == 200 + 4 * 5


@pytest.mark.parametrize(
    "raw",
    [b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x30\x03\x02\x01", b"\x1f\x01\0", b"\x30\x00"],
)
def test_a_der_body_that_does_not_parse_falls_back_to_its_head(raw: bytes) -> None:
    body = base64.b64encode(raw + random.Random(5).randbytes(90)).decode()
    pem = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
    matcher = TokenMatcher([pem])
    assert matcher.found(body[:48]) == []
    assert matcher.found(body[80:100]) == [pem]


@pytest.mark.parametrize(("kind", "scalar"), [("ed25519", (30, 62)), ("ec", (60, 90))])
def test_a_curve_key_matches_by_its_private_scalar_not_its_public_point(
    kind: str, scalar: tuple[int, int]
) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    key = (
        ed25519.Ed25519PrivateKey.generate()
        if kind == "ed25519"
        else ec.generate_private_key(ec.SECP256R1())
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    matcher = TokenMatcher([pem])
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    assert matcher.found(public) == []
    body = "".join(pem.splitlines()[1:-1])
    assert matcher.found(f"scalar {body[scalar[0] : scalar[1]]}") == [pem]
    assert matcher.found(body[:20]) == []
    assert matcher.found(pem) == [pem]
