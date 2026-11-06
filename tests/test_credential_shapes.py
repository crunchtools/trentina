"""The one credential-shape table, read as a detector (#511).

``logsafe`` reads the same patterns to redact; ``tests/test_log_scrub.py``
holds the redaction side. Here we hold the detection side: every kind is found
with its own label, a near-miss is not found, and each shape is linear.
"""

from __future__ import annotations

import time

import pytest

from trentina import credential_shapes as c
from trentina.credential_shapes import CredentialKind as K

# A 42-char key body, split in the source so no scanner reads the file as a leak.
_TAIL = "Zq7" * 14

#: (id, text, the kind it must be found under).
_ATTACKS = [
    ("aws-access-key", "with " + "AK" + "IA" + "IOSFODNN7EXAMPLE now", K.AWS_ACCESS_KEY),
    ("aws-temp-key", "set " + "AS" + "IA" + "IOSFODNN7EXAMPLE", K.AWS_ACCESS_KEY),
    ("openai", "key " + "sk" + "-proj-" + _TAIL, K.OPENAI_KEY),
    ("google-api", "key " + "AI" + "za" + _TAIL[:35], K.GOOGLE_API_KEY),
    ("google-oauth", "tok " + "ya" + "29." + _TAIL, K.GOOGLE_OAUTH_TOKEN),
    # A token this gateway minted for one of its own profiles (#635).
    ("trentina-profile", "auth " + "tr" + "t_" + _TAIL, K.TRENTINA_PROFILE_TOKEN),
    ("matrix", "tok " + "sy" + "t_" + _TAIL, K.MATRIX_TOKEN),
    ("github-classic", "tok " + "gh" + "p_" + "A" * 36, K.GITHUB_TOKEN),
    ("github-pat", "tok " + "github" + "_pat_" + "A" * 22, K.GITHUB_TOKEN),
    ("slack", "tok " + "xo" + "xb-" + "0123456789", K.SLACK_TOKEN),
    ("jwt", "tok " + "ey" + "J" + _TAIL + "." + "ey" + "J" + _TAIL + "." + _TAIL, K.JWT),
    ("pem", "-----BE" + "GIN RSA PRIVATE KEY-----", K.PEM_PRIVATE_KEY),
    ("query-password", "POST /login?password=hunter2hunter2hunter2", K.QUERY_SECRET),
    ("authorization", "Authorization: Bearer " + _TAIL, K.AUTHORIZATION),
    ("userinfo", "postgres://user:s3cretpass@db.example:5432/x", K.URL_USERINFO),
]

#: Shapes an attacker's string gets near but does not reach — none may be found.
_NEAR_MISSES = [
    "AKIAEXAMPLE is too short",  # AWS prefix, under 16 trailing chars
    "AKIAIOSFODNN7EXAMPLE12 has too many",  # 18 trailing: the fixed {16} + boundary fails
    "a uuid 550e8400-e29b-41d4-a716-446655440000 is not a key",
    "commit 3fa9c1d2aaaabbbbccccddddeeee000011112222 is a sha",
    "GET /search?monkey=banana&turkey=1",  # query, but not a secret param
    "the word secret appears but secret= does not",
    "trt_short is under twenty",  # the minted-token lead-in, body too short
    "a trt_ lead-in with nothing after it",
    "Bearer token authentication is a phrase",  # under 20 chars of value
    "eyJ is how a JWT starts but eyJonly is not one",
    "-----BEGIN PUBLIC KEY----- is not private",
    "sk-short",  # sk- prefix, under 20 chars
]


@pytest.mark.parametrize(("text", "kind"), [a[1:] for a in _ATTACKS], ids=[a[0] for a in _ATTACKS])
def test_a_credential_is_found_under_its_kind(text: str, kind: K) -> None:
    assert c.has_credential(text) is True
    assert kind in c.kinds(text)
    assert any(found_kind is kind for found_kind, _ in c.find(text))


@pytest.mark.parametrize("text", _NEAR_MISSES)
def test_a_near_miss_is_not_a_credential(text: str) -> None:
    assert c.has_credential(text) is False
    assert c.find(text) == []
    assert c.kinds(text) == {}


def test_empty_and_plain_text_are_clean() -> None:
    assert c.find("") == []
    assert c.has_credential("the quick brown fox jumps over the lazy dog") is False


def test_a_query_key_is_both_a_query_secret_and_its_shape() -> None:
    """``?key=sk-...`` is reported under both kinds; presence is what matters."""
    text = "GET /v1?key=" + "sk" + "-proj-" + _TAIL
    found = c.kinds(text)
    assert found[K.QUERY_SECRET] == 1
    assert found[K.OPENAI_KEY] == 1


def test_has_credential_agrees_with_find() -> None:
    for _id, text, _kind in _ATTACKS:
        assert c.has_credential(text) is bool(c.find(text))


_HOSTILE = [
    "AKIA",
    "trt_",
    "trt_" + "a" * 19,  # one short of the body minimum, repeated
    "AKIA" + "B" * 15,  # the fixed {16} + boundary, repeated
    "-----BEGIN ",
    "-----BEGIN A PRIVATE KEY-----",  # the PEM body loop
    "?key=",
    "sk-",
    "eyJ",
    "Bearer ",
    "://a:",
]


@pytest.mark.parametrize("unit", _HOSTILE)
def test_find_stays_linear(unit: str) -> None:
    """Request bodies can be large; a pattern that rescans is a way to stall one."""
    for text in (unit * (1_000_000 // len(unit)), unit + "a" * 1_000_000):
        start = time.perf_counter()
        c.find(text)
        assert time.perf_counter() - start < 2.0
