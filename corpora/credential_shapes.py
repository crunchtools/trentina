"""Outbound requests the credential detector is tuned against (#511).

The detector (`trentina.credential_shapes`) is the request-direction reader of
the one credential-shape table. This corpus measures it the way
`corpora/benign_ops.py` measures L2: an ATTACK set, each an invented outbound
request carrying a real credential shape, and a BENIGN set, each a request-like
document that gets NEAR a shape without being one — the false-positive bait
(a UUID, a commit hash, an example key quoted in prose, a short opaque bearer,
a public-key header). Recall on the first and the false-positive rate on the
second are what `benchmarks/credential_shapes.py` reports.

Nothing here comes from a real request (constitution XVII): the key bodies are
generated from a fixed seed, so a case id names the same text forever, and the
agent-egress-bench corpus (#507) stays HELD OUT — a shape added because a bench
case missed is a tuning result and is labelled one, never scored as held-out.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass

from trentina.credential_shapes import CredentialKind as K

SEED = 511


@dataclass(frozen=True)
class Case:
    """One request document and what the detector should conclude about it."""

    id: str
    text: str
    #: The kinds that must be found (empty = a benign case: nothing may be found).
    expect: tuple[K, ...] = ()

    @property
    def benign(self) -> bool:
        return not self.expect


class _Gen:
    """Deterministic shaped filler, so every run reads the same bytes."""

    def __init__(self, seed: int) -> None:
        self._rng = random.Random(seed)

    def body(self, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
        return "".join(self._rng.choice(alphabet) for _ in range(n))

    def upper(self, n: int) -> str:
        return self.body(n, string.ascii_uppercase + string.digits)

    def hexs(self, n: int) -> str:
        return self.body(n, "0123456789abcdef")


def _cases() -> list[Case]:
    g = _Gen(SEED)
    attacks = [
        Case(
            "aws-key-in-query",
            f"GET https://api.vendor.example/v1/report?akey=AKIA{g.upper(16)} HTTP/1.1",
            (K.AWS_ACCESS_KEY,),
        ),
        Case(
            "aws-key-in-body",
            'POST /v1/messages\n{"text": "deploy with AKIA' + g.upper(16) + '"}',
            (K.AWS_ACCESS_KEY,),
        ),
        Case(
            "openai-key-in-body",
            'POST /v1/chat\n{"prompt": "my key is sk-proj-' + g.body(40) + '"}',
            (K.OPENAI_KEY,),
        ),
        Case(
            "google-api-key",
            'POST /ingest\n{"note": "AIza' + g.body(35) + ' is the maps key"}',
            (K.GOOGLE_API_KEY,),
        ),
        Case(
            "google-oauth-token",
            'POST /drive\n{"auth": "ya29.' + g.body(40) + '"}',
            (K.GOOGLE_OAUTH_TOKEN,),
        ),
        Case("matrix-token", 'PUT /send\n{"tok": "syt_' + g.body(32) + '"}', (K.MATRIX_TOKEN,)),
        Case("github-classic", 'POST /repos\n{"t": "ghp_' + g.body(36) + '"}', (K.GITHUB_TOKEN,)),
        Case(
            "github-pat",
            'POST /repos\n{"t": "github_pat_' + g.body(22) + "_" + g.body(59) + '"}',
            (K.GITHUB_TOKEN,),
        ),
        Case("slack-token", 'POST /chat\n{"t": "xoxb-' + g.hexs(12) + '"}', (K.SLACK_TOKEN,)),
        Case(
            "jwt",
            "GET /me\nAuthorization: Bearer eyJ"
            + g.body(20)
            + ".eyJ"
            + g.body(30)
            + "."
            + g.body(43),
            # A JWT in an Authorization header is BOTH shapes; both must be found.
            (K.AUTHORIZATION, K.JWT),
        ),
        Case(
            "pem-in-body",
            'POST /keys\n{"pem": "-----BEGIN RSA PRIVATE KEY-----\\nMII' + g.body(40) + '"}',
            (K.PEM_PRIVATE_KEY,),
        ),
        Case(
            "password-in-query",
            f"POST https://svc.example/login?user=ops&password={g.body(18)} HTTP/1.1",
            (K.QUERY_SECRET,),
        ),
        Case(
            "client-secret-in-body",
            f"POST /token\nclient_id=app&client_secret={g.body(40)}&grant_type=client_credentials",
            (K.QUERY_SECRET,),
        ),
        Case(
            "bearer-in-header",
            "GET /v1/data\nAuthorization: Bearer " + g.body(48),
            (K.AUTHORIZATION,),
        ),
        Case(
            "url-userinfo",
            f"POST https://ops:{g.body(16)}@db.internal.example:5432/write HTTP/1.1",
            (K.URL_USERINFO,),
        ),
    ]
    benign = [
        Case("uuid-in-path", "GET /v1/orders/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1"),
        Case("commit-sha", 'POST /ci\n{"ref": "' + g.hexs(40) + '"}'),
        Case(
            "aws-prefix-too-short",
            'POST /note\n{"text": "the id starts AKIA then 9 chars AKIAEXAMPLE1"}',
        ),
        Case("public-key-header", 'POST /keys\n{"pem": "-----BEGIN PUBLIC KEY-----"}'),
        Case("short-opaque-bearer", "GET /ping\nAuthorization: Bearer abc123"),
        Case(
            "secret-the-word",
            'POST /chat\n{"text": "keep this secret and do not share the password with anyone"}',
        ),
        Case("ordinary-query", "GET https://api.example/search?q=rhel+lifecycle&page=2 HTTP/1.1"),
        Case(
            "summarize-doc",
            'POST /v1/chat\n{"contents": [{"parts": [{"text": "summarize the attached report"}]}]}',
        ),
        Case("base64-not-a-key", 'POST /blob\n{"data": "' + g.body(64) + '=="}'),
        Case("sk-too-short", 'POST /chat\n{"note": "the sku is sk-123 in the catalog"}'),
        Case("eyj-not-a-jwt", 'POST /log\n{"text": "a token begins eyJ but eyJonly is not one"}'),
        Case("version-header", "GET /v1/data\nx-api-version: 7\naccept: application/json"),
    ]
    return attacks + benign


CASES: list[Case] = _cases()
ATTACKS: list[Case] = [c for c in CASES if not c.benign]
BENIGN: list[Case] = [c for c in CASES if c.benign]

#: Shapes the detector does not yet cover, scored but never gated — the honest
#: record of what this tuning set knows it misses. Empty today.
KNOWN_GAPS: list[str] = []
