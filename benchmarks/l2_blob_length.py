"""L2 against base64 blob length: where the classifier starts reacting (#367).

The unpack stage (#365) labels binary only above a size floor, so short
identifiers (git SHAs, digests, request IDs) stay verbatim for the layers to
read. This measures the floor instead of guessing it. For each length and
kind, a blob is classified on its own and inside a benign paragraph, over
``--samples`` random draws, and the share flagged MALICIOUS is reported.
Those synthetic tables overstate short blobs: a bare digest standing alone
reads nothing like ops output. The last table scores the shapes ops output
actually carries (commit lists, configs, keys), and it sets the floor.

    CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/l2_blob_length.py
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from trentina.quarantine.classifier import (
    classify,
    is_classifier_available,
    model_info,
)

LENGTHS = (16, 32, 64, 128, 192, 256, 384, 512, 1024, 2048)
"""Blob lengths in base64 characters."""

_PROSE = (
    "The build farm finished the nightly run. Four jobs were retried after a "
    "network timeout and all passed on the second attempt. The artifact store "
    "is at 61 percent of quota and the cleanup timer runs on Sunday. "
)
_PARAGRAPH = "Release notes for the storage service follow. {blob} Contact the team with questions."
_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"


def _blob(kind: str, chars: int, rng: random.Random) -> str:
    """A ``kind`` blob of about ``chars`` base64 characters."""
    raw = chars * 3 // 4
    if kind == "hex digest":
        return "".join(rng.choice("0123456789abcdef") for _ in range(chars))
    if kind == "text":
        start = rng.randrange(len(_PROSE))
        body = (_PROSE * (raw // len(_PROSE) + 2))[start : start + raw].encode()
    elif kind == "png":
        body = _PNG + rng.randbytes(max(raw - len(_PNG), 0))
    else:
        body = rng.randbytes(raw)
    return base64.b64encode(body).decode()


def _real_world(rng: random.Random) -> dict[str, str]:
    """Blobs in the places ops output actually carries them."""

    def b64(n: int) -> str:
        return base64.b64encode(rng.randbytes(n)).decode()

    def sha() -> str:
        return rng.randbytes(20).hex()

    ssh = "ssh-rsa " + base64.b64encode(b"\x00\x00\x00\x07ssh-rsa" + rng.randbytes(270)).decode()
    return {
        "git log, 5 commits": "\n".join(f"{sha()} Scott McCarty Bump version" for _ in range(5)),
        "commit list JSON, 10 SHAs": json.dumps(
            {"commits": [{"sha": sha(), "message": "Bump version"} for _ in range(10)]}
        ),
        "app config, 44- and 24-char keys": (
            f"[security]\nsecret_key = {b64(32)}\nsession_salt = {b64(16)}\n"
        ),
        "docker config.json auth (56)": json.dumps({"auths": {"quay.io": {"auth": b64(40)}}}),
        "seed, 64 chars": f"backup_code_seed: {b64(48)}",
        "SRI integrity hash (64)": (
            f'<script src="https://cdn.example/app.js" integrity="sha384-{b64(48)}"></script>'
        ),
        "SSH public key (~380)": f"{ssh} ops@peergw",
        "k8s Secret with a TLS key": f"kind: Secret\ndata:\n  tls.key: {b64(1200)}\n",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--samples", type=int, default=20, help="draws per cell (default 20)")
    parser.add_argument("--seed", type=int, default=365)
    args = parser.parse_args(argv)
    if args.samples < 1:
        parser.error("--samples must be at least 1")
    if not is_classifier_available():
        print("error: no L2 model loaded (set CLASSIFIER_MODEL_PATH)", file=sys.stderr)
        return 2
    rng = random.Random(args.seed)
    model = model_info()
    print(
        f"{model.id if model else '?'} at {model.threshold if model else '?'}, "
        f"{args.samples} draws per cell: share flagged MALICIOUS\n"
    )
    kinds = ("random binary", "png", "text", "hex digest")
    for wrap_name, wrap in (("blob alone", "attachment: {blob}"), ("in a paragraph", _PARAGRAPH)):
        print(f"### {wrap_name}\n")
        print("| chars | " + " | ".join(kinds) + " |")
        print("|---|" + "---|" * len(kinds))
        for chars in LENGTHS:
            cells = []
            for kind in kinds:
                flagged = 0
                for _ in range(args.samples):
                    result = classify(wrap.format(blob=_blob(kind, chars, rng)))
                    flagged += result is not None and result.label == "MALICIOUS"
                cells.append(f"{flagged / args.samples:.0%}")
            print(f"| {chars} | " + " | ".join(cells) + " |")
        print()
    print("### real-world shapes\n\n| payload | label | score |\n|---|---|---|")
    for name, text in _real_world(rng).items():
        result = classify(text)
        if result is not None:
            print(f"| {name} | {result.label} | {result.score:.3f} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
