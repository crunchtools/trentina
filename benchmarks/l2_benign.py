"""L2 benign gate: an L2 model must not refuse what the gateway delivers (#411, #404).

The obfuscation gate (``l2_obfuscation.py``) holds a model to reading through
encodings. This one holds it to the other side. Every case of the benign
corpus (``corpora/benign_ops.py``: operations output and agent-forum replies,
invented, of the shapes production refused) is read exactly as the gateway
reads a tool response: the structured copy of the text block dropped as the
router drops it (``results._drop_duplicate_structured``, #431), through the
default pre-processors (``gateway.transform.transform_response``), collected
the way the perimeter collects it, and unpacked. L2 scores that once.

The corpus is split one case in four for tuning. A threshold, or a
pre-processor's wording, is chosen on the tuning split; the held-out split is
what is reported, gated and recorded. Exit 1 when the model, at its own
threshold, flags more than ``BENIGN_MAX_RATE`` of the held-out cases.

A shape the shipped model is known to flag (``benign_ops.KNOWN_GAPS``) is
scored and printed on every run and recorded beside the result, outside the
budget: a gap that is measured every build, not one that is forgotten.

    CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/l2_benign.py

``--record`` writes the held-out result into the model's
``trentina-model.json``; the image build runs it after the obfuscation gate
and fails on a failing one. ``--sweep`` adds the table a threshold is chosen
from: benign flagged on each split, attacks detected plain, and whether the
obfuscation gate would still pass, at each cut. It scores every attack under
every transform, so it is the slow half and the build leaves it off.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.benign_ops import BENIGN, CATEGORIES, KNOWN_GAPS, Benign, in_tuning
from corpora.internal import CORPUS
from trentina.config import get_config
from trentina.gateway.ingress_defense import _collect_response_texts
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.results import _drop_duplicate_structured
from trentina.gateway.transform import transform_response
from trentina.quarantine.benign_gate import BENIGN_KEY, BENIGN_MAX_RATE, allowed, record_of
from trentina.quarantine.classifier import (
    MANIFEST_FILE,
    classify,
    is_classifier_available,
    model_info,
)
from trentina.quarantine.obfuscation import GATE_MAX_DROP, TRANSFORMS
from trentina.unpack.scan import unpack

SPLITS = ("held-out", "tuning")
SWEEP = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99)

_BACKEND = Backend(url="http://ops.invalid/mcp", tools_allow=["*"])
_PROFILE = Profile(
    name="benign-gate",
    auth=AuthConfig(bearer_token_env="BENIGN_GATE_TOKEN"),
    backends={"ops": _BACKEND},
)
"""A profile with every default: the pre-processing an operator who
configured nothing gets."""


async def as_read(case: Benign) -> str:
    """``case`` as L2 reads it behind the gateway.

    A tool response arrives as a JSON text block and the same object as
    ``structuredContent``; a document as a text block alone. The router drops
    a structured copy that repeats the text, the default pre-processors
    rewrite the text block, the perimeter collects what is left, and the
    unpack stage builds what the layers read from that.
    """
    text = json.dumps(case.payload, separators=(",", ":")) if case.structured else case.payload
    blocks: list[Any] = [{"type": "text", "text": text}]
    structured = _drop_duplicate_structured(case.payload if case.structured else None, blocks)
    outcome = await transform_response(
        profile=_PROFILE,
        backend=_BACKEND,
        backend_name="ops",
        tool_name=case.category,
        content_blocks=blocks,
    )
    texts, _, _, _ = _collect_response_texts(outcome.content_blocks, structured)
    return unpack("\n".join(texts)).text


def _score(text: str) -> float:
    result = classify(text)
    if result is None:
        raise RuntimeError("the L2 model stopped answering")
    return result.score


async def score_benign() -> dict[str, float]:
    """Each benign case's L2 score, by case id."""
    return {case.id: _score(await as_read(case)) for case in BENIGN}


def by_category(
    scores: dict[str, float],
    threshold: float,
    split: str,
    categories: tuple[str, ...] = CATEGORIES,
) -> dict[str, Any]:
    """``(flagged, cases)`` per category for one split at ``threshold``.

    The gated categories unless ``categories`` names others (``KNOWN_GAPS``).
    """
    tuning = split == "tuning"
    out: dict[str, tuple[int, int]] = {}
    for name in categories:
        mine = [scores[c.id] for c in BENIGN if c.category == name and in_tuning(c.id) == tuning]
        out[name] = (sum(score >= threshold for score in mine), len(mine))
    return out


def report(scores: dict[str, float], threshold: float) -> str:
    """Flagged per category on both splits, held-out first."""
    splits = {split: by_category(scores, threshold, split) for split in SPLITS}
    lines = ["| category | held-out flagged | tuning flagged |", "|---|---|---|"]
    for name in CATEGORIES:
        cells = " | ".join("{} of {}".format(*splits[split][name]) for split in SPLITS)
        lines.append(f"| {name} | {cells} |")
    totals = " | ".join(
        "**{} of {}**".format(
            *(sum(column) for column in zip(*splits[split].values(), strict=True))
        )
        for split in SPLITS
    )
    lines.append(f"| all | {totals} |")
    for name in KNOWN_GAPS:
        cells = " | ".join(
            "{} of {}".format(*by_category(scores, threshold, split, (name,))[name])
            for split in SPLITS
        )
        lines.append(f"| {name} (known gap, not gated) | {cells} |")
    return "\n".join(lines)


def sweep(scores: dict[str, float]) -> str:
    """The table a threshold is chosen from: benign flagged, attacks kept, and
    whether the obfuscation gate still passes, at each cut."""
    attacks = [c.payload for c in CORPUS if c.expect_injection]
    plain = [_score(a) for a in attacks]
    under = {name: [_score(change(a)) for a in attacks] for name, change in TRANSFORMS.items()}
    lines = [
        (
            "| threshold | held-out benign flagged | tuning benign flagged | attacks, plain "
            "| fewest under a transform | obfuscation gate |"
        ),
        "|---|---|---|---|---|---|",
    ]
    for cut in SWEEP:
        flagged = [
            "{} of {}".format(
                *(sum(c) for c in zip(*by_category(scores, cut, split).values(), strict=True))
            )
            for split in SPLITS
        ]
        kept = sum(score >= cut for score in plain)
        fewest = min(sum(score >= cut for score in column) for column in under.values())
        gate = "pass" if kept - fewest <= GATE_MAX_DROP else "FAIL"
        lines.append(
            f"| {cut:g} | {flagged[0]} | {flagged[1]} | {kept} of {len(attacks)} "
            f"| {fewest} | {gate} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--record",
        action="store_true",
        help=f"write the held-out result into the model's {MANIFEST_FILE}, pass or fail",
    )
    parser.add_argument("--sweep", action="store_true", help="also print the threshold table")
    parser.add_argument("--json", type=Path, help="write every case's score here")
    args = parser.parse_args(argv)
    # transform_response logs one line a response at WARNING, the level
    # production reads; here it would bury the report.
    logging.getLogger("trentina.gateway.transform").setLevel(logging.ERROR)
    model = model_info() if is_classifier_available() else None
    if model is None:
        print("error: no L2 model loaded (set CLASSIFIER_MODEL_PATH)", file=sys.stderr)
        return 2

    scores = asyncio.run(score_benign())
    record = record_of(by_category(scores, model.threshold, "held-out"), model.threshold)
    record["known_gaps"] = {
        name: dict(zip(("flagged", "of"), counts, strict=True))
        for name, counts in by_category(scores, model.threshold, "held-out", KNOWN_GAPS).items()
    }
    print(f"{model.id} at {model.threshold:g}, {len(BENIGN)} benign cases\n")
    print(report(scores, model.threshold))
    verdict = "pass" if record["passed"] else "FAIL"
    print(
        f"\nheld-out: {record['flagged']} of {record['cases']} flagged, "
        f"{allowed(record['cases'])} allowed ({BENIGN_MAX_RATE:.0%}): {verdict}"
    )
    flagged = sorted(case_id for case_id, score in scores.items() if score >= model.threshold)
    if flagged:
        print("flagged: " + ", ".join(f"{case_id} ({scores[case_id]:.2f})" for case_id in flagged))
    if args.sweep:
        print("\n" + sweep(scores))
    if args.json:
        args.json.write_text(json.dumps({"model": model.id, "scores": scores}, indent=1) + "\n")
    if args.record:
        _write_record(record)
    return 0 if record["passed"] else 1


def _write_record(record: dict[str, Any]) -> None:
    """Add the record to the manifest beside the loaded model."""
    path = Path(get_config().classifier_model_path) / MANIFEST_FILE
    manifest = json.loads(path.read_text()) if path.is_file() else {}
    manifest[BENIGN_KEY] = record
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"\nrecorded in {path}")


if __name__ == "__main__":
    sys.exit(main())
