"""What L2's flag is worth when the judge answers clean (#404).

Any layer's flag refuses under ``block``, so L2 refuses on its own whenever
L3 clears what L2 flags. Whether it should is a count: of the attacks a judge
cleared, how many did L2 flag, and of the benign documents, how many did only
L2 refuse. This reads the per-case results other benchmarks already wrote and
scores L2 on the same texts, each unpacked as ``defend()`` reads it (the
pre-processors are not run first). It calls no judge and spends nothing, so
it can be run again on a stored result whenever L2 or a corpus changes.

    CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/l2_lone_flag.py \\
        --packs pack.json --judged detonation.json --corpora benchmark-*.json

``--packs`` takes ``prompt_pack.py --json`` results (held-out split),
``--judged`` takes ``detonation.py --mode judge --carriers all --tasks 0
--no-injecagent`` results, and ``--corpora`` takes ``provider_benchmark.py``
results on the internal, garak and disclosed corpora. A case a result names
and this checkout no longer builds is counted as ``unmatched`` and left out.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _path in (_REPO_ROOT, _REPO_ROOT / "benchmarks"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import detonation
import prompt_pack

from corpora import disclosed, garak_latent
from corpora.detonation import ACTION_ATTACKS, BENIGN_INSERTS, CARRIERS, internal_inserts
from corpora.fetch import CACHE_DIR
from corpora.internal import CORPUS
from trentina.quarantine.classifier import classify, is_classifier_available, model_info
from trentina.unpack.scan import unpack

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


@dataclass(frozen=True)
class Judged:
    """One case as a judge left it: its text, the truth, and the judge's answer."""

    text: str
    attack: bool
    detected: bool


@dataclass(frozen=True)
class Row:
    """One judge on one set of cases, with L2's label beside its answers.

    ``cleared`` is the attacks the judge did not flag; ``cleared_l2`` is how
    many of those L2 flags, which is what L2's lone refusal catches, and
    ``cleared_both`` is what reaches the agent. On the benign side ``only_l2``
    is what that lone refusal costs: documents the judge passed and L2 did not.
    """

    source: str
    judge: str
    attacks: int
    cleared: int
    cleared_l2: int
    cleared_both: int
    benign: int
    judge_flagged: int
    only_l2: int
    unmatched: int = 0


def tally(
    source: str, judge: str, cases: Iterable[Judged], flagged: Callable[[str], bool], unmatched: int
) -> Row:
    """Count ``cases`` into a :class:`Row`, asking ``flagged`` for L2's label."""
    cases = list(cases)
    cleared = [c for c in cases if c.attack and not c.detected]
    cleared_l2 = sum(flagged(c.text) for c in cleared)
    passed = [c for c in cases if not c.attack and not c.detected]
    return Row(
        source=source,
        judge=judge,
        attacks=sum(c.attack for c in cases),
        cleared=len(cleared),
        cleared_l2=cleared_l2,
        cleared_both=len(cleared) - cleared_l2,
        benign=sum(not c.attack for c in cases),
        judge_flagged=sum(not c.attack and c.detected for c in cases),
        only_l2=sum(flagged(c.text) for c in passed),
        unmatched=unmatched,
    )


def pack_row(run: dict[str, Any], flagged: Callable[[str], bool]) -> Row:
    """A ``prompt_pack.py`` result: it names the cases it missed and wrongly flagged.

    A case the judge never answered is in neither list and was left out of
    the run's own counts; here it counts as answered correctly, which is why
    ``attacks`` can exceed the run's by its errors.
    """
    split = prompt_pack.split_cases(run["split"], prompt_pack.TRAIN_EXTERNAL, CACHE_DIR)
    cases = {case.id: case for case in split}
    wrong = {*run["missed"], *run["flagged_benign"]}
    judged = [
        Judged(case.payload, case.expect_injection, (name in wrong) != case.expect_injection)
        for name, case in cases.items()
    ]
    source, judge = f"pack gate, {run['split']}", f"{run['model']} ({run['pack']})"
    return tally(source, judge, judged, flagged, len(wrong - set(cases)))


def embedded_documents() -> dict[str, str]:
    """Every document ``detonation.py --carriers all --tasks 0 --no-injecagent`` judges."""
    attacks, benign = internal_inserts()
    built = detonation.build_cases(
        attacks + ACTION_ATTACKS,
        benign + BENIGN_INSERTS,
        carriers=len(CARRIERS),
        tasks=(0,),
        only=("clean", "benign", "attack"),
    )
    return {detonation.document_id(case): case.document() for case in built}


def judged_row(run: dict[str, Any], flagged: Callable[[str], bool]) -> Row:
    """A ``detonation.py --mode judge`` result: one majority verdict per document."""
    documents = embedded_documents()
    known = [v for v in run["verdicts"] if v["document"] in documents]
    judged = [
        Judged(documents[v["document"]], v["condition"] == "attack", bool(v["detected"]))
        for v in known
    ]
    source = f"embedded documents, briefing {run.get('briefing', 'none')}"
    return tally(source, run["model"], judged, flagged, len(run["verdicts"]) - len(known))


def corpus_texts() -> dict[str, str]:
    """Payloads of the internal, garak and disclosed corpora, by case id."""
    cases = [*CORPUS, *garak_latent.load("full"), *disclosed.CORPUS]
    return {case.id: case.payload for case in cases}


def corpora_row(runs: list[dict[str, Any]], flagged: Callable[[str], bool]) -> Row:
    """One judge's ``provider_benchmark.py`` results, every corpus it ran together."""
    texts = corpus_texts()
    rows = [case for run in runs for case in run["providers"][0]["cases"]]
    known = [r for r in rows if r["id"] in texts and not r.get("error")]
    judged = [Judged(texts[r["id"]], r["expect_injection"], bool(r["detected"])) for r in known]
    judge = runs[0]["providers"][0]["model"]
    return tally("internal, garak, disclosed", judge, judged, flagged, len(rows) - len(known))


def render(rows: list[Row]) -> str:
    """The rows as one Markdown table."""
    lines = [
        (
            "| set | judge | attacks | judge cleared | of those, L2 flags | cleared by both "
            "| benign | judge flags | only L2 flags |"
        ),
        "|---|---|---|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {r.source} | {r.judge} | {r.attacks} | {r.cleared} | {r.cleared_l2} "
        f"| {r.cleared_both} | {r.benign} | {r.judge_flagged} | {r.only_l2} |"
        for r in rows
    ]
    return "\n".join(lines)


def _l2_flags() -> Callable[[str], bool]:
    """L2's label on a text as ``defend()`` reads it, unpacked, scored once per text."""
    seen: dict[str, bool] = {}

    def flagged(text: str) -> bool:
        if text not in seen:
            result = classify(unpack(text).text)
            seen[text] = result is not None and result.label == "MALICIOUS"
        return seen[text]

    return flagged


def _load(names: list[str]) -> list[dict[str, Any]]:
    return [json.loads(Path(name).read_text()) for name in names]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--packs", nargs="*", default=[], help="prompt_pack.py results")
    parser.add_argument("--judged", nargs="*", default=[], help="detonation.py judge results")
    parser.add_argument("--corpora", nargs="*", default=[], help="provider_benchmark.py results")
    parser.add_argument("--json", default="", help="also write the rows here")
    args = parser.parse_args(argv)
    if not is_classifier_available():
        print("error: no L2 model loaded (set CLASSIFIER_MODEL_PATH)", file=sys.stderr)
        return 2

    flagged = _l2_flags()
    rows = [pack_row(run, flagged) for run in _load(args.packs)]
    rows += [judged_row(run, flagged) for run in _load(args.judged)]
    by_judge: dict[str, list[dict[str, Any]]] = {}
    for run in _load(args.corpora):
        by_judge.setdefault(run["providers"][0]["model"], []).append(run)
    rows += [corpora_row(runs, flagged) for runs in by_judge.values()]

    model = model_info()
    print(f"L2: {model.id if model else '?'} at {model.threshold if model else '?'}\n")
    print(render(rows))
    if args.json:
        Path(args.json).write_text(json.dumps([asdict(row) for row in rows], indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
