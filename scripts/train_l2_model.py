"""Fine-tune the shipped L2 model on ``l2_train_data.py``'s set.

Starts from Horizon (``Horizon-Labs/prompt-injection-guard-small``) at the
revision the image pins, keeps its head and labels (``SAFE``/``INJECTION``),
and trains briefly at a low learning rate: the goal is to move what it
learned about envelopes, not to relearn injection. Three things hold it to
what Horizon already reads well (runs 2 and 3 drifted on shapes no training
row resembled):

- rows marked ``distill`` train toward Horizon's own score as well as their
  label, the loss Horizon's own trainer uses (``--distill``,
  horizon-ai-labs/agent-io-guards ``train/train.py``);
- the token embeddings, most of the model's weights and none of what an
  envelope changes, stay frozen;
- after training, ``--blends`` writes the weights interpolated back toward
  Horizon's (WiSE-FT, Wortsman et al. 2022), one model per mix, for the gates
  to choose between.

The checkpoint written to ``--out`` (and each ``--out``/``blend-<a>``) is a
plain ``safetensors`` sequence-classification model that
``export_l2_model.py --src`` turns into the ONNX export the image ships.

    python scripts/train_l2_model.py --data build/l2-train --out build/l2-model

Writes ``training.json`` beside each model: base and revision, data
provenance, hyperparameters, the blend, and the validation loss and accuracy.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

BASE = "Horizon-Labs/prompt-injection-guard-small"
BASE_REVISION = "3215a27edd62c5ba0bd786c57a9d243b2158e70e"
"""The Containerfile's ``HORIZON_REVISION``: the model production runs.
``tests/test_l2_envelopes.py`` fails when the two differ."""

SEED = 20261025
LOG_EVERY_STEPS = 50
EVALS_PER_RUN = 4
"""Validation passes over training; the one with the lowest loss is kept."""
TEACHER_BATCH = 32
GUARD_TOKENS = 64
"""Tokens neighbouring windows share: the runtime's default (``classifier.py``)."""
BENIGN_WINDOWS = 3
"""Windows one long benign row gives at most (its first, middle and last), so
a few long envelopes do not outnumber every attack (run 40191101108: 7,344
windows from 6,160 rows, 1,115 attacks dropped)."""


def windows(
    tok: Any,
    path: Path,
    content: int,
    labels: tuple[int, int],
    dropped: dict[str, int],
    split: str,
) -> list[dict]:
    """``path``'s rows as the runtime scans them: windows of ``content`` tokens.

    A benign row is benign in every window, so a long one gives up to
    ``BENIGN_WINDOWS`` of them. An attack is an attack only in a window that
    holds it: a long one gives the window that starts ``GUARD_TOKENS`` before
    where the data builder found it (``at``), and is dropped and counted in
    ``dropped[split]`` when it was not found, never mislabelled. Each window
    carries ``soft``, its target probability of ``INJECTION`` (its label until
    ``teach`` replaces it), and the row's ``distill`` mark.
    """
    safe, injection = labels
    stride = content - GUARD_TOKENS

    def example(ids: list[int], label: int, distill: bool) -> dict:
        # The runtime's wrapping (classifier._pad_segment). Not
        # build_inputs_with_special_tokens: on Horizon's fast tokenizer it
        # adds nothing, and runs 1 to 4 trained the head on the first content
        # token where the runtime puts CLS.
        full = [tok.cls_token_id, *ids, tok.sep_token_id]
        return {
            "input_ids": full,
            "attention_mask": [1] * len(full),
            "labels": label,
            "soft": float(label == injection),
            "distill": distill,
        }

    out = []
    for line in path.read_text().splitlines():
        row = json.loads(line)
        distill = bool(row.get("distill"))
        enc = tok(row["text"], add_special_tokens=False, return_offsets_mapping=True)
        ids = enc["input_ids"]
        if len(ids) <= content:
            out.append(example(ids, injection if row["label"] else safe, distill))
        elif not row["label"]:
            starts = list(range(0, len(ids), stride))
            picks = sorted({starts[0], starts[len(starts) // 2], starts[-1]})
            out += [example(ids[i : i + content], safe, distill) for i in picks[:BENIGN_WINDOWS]]
        elif row.get("at", -1) < 0:
            dropped[split] += 1
        else:
            first = next(
                (k for k, (_, end) in enumerate(enc["offset_mapping"]) if end > row["at"]),
                len(ids),
            )
            begin = max(0, min(first - GUARD_TOKENS, len(ids) - content))
            out.append(example(ids[begin : begin + content], injection, distill))
    return out


def teach(model: Any, collate: Any, examples: list[dict], injection: int) -> int:
    """Set ``soft`` to the base model's own score on every ``distill`` window.

    Runs before training, while ``model`` is still the base; a text repeated
    (the anchors are) is scored once. Returns how many windows it scored.
    """
    import torch

    todo = sorted((e for e in examples if e["distill"]), key=lambda e: len(e["input_ids"]))
    seen: dict[tuple[int, ...], float] = {}
    fresh = list({tuple(e["input_ids"]): e for e in todo}.values())
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    with torch.no_grad():
        for i in range(0, len(fresh), TEACHER_BATCH):
            part = fresh[i : i + TEACHER_BATCH]
            batch = collate(
                [{"input_ids": e["input_ids"], "attention_mask": e["attention_mask"]} for e in part]
            )
            batch = {k: v.to(device) for k, v in batch.items()}
            probs = torch.softmax(model(**batch).logits.float(), -1)[:, injection]
            seen.update(zip((tuple(e["input_ids"]) for e in part), probs.tolist(), strict=True))
    model.train()
    for e in todo:
        e["soft"] = seen[tuple(e["input_ids"])]
    return len(fresh)


def distill_loss(logits: Any, gold: Any, soft: Any, weight: float, labels: tuple[int, int]) -> Any:
    """``(1 - weight)`` cross-entropy on ``gold`` plus ``weight`` cross-entropy on
    ``soft``, the target probability of ``INJECTION`` (Horizon's ``--distill``)."""
    import torch

    safe, injection = labels
    logp = torch.log_softmax(logits.float(), -1)
    target = torch.zeros_like(logp)
    target[:, injection], target[:, safe] = soft.float(), 1 - soft.float()
    hard = torch.nn.functional.nll_loss(logp, gold)
    return (1 - weight) * hard + weight * -(target * logp).sum(-1).mean()


def write_blends(
    model: Any, tok: Any, out: Path, record: dict[str, Any], blends: list[float]
) -> None:
    """Save ``model`` to ``out``, then each ``(1 - a) * base + a * model`` to
    ``out/blend-<a>`` (WiSE-FT), each with its ``training.json``."""
    from transformers import AutoModelForSequenceClassification

    def save(path: Path, blend: float) -> None:
        model.save_pretrained(path, safe_serialization=True)
        tok.save_pretrained(path)
        (path / "training.json").write_text(
            json.dumps({**record, "blend": blend}, indent=2, default=str)
        )

    save(out, 1.0)
    if not blends:
        return
    tuned = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
    base = AutoModelForSequenceClassification.from_pretrained(
        BASE, revision=BASE_REVISION
    ).state_dict()
    for a in blends:
        model.load_state_dict(
            {k: (1 - a) * base[k] + a * v if v.is_floating_point() else v for k, v in tuned.items()}
        )
        save(out / f"blend-{a:g}", a)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--epochs", type=float, default=2.0)
    p.add_argument(
        "--lr",
        type=float,
        default=2e-5,
        help="GPU round 3 (docs/benchmark.md): with distill 0.5 and the advisory "
        "text, 2e-5 for 2 epochs beat 1e-5, 3e-5 and a third epoch on real replies.",
    )
    p.add_argument("--batch", type=int, default=8)
    p.add_argument("--max-length", type=int, default=512)
    p.add_argument(
        "--distill",
        type=float,
        default=0.5,
        help="Weight of the loss toward the base model's score on distill rows "
        "(Horizon v2.3 trained with 0.5).",
    )
    p.add_argument(
        "--blends",
        default="",
        help="Comma-separated mixes of the fine-tuned weights to write beside the "
        "full fine-tune (1.0, written to --out), the rest Horizon's, e.g. 0.4,0.6,0.8. "
        "None by default: round 3 shipped the full fine-tune, blend 0.8 within noise.",
    )
    p.add_argument("--threads", type=int, default=0, help="torch threads; 0 keeps the default.")
    args = p.parse_args()
    blends = [float(a) for a in args.blends.split(",") if a.strip()]
    if not all(0 < a < 1 for a in blends) or not 0 <= args.distill < 1:
        p.error("blends must lie strictly between 0 and 1, and distill in [0, 1)")

    import torch
    import transformers
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        DataCollatorWithPadding,
        Trainer,
        TrainingArguments,
    )

    if args.threads:
        torch.set_num_threads(args.threads)
    tok = AutoTokenizer.from_pretrained(BASE, revision=BASE_REVISION)
    model = AutoModelForSequenceClassification.from_pretrained(BASE, revision=BASE_REVISION)
    labels = {v: int(k) for k, v in model.config.id2label.items()}
    safe, injection = labels["SAFE"], labels["INJECTION"]
    collate = DataCollatorWithPadding(tok)

    content = args.max_length - tok.num_special_tokens_to_add()
    dropped = {"train": 0, "val": 0}
    train, val = (
        windows(tok, args.data / f"{split}.jsonl", content, (safe, injection), dropped, split)
        for split in ("train", "val")
    )
    taught = {
        split: teach(model, collate, rows, injection) if args.distill else 0
        for split, rows in (("train", train), ("val", val))
    }
    for e in (*train, *val):
        del e["distill"]
    model.get_input_embeddings().weight.requires_grad_(False)

    class DistillTrainer(Trainer):
        """Cross-entropy on the label, mixed with cross-entropy on ``soft``."""

        def compute_loss(
            self,
            model: Any,
            inputs: dict[str, Any],
            return_outputs: bool = False,
            num_items_in_batch: Any = None,
        ) -> Any:
            soft, gold = inputs.pop("soft"), inputs.pop("labels")
            outputs = model(**inputs)
            loss = distill_loss(outputs.logits, gold, soft, args.distill, (safe, injection))
            if num_items_in_batch:  # accumulated steps: the Trainer divides by the total
                loss = loss * len(gold) / num_items_in_batch
            return (loss, outputs) if return_outputs else loss

    def metrics(pred: Any) -> dict:
        logits, gold = pred
        return {"accuracy": float((logits.argmax(-1) == gold).mean())}

    steps = max(1, int(len(train) / args.batch * args.epochs))
    every = max(1, steps // EVALS_PER_RUN)
    trainer = DistillTrainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(args.out / "checkpoints"),
            num_train_epochs=args.epochs,
            learning_rate=args.lr,
            per_device_train_batch_size=args.batch,
            per_device_eval_batch_size=args.batch,
            warmup_ratio=0.06,
            weight_decay=0.01,
            adam_beta2=0.98,
            adam_epsilon=1e-6,
            lr_scheduler_type="cosine",
            max_grad_norm=1.0,
            eval_strategy="steps",
            eval_steps=every,
            save_strategy="steps",
            save_steps=every,
            save_total_limit=1,
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            label_names=["labels"],
            remove_unused_columns=False,  # ``soft`` is no model input; the loss needs it
            logging_steps=LOG_EVERY_STEPS,
            report_to=[],
            seed=SEED,
            use_cpu=not torch.cuda.is_available(),
        ),
        train_dataset=train,
        eval_dataset=val,
        data_collator=collate,
        compute_metrics=metrics,
    )
    trainer.train()
    result = trainer.evaluate()
    shutil.rmtree(args.out / "checkpoints", ignore_errors=True)
    record = {
        "base": BASE,
        "base_revision": BASE_REVISION,
        "data": json.loads((args.data / "sources.json").read_text()),
        "hyperparameters": {k: v for k, v in vars(args).items() if k not in {"data", "out"}},
        "windows": {"train": len(train), "val": len(val)},
        "teacher_scored": taught,
        "long_attacks_dropped": dropped,
        "validation": result,
        "trained_on": {
            "device": torch.cuda.get_device_name() if torch.cuda.is_available() else "cpu",
            "torch": torch.__version__,
            "transformers": transformers.__version__,
        },
    }

    write_blends(model, tok, args.out, record, blends)
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
