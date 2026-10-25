"""Fine-tune the shipped L2 model on ``l2_train_data.py``'s set.

Starts from Horizon (``Horizon-Labs/prompt-injection-guard-small``) at the
revision the image pins, keeps its head and labels (``SAFE``/``INJECTION``),
and trains briefly at a low learning rate: the goal is to move what it
learned about envelopes, not to relearn injection. The checkpoint written to
``--out`` is a plain ``safetensors`` sequence-classification model that
``export_l2_model.py --src`` turns into the ONNX export the image ships.

    python scripts/train_l2_model.py --data build/l2-train --out build/l2-model

Writes ``training.json`` beside the model: base and revision, data
provenance, hyperparameters, and the validation loss and accuracy.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

BASE = "Horizon-Labs/prompt-injection-guard-small"
BASE_REVISION = "3215a27edd62c5ba0bd786c57a9d243b2158e70e"
"""The Containerfile's ``HORIZON_REVISION``: the model production runs.
``tests/test_l2_envelopes.py`` fails when the two differ."""

SEED = 20261025
LOG_EVERY_STEPS = 50
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
    ``dropped[split]`` when it was not found, never mislabelled.
    """
    safe, injection = labels
    stride = content - GUARD_TOKENS

    def example(ids: list[int], label: int) -> dict:
        full = tok.build_inputs_with_special_tokens(ids)
        return {"input_ids": full, "attention_mask": [1] * len(full), "labels": label}

    out = []
    for line in path.read_text().splitlines():
        row = json.loads(line)
        enc = tok(row["text"], add_special_tokens=False, return_offsets_mapping=True)
        ids = enc["input_ids"]
        if len(ids) <= content:
            out.append(example(ids, injection if row["label"] else safe))
        elif not row["label"]:
            starts = list(range(0, len(ids), stride))
            picks = sorted({starts[0], starts[len(starts) // 2], starts[-1]})
            out += [example(ids[i : i + content], safe) for i in picks[:BENIGN_WINDOWS]]
        elif row.get("at", -1) < 0:
            dropped[split] += 1
        else:
            first = next(
                (k for k, (_, end) in enumerate(enc["offset_mapping"]) if end > row["at"]),
                len(ids),
            )
            begin = max(0, min(first - GUARD_TOKENS, len(ids) - content))
            out.append(example(ids[begin : begin + content], injection))
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--epochs", type=float, default=1.0)
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--batch", type=int, default=8)
    p.add_argument("--max-length", type=int, default=512)
    p.add_argument("--threads", type=int, default=0, help="torch threads; 0 keeps the default.")
    args = p.parse_args()

    import torch
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

    content = args.max_length - tok.num_special_tokens_to_add()
    dropped = {"train": 0, "val": 0}
    train, val = (
        windows(tok, args.data / f"{split}.jsonl", content, (safe, injection), dropped, split)
        for split in ("train", "val")
    )

    def metrics(pred: tuple) -> dict:
        logits, gold = pred
        return {"accuracy": float((logits.argmax(-1) == gold).mean())}

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(args.out / "checkpoints"),
            num_train_epochs=args.epochs,
            learning_rate=args.lr,
            per_device_train_batch_size=args.batch,
            per_device_eval_batch_size=args.batch,
            warmup_ratio=0.06,
            weight_decay=0.01,
            eval_strategy="epoch",
            save_strategy="no",
            logging_steps=LOG_EVERY_STEPS,
            report_to=[],
            seed=SEED,
            use_cpu=not torch.cuda.is_available(),
        ),
        train_dataset=train,
        eval_dataset=val,
        data_collator=DataCollatorWithPadding(tok),
        compute_metrics=metrics,
    )
    trainer.train()
    result = trainer.evaluate()
    model.save_pretrained(args.out, safe_serialization=True)
    tok.save_pretrained(args.out)
    sources = json.loads((args.data / "sources.json").read_text())
    (args.out / "training.json").write_text(
        json.dumps(
            {
                "base": BASE,
                "base_revision": BASE_REVISION,
                "data": sources,
                "hyperparameters": {
                    k: v for k, v in vars(args).items() if k not in {"data", "out"}
                },
                "windows": {"train": len(train), "val": len(val)},
                "long_attacks_dropped": dropped,
                "validation": result,
            },
            indent=2,
            default=str,
        )
    )
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
