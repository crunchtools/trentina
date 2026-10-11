#!/usr/bin/env python3
"""Export an L2 classifier for Trentina: pinned download, ONNX, manifest (#350).

Runs in the Containerfile's model-builder stage, which has torch and optimum;
the runtime image has neither. Also the way to try a candidate model: run it
in that same builder image, mount the output directory into the gateway and
point ``CLASSIFIER_MODEL_PATH`` at it.

    python scripts/export_l2_model.py --repo ORG/NAME --revision SHA \\
        --out /models/NAME --id NAME --threshold 0.5 --malicious-labels INJECTION

The manifest (``trentina-model.json``) is what ``quarantine/classifier.py``
reads to know which outputs are malicious, at what threshold, and in what
window the model is scanned (#438); see ``resolve_model`` there. Name the
malicious outputs by label when the model's ``config.json`` labels them, by
index when it does not.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

TOKENIZER_FILES = ["tokenizer.json", "tokenizer_config.json", "special_tokens_map.json"]
"""What the runtime's tokenizer loads; a ``cls-linear`` export copies these."""

FILES = ["config.json", "model.safetensors", *TOKENIZER_FILES]
"""What a sequence-classification export needs. Named rather than globbed, so
a repo's training code, eval data and pickles are never downloaded."""

COMMIT_SHA_LENGTH = 40
"""A pin is a full commit SHA: a branch or tag can move under the image."""

ONNX_OPSET = 17
"""The ONNX opset of a ``cls-linear`` export, as checked against PIGuard (#353)."""

HEADS = ("auto", "cls-linear")
"""How the classifier head is built. ``auto`` is whatever the config's
architecture is, exported by optimum. ``cls-linear`` is a DeBERTa-v2 encoder
with one Linear on the first token and NO pooler: PIGuard's head, which its
repo builds in remote code we do not run. Its checkpoint still carries
``pooler.dense``, so exporting it as a stock DeBERTa loads cleanly and scores
wrong (#353)."""


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo", required=True)
    p.add_argument("--revision", required=True, help="A commit SHA, never a branch.")
    p.add_argument("--out", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--license", default="")
    p.add_argument("--threshold", type=float, required=True)
    p.add_argument("--head", choices=HEADS, default="auto")
    p.add_argument(
        "--window-tokens",
        type=int,
        help="Tokens one L2 pass reads (#438). Omitted, the runtime uses 512 "
        "or the model's max_position_embeddings, whichever is smaller.",
    )
    p.add_argument(
        "--guard-tokens",
        type=int,
        help="Content tokens neighbouring windows share. Omitted, the runtime uses 64.",
    )
    polarity = p.add_mutually_exclusive_group(required=True)
    polarity.add_argument("--malicious-labels", nargs="+")
    polarity.add_argument("--malicious-indices", nargs="+", type=int)
    args = p.parse_args()

    if len(args.revision) != COMMIT_SHA_LENGTH or any(
        c not in "0123456789abcdef" for c in args.revision
    ):
        p.error("--revision must be a full 40-character commit SHA")

    from huggingface_hub import snapshot_download  # builder-stage dependency

    with tempfile.TemporaryDirectory() as src:
        snapshot_download(args.repo, revision=args.revision, local_dir=src, allow_patterns=FILES)
        if not (Path(src) / "model.safetensors").is_file():
            print(f"{args.repo}@{args.revision} has no model.safetensors", file=sys.stderr)
            return 1
        if args.head == "cls-linear":
            _export_cls_linear(Path(src), Path(args.out))
        else:
            from optimum.exporters.onnx import main_export

            main_export(src, output=args.out, task="text-classification")

    manifest = {
        "id": args.id,
        "source": args.repo,
        "revision": args.revision,
        "license": args.license,
        "threshold": args.threshold,
    }
    if args.window_tokens is not None:
        manifest["window_tokens"] = args.window_tokens
    if args.guard_tokens is not None:
        manifest["guard_tokens"] = args.guard_tokens
    if args.malicious_labels:
        manifest["malicious_labels"] = args.malicious_labels
    else:
        manifest["malicious_indices"] = args.malicious_indices
    (Path(args.out) / "trentina-model.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"exported {args.repo}@{args.revision} to {args.out}")
    return 0


def _export_cls_linear(src: Path, out: Path) -> None:
    """Export a DeBERTa-v2 encoder + Linear(CLS) head, built here, not fetched.

    Every checkpoint tensor but the unused pooler must load, strictly: a
    renamed or missing tensor fails the export instead of leaving a layer at
    its random initialization. ``config.json`` is rewritten as plain
    ``deberta-v2`` so the runtime's ``AutoTokenizer`` never looks for the
    repo's remote config class; only its labels are read at runtime.
    """
    import torch
    from safetensors.torch import load_file
    from transformers import DebertaV2Config, DebertaV2Model

    raw = json.loads((src / "config.json").read_text())
    for key in ("auto_map", "architectures"):
        raw.pop(key, None)
    raw["model_type"] = "deberta-v2"
    config = DebertaV2Config(**raw)

    class ClsLinear(torch.nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.deberta = DebertaV2Model(config)
            self.classifier = torch.nn.Linear(config.hidden_size, config.num_labels)

        def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
            hidden = self.deberta(input_ids=input_ids, attention_mask=attention_mask)
            return self.classifier(hidden.last_hidden_state[:, 0, :])

    model = ClsLinear()
    model.train(False)  # inference mode: dropout off
    state = {
        k: v for k, v in load_file(src / "model.safetensors").items() if not k.startswith("pooler.")
    }
    model.load_state_dict(state, strict=True)

    out.mkdir(parents=True, exist_ok=True)
    ids = torch.ones((1, 16), dtype=torch.int64)
    torch.onnx.export(
        model,
        (ids, torch.ones_like(ids)),
        str(out / "model.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits": {0: "batch"},
        },
        opset_version=ONNX_OPSET,
        dynamo=False,
    )
    for name in TOKENIZER_FILES:
        if (src / name).is_file():
            shutil.copy(src / name, out / name)
    (out / "config.json").write_text(json.dumps(raw, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
