"""The L2 exporter's tokenizer hand-off (scripts/export_l2_model.py, a911)."""

from __future__ import annotations

from pathlib import Path

from scripts import export_l2_model


def test_an_export_carries_the_sources_tokenizer_and_nothing_stale(tmp_path: Path) -> None:
    """optimum-onnx's transformers 4 cannot read a tokenizer transformers 5 saved, so
    whatever it left is replaced by the trainer's own files, and a file the source
    does not have is not kept."""
    src, out = tmp_path / "src", tmp_path / "out"
    src.mkdir()
    out.mkdir()
    (src / "tokenizer.json").write_text('{"model": "trained"}')
    (src / "tokenizer_config.json").write_text('{"tokenizer_class": "TokenizersBackend"}')
    (out / "tokenizer_config.json").write_text('{"tokenizer_class": "re-saved"}')
    (out / "special_tokens_map.json").write_text("{}")
    (out / "model.onnx").write_bytes(b"onnx")

    export_l2_model._carry_tokenizer(src, out)

    assert (out / "tokenizer.json").read_text() == '{"model": "trained"}'
    assert (out / "tokenizer_config.json").read_text() == (
        src / "tokenizer_config.json"
    ).read_text()
    assert not (out / "special_tokens_map.json").exists()
    assert (out / "model.onnx").read_bytes() == b"onnx", "only tokenizer files are touched"
