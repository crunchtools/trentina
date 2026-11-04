"""Every native extension loads in the distroless runtime.

The runtime stage copies only site-packages plus libstdc++, so an extension
that needs a shared object from anywhere else fails here and nowhere else --
which is how onnxruntime broke once already. Runs inside the built image
(python-sdlc `pytest-in-image`); ignored outside it.
"""

from __future__ import annotations

import importlib

import pytest

NATIVE = ["onnxruntime", "vodozemac", "cv2", "PIL", "pypdf", "rapidocr", "shapely", "pyclipper"]


@pytest.mark.parametrize("module", NATIVE)
def test_native_extension_loads(module: str) -> None:
    loaded = importlib.import_module(module)
    assert loaded.__spec__ is not None and loaded.__spec__.origin, f"{module} has no origin"
