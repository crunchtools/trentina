"""Read the text drawn in images, as JSON, in a child process (#370).

Run by ``ocr.read_images`` and by nothing else:

    python -m trentina.unpack.ocr_worker < request.json

The request is ``{"images": [<base64>, ...], "seconds": <budget>}``; the
answer has one entry per image, ``{"text": [...], "faint": [...]}``, or null
for an image that could not be read or that the budget ran out before.
Like the PDF worker, this is a process so that it can be stopped: it
decodes hostile images with three native libraries and then holds most of
a gigabyte while the models run. It limits its own CPU and address space,
starts with no credential, and is killed at a deadline.

Each image is read twice. Once as it is, and once with its contrast
stretched, which turns near-white text on white into black on white. The
second pass recognizes only the boxes the first did not read. A line either
pass finds in a box with almost no contrast in the picture as it arrived is
``faint``: text a person looking at it would not see. Transparency is laid over
mid-grey first, so text drawn in white or in black on a clear background
shows either way.

This is an OCR-level guarantee, and it is stated as one (Known gaps):
print and screen text in the scripts the bundled PP-OCR models read.
Handwriting, stylised lettering, text rotated well off the horizontal and
an image built to fool a model are outside it.
"""

from __future__ import annotations

import base64
import io
import json
import os
import resource
import sys
import time
import warnings
from typing import Any

CPU_SECONDS = 240
"""CPU time, summed over threads. The three models each keep a small pool of
threads that spin while they wait, so a minute of wall clock is several
minutes of CPU. The wall-clock kill is the limit that bites first."""

MEMORY_BYTES = 6 * 1024 * 1024 * 1024
"""Address space, not resident memory: onnxruntime and OpenCV map far more
than they touch. Resident use measured about 0.8 GB."""

THREADS = 2
"""Threads for EVERY native pool, not only onnxruntime's. OpenMP and OpenBLAS
size their own pools from the machine's core count and reserve address space
per thread, so on a 24-core CI runner the worker hit ``RLIMIT_AS`` with
std::bad_alloc before it read one image, while on 16 cores it fit."""

NATIVE_POOLS = ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
"""Read once, when numpy and onnxruntime load, so set before those imports."""
MAX_PIXELS = 40_000_000
"""Pixels an image may declare. Larger is refused before it is decoded."""

MAX_SIDE = 2000
"""An image is scaled down to this on its longer side before it is read."""

MAX_FRAMES = 4
"""Frames of an animation or pages of a TIFF read. More, and the image is
unread: a frame nobody OCRed is a frame nobody judged."""

FORMATS = frozenset({"PNG", "JPEG", "GIF", "WEBP", "BMP", "TIFF", "ICO", "MPO"})
FAINT_CONTRAST = 20.0
"""Grey levels, of 255, between a text box's light and dark below which a
person does not see the text. Measured: text five levels off its background
is found only by the stretched pass; fifteen levels off is read by both."""

DETECT_SIDE = 1600
"""The longer side text detection works at. Smaller images are not enlarged."""

FAINT_SIDE = 1200
"""The longer side of the copy the second pass detects on. Detection took
4.1 s at 1800 pixels and 1.4 s at 1200 on the same page, finding the same
forty lines."""

MAX_FAINT_BOXES = 200
"""Boxes the second pass will consider in one frame."""

SPREAD = (0.5, 99.5)
"""Percentiles a box's light and dark are read at. Wide, because the ink of a
slanted line is a few percent of its upright box; not the extremes, which
one stray pixel sets."""

MARGIN = 4
"""Pixels added around a detected box before it is cut out or measured."""

OPAQUE = 255
BACKDROP = (128, 128, 128)
"""What transparency is laid over: neither white text nor black disappears on it."""


def _stretched(frame: Any) -> Any:
    """The frame with each colour channel's histogram equalized."""
    import cv2

    return cv2.merge([cv2.equalizeHist(channel) for channel in cv2.split(frame)])


Rect = tuple[int, int, int, int]


def _rect(box: Any, scale: float, shape: tuple[int, ...]) -> Rect:
    """A detected quadrilateral as ``(left, top, right, bottom)`` in the frame,
    a little wider than detected so no stroke is cut."""
    xs = [point[0] / scale for point in box]
    ys = [point[1] / scale for point in box]
    return (
        max(int(min(xs)) - MARGIN, 0),
        max(int(min(ys)) - MARGIN, 0),
        min(int(max(xs)) + MARGIN, shape[1]),
        min(int(max(ys)) + MARGIN, shape[0]),
    )


def _mostly_inside(rect: Rect, others: list[Rect]) -> bool:
    """Whether at least half of ``rect`` lies inside one of ``others``."""
    area = max((rect[2] - rect[0]) * (rect[3] - rect[1]), 1)
    for other in others:
        width = min(rect[2], other[2]) - max(rect[0], other[0])
        height = min(rect[3], other[3]) - max(rect[1], other[1])
        if width > 0 and height > 0 and 2 * width * height >= area:
            return True
    return False


def _contrast(frame: Any, rect: Rect) -> float:
    """How far apart the light and dark of a text box are, in the frame as it
    arrived: the widest spread of any colour channel, 0 to 255."""
    import numpy as np

    crop = frame[rect[1] : rect[3], rect[0] : rect[2]]
    if crop.size == 0:
        return 0.0
    low, high = np.percentile(crop.reshape(-1, crop.shape[-1]), SPREAD, axis=0)
    return float((high - low).max())


def _first_pass(engine: Any, frame: Any) -> list[tuple[str, Rect]]:
    """Every line the engine reads in the frame as it arrived, with its box."""
    # Every call names all three stages: the engine remembers the last choice.
    found = engine(frame, use_det=True, use_cls=True, use_rec=True)
    texts = getattr(found, "txts", None) or ()
    boxes = getattr(found, "boxes", None)
    if boxes is None or len(boxes) != len(texts):
        return []
    return [
        (str(text), _rect(box, 1.0, frame.shape))
        for text, box in zip(texts, boxes, strict=True)
        if text
    ]


def _second_pass(engine: Any, frame: Any, taken: list[Rect]) -> list[tuple[str, Rect]]:
    """Lines found only once the contrast is stretched.

    Detection runs on a smaller copy, because detection is most of the cost
    and faint text is no smaller than the rest. Only boxes the first pass did
    not already read are recognized, from the full-size stretched frame: the
    stretch amplifies JPEG ringing, and text the first pass read well comes
    out of it worse.
    """
    import cv2

    stretched = _stretched(frame)
    scale = min(1.0, FAINT_SIDE / max(frame.shape[:2]))
    small = cv2.resize(stretched, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    found = engine(small, use_det=True, use_cls=False, use_rec=False)
    boxes = getattr(found, "boxes", None)
    lines: list[tuple[str, Rect]] = []
    for box in [] if boxes is None else boxes[:MAX_FAINT_BOXES]:
        rect = _rect(box, scale, frame.shape)
        if _mostly_inside(rect, taken):
            continue
        crop = stretched[rect[1] : rect[3], rect[0] : rect[2]]
        recognized = engine(crop, use_det=False, use_cls=False, use_rec=True)
        read = getattr(recognized, "txts", None) or ()
        lines.extend((str(text), rect) for text in read if text)
    return lines


def _read(engine: Any, packed: bytes) -> dict[str, list[str]] | None:
    """One image: what it says, and what it says too faintly to see.

    None for a format this does not open or an animation of more than
    ``MAX_FRAMES`` frames. Each frame is laid over ``BACKDROP`` first and
    scaled down to ``MAX_SIDE``.
    """
    import numpy as np
    from PIL import Image, ImageSequence

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    image = Image.open(io.BytesIO(packed))
    if image.format not in FORMATS or getattr(image, "n_frames", 1) > MAX_FRAMES:
        return None
    text: list[str] = []
    faint: list[str] = []
    for still in ImageSequence.Iterator(image):
        rgba = still.convert("RGBA")
        flat = Image.new("RGBA", rgba.size, (*BACKDROP, OPAQUE))
        flat.alpha_composite(rgba)
        rgb = flat.convert("RGB")
        rgb.thumbnail((MAX_SIDE, MAX_SIDE))
        frame = np.asarray(rgb)
        first = _first_pass(engine, frame)
        second = _second_pass(engine, frame, [rect for _, rect in first])
        for line, rect in (*first, *second):
            (faint if _contrast(frame, rect) < FAINT_CONTRAST else text).append(line)
    return {"text": text, "faint": faint}


def main() -> int:
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    os.environ.update(dict.fromkeys(NATIVE_POOLS, str(THREADS)))
    warnings.simplefilter("error")  # a decompression-bomb warning refuses the image
    request = json.load(sys.stdin)
    import cv2
    from rapidocr import RapidOCR

    cv2.setNumThreads(THREADS)

    engine = RapidOCR(
        params={
            "Global.log_level": "critical",
            "EngineConfig.onnxruntime.intra_op_num_threads": THREADS,
            "EngineConfig.onnxruntime.inter_op_num_threads": 1,
            # Cap the longer side; never enlarge. The default enlarges a small
            # image until its shorter side is 736, which cost a 900 by 300
            # banner 2.0 s where this costs 0.6 s, for the same two lines.
            "Det.limit_type": "max",
            "Det.limit_side_len": DETECT_SIDE,
        }
    )
    stop_at = time.monotonic() + float(request["seconds"])
    answers: list[dict[str, list[str]] | None] = []
    for encoded in request["images"]:
        if time.monotonic() > stop_at:
            answers.append(None)  # out of time: unread, and said so
            continue
        try:
            answers.append(_read(engine, base64.b64decode(encoded, validate=True)))
        except (OSError, ValueError, Warning, ArithmeticError, MemoryError):
            answers.append(None)  # this image is unread; the others are still read
    json.dump({"images": answers}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
