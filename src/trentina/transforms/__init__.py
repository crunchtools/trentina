"""Transforms: payload transformation outside the security perimeter.

One role, one bucket. See ``base.py`` for the invariants; the short version is
that this package may subtract but never absolve — it drops, collapses,
decodes, normalizes and restructures, and everything it emits is exactly as
untrusted as what went in and crosses the guards on the way.

Two input shapes, not two roles. Most processors are ``str -> str``
(``Transform``). ``select`` and ``matrix`` take parsed JSON and return the
strings worth reading out of it (``DocumentProcessor``), because
``m.room.encrypted`` is a structure rather than a substring. They were a
separate framework until #167, on a ruling that did not hold.
"""

from ..channels import Channel
from .base import Cost, Transform, TransformContext, TransformResult
from .compose import Strategy, TransformOutcome, run_transforms
from .detect import DetectProcessor
from .email import EmailProcessor
from .html import HtmlProcessor
from .matrix import MatrixProcessor
from .petit import PetitProcessor
from .select import DEFAULT_SKIP_SAMPLE_BYTES, SelectProcessor
from .structured import StructuredProcessor
from .summarize import SummarizeProcessor
from .view import (
    DocumentProcessor,
    Selection,
    SelectionContext,
    SkipReason,
    UndecryptableEvent,
)

__all__ = [
    "DEFAULT_SKIP_SAMPLE_BYTES",
    "Channel",
    "Cost",
    "DetectProcessor",
    "DocumentProcessor",
    "EmailProcessor",
    "HtmlProcessor",
    "MatrixProcessor",
    "PetitProcessor",
    "SelectProcessor",
    "Selection",
    "SelectionContext",
    "SkipReason",
    "Strategy",
    "StructuredProcessor",
    "SummarizeProcessor",
    "Transform",
    "TransformContext",
    "TransformOutcome",
    "TransformResult",
    "UndecryptableEvent",
    "run_transforms",
]
