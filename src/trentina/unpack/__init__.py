"""The unpack stage: what the layers read, built from what will be delivered (#365).

The transforms, which run first, decide what the agent receives. This
stage decides what L1, L2 and L3 read: the same text with every packed part
unpacked. Base64 and hex that decode to text are decoded, binary is labelled
by its signature, and later archives, PDFs and images are extracted. It
never changes the delivery, so nothing has to be put back afterwards.

The rule it serves: nothing is delivered that the layers did not read, in
its original or decoded form, or, for binary, by its identified type.

``scan.unpack`` is the entry point. ``UnpackStats`` lives apart from it so
``l1/pipeline.py`` can carry the counts without importing the scanner.
"""

from .stats import UnpackStats

__all__ = ["UnpackStats"]
