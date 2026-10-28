"""The transform contract is a versioned ABC, and the in-tree transforms obey it.

``Transform`` is the public plugin surface (Trentina 3.0 plan §B.5): an author
subclasses it, overrides ``run``, and inherits defaults. Two promises are held
here so a later change cannot break them quietly:

* ``run``'s signature is FROZEN. The compat anchor (``api_version``) is worth
  nothing if ``run`` can be re-shaped within a major; a plugin written against
  version 1 must keep running. Adding a new method WITH a default is allowed —
  changing ``run`` is not.
* The in-tree transforms subclass the SAME contract. Dogfooding: core code gets
  no privileged hook the ecosystem does not (plan §C.1). If our own transforms
  drifted off the base, the contract would be a lie.
"""

from __future__ import annotations

import inspect

import pytest

from trentina.channels import Channel, Kind
from trentina.transforms.base import Cost, Declined, Transform, TransformContext, TransformResult
from trentina.transforms.detect import DetectProcessor
from trentina.transforms.email import EmailProcessor
from trentina.transforms.html import HtmlProcessor
from trentina.transforms.pdf import PdfProcessor
from trentina.transforms.petit import PetitProcessor
from trentina.transforms.structured import StructuredProcessor
from trentina.transforms.summarize import SummarizeProcessor

# Every in-tree TEXT transform. The document processors (select, matrix) are a
# different contract (``view.DocumentProcessor``, ``Kind.DOCUMENT``) and retire
# with ``Kind.DOCUMENT`` in a later phase, so they are not held to this base.
TEXT_TRANSFORMS = [
    DetectProcessor,
    EmailProcessor,
    HtmlProcessor,
    PdfProcessor,
    PetitProcessor,
    StructuredProcessor,
    SummarizeProcessor,
]


@pytest.mark.parametrize("cls", TEXT_TRANSFORMS, ids=lambda c: c.__name__)
def test_in_tree_transform_subclasses_the_contract(cls: type) -> None:
    """Each in-tree text transform IS a ``Transform`` and declares version 1."""
    assert issubclass(cls, Transform)
    instance = cls()
    assert isinstance(instance, Transform)
    assert instance.api_version == 1
    assert isinstance(instance.name, str) and instance.name
    assert isinstance(instance.cost, Cost)
    assert instance.kind is Kind.TEXT
    assert Channel.TOOL in instance.channels


def test_transform_is_abstract() -> None:
    """``Transform`` cannot be instantiated bare, and a subclass that does not
    override ``run`` cannot either — the one method is the whole obligation.

    The candidates are held as plain ``type`` so the runtime check needs no
    mypy suppression for instantiating an abstract class."""

    class NoRun(Transform):
        name = "no-run"

    candidates: tuple[type, ...] = (Transform, NoRun)
    for cls in candidates:
        with pytest.raises(TypeError):
            cls()


def test_run_signature_is_frozen() -> None:
    """``run`` is the compat anchor: (self, payload, ctx, /) -> TransformResult,
    both arguments positional-only so an author may name them anything and an
    override is never rejected on a parameter-name mismatch. A change here is a
    deliberate break of the v1 promise, not a refactor."""
    sig = inspect.signature(Transform.run)
    params = list(sig.parameters.values())
    assert [p.name for p in params] == ["self", "payload", "ctx"]
    assert params[1].kind is inspect.Parameter.POSITIONAL_ONLY
    assert params[2].kind is inspect.Parameter.POSITIONAL_ONLY
    # Annotations are strings under ``from __future__ import annotations``.
    assert params[1].annotation == "str"
    assert params[2].annotation == "TransformContext"
    assert sig.return_annotation == "TransformResult"


def test_contract_defaults() -> None:
    """A subclass that sets only ``name`` and ``run`` inherits the defaults —
    the point of an ABC over a Protocol."""

    class Minimal(Transform):
        name = "minimal"

        async def run(self, payload: str, ctx: TransformContext, /) -> TransformResult:
            return Declined("minimal")

    m = Minimal()
    assert m.cost is Cost.FREE
    assert m.kind is Kind.TEXT
    assert m.channels == frozenset({Channel.TOOL})
    assert m.api_version == 1
