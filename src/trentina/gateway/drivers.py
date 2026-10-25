"""The one registry: a configured name becomes a transform.

There is one driver role — the transform; guards are fixed trust machinery,
not a pluggable driver role. Everything a profile can name in `processors:`
resolves here, and nowhere else answers the question "the profile asked for X
on the Y channel; give me it, or fail the load".

There were two registries until #167, one per role, each with its own parity
test and only one of them with a channel lock. That was the cost of the split:
the lock was written once, in the half nobody copied it out of, so a
transform could be named on any channel and nothing checked. Different
input shapes do not need different wiring.

**Channel locking.** A processor declares the ingresses it understands and
selecting one elsewhere is a ``ProfileConfigError`` at config load, not a
runtime surprise. ``loader._check_drivers`` builds every driver a profile
names at startup, which is what makes "at load" true rather than "on the first
request that happens to use it". The Matrix case is the loud one — a Matrix
processor pointed at alert-ingress JSON would find no Matrix event shape, fall
through to generic rules, and produce a perimeter nobody had checked against
that payload. The text case is quiet and just as wrong: a reducer tuned for
one shape, pointed at another, declines forever and looks like it is working.

**Kind locking.** A channel hands its processors either a string or a parsed
document, never both. Refusing the mismatch here turns what would be an
AttributeError deep inside a request into a refused config.

**Parity.** The table is declared twice — once here, once as a ``Literal`` in
``profile.py`` that makes pydantic reject an unknown name at YAML load. A
single parity test (``tests/test_gateway_drivers.py``) keeps them in step. A
driver registered but not in the Literal is dead on arrival: wired in, passing
its own tests, and nameable by no profile.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..channels import Channel, Kind
from ..transforms import (
    DetectProcessor,
    EmailProcessor,
    HtmlProcessor,
    MatrixProcessor,
    PetitProcessor,
    SelectProcessor,
    StructuredProcessor,
    SummarizeProcessor,
)
from .errors import ProfileConfigError

if TYPE_CHECKING:
    from collections.abc import Callable

    from .profile import ProcessorChainConfig

Driver = "Transform | DocumentProcessor"

# Text processors are stateless by contract, so one instance each for the
# process. Document processors may own per-profile state (the Matrix one owns
# a key cache), so they are built per call. Factories throughout rather than a
# mix, so the table reads one way.
_DETECT = DetectProcessor()
_PETIT = PetitProcessor()
_STRUCTURED = StructuredProcessor()
_EMAIL = EmailProcessor()
_HTML = HtmlProcessor()
_SUMMARIZE = SummarizeProcessor()


def _make_matrix(cfg: ProcessorChainConfig, keys: Any) -> MatrixProcessor:
    """Decryption on top of selection: decrypted text goes through the same
    rules as anything else, so it gets its own SelectProcessor rather than a
    shortcut."""
    return MatrixProcessor(
        select=SelectProcessor(skip_sample_bytes=cfg.skip_sample_bytes),
        keys=keys,
    )


TRANSFORMS: dict[str, Callable[[ProcessorChainConfig, Any], Any]] = {
    "detect": lambda _cfg, _keys: _DETECT,
    "petit": lambda _cfg, _keys: _PETIT,
    "structured": lambda _cfg, _keys: _STRUCTURED,
    "email": lambda _cfg, _keys: _EMAIL,
    "html": lambda _cfg, _keys: _HTML,
    "summarize": lambda _cfg, _keys: _SUMMARIZE,
    "select": lambda cfg, _keys: SelectProcessor(skip_sample_bytes=cfg.skip_sample_bytes),
    "matrix": _make_matrix,
}

# What each channel hands a processor. A channel that fed both would need a
# processor to introspect its own input, which is how you get a driver that
# guesses.
CHANNEL_KIND: dict[Channel, Kind] = {
    Channel.TOOL: Kind.TEXT,
    Channel.TOOL_DESCRIPTION: Kind.TEXT,
    Channel.ALERT: Kind.TEXT,
    Channel.MATRIX: Kind.DOCUMENT,
    Channel.MATRIX_BRIDGE: Kind.TEXT,
}


def build_transforms(
    cfg: ProcessorChainConfig,
    *,
    channel: Channel,
    profile_name: str = "",
    keys: Any = None,
) -> list[Any]:
    """Resolve the configured processors, in order, or fail closed.

    An empty list is the no-op and is meaningful: on a text channel it
    delivers the payload unchanged, and on a document channel it reads
    everything. That is why there is no ``full`` processor any more — "read
    everything" is what naming nothing already means.

    An unknown name is a load error rather than a silent skip. Dropping it
    quietly is how a typo becomes a profile that looks reduced and is not, and
    the same typo in ``tools_allow`` would be caught.
    """
    want = CHANNEL_KIND[channel]
    out: list[Any] = []
    for name in cfg.processors:
        factory = TRANSFORMS.get(name)
        if factory is None:  # pragma: no cover - the Literal blocks this
            raise ProfileConfigError(
                f"Profile {profile_name!r}: unknown transform {name!r}; known: {sorted(TRANSFORMS)}"
            )
        processor = factory(cfg, keys)
        if channel not in processor.channels:
            raise ProfileConfigError(
                f"Profile {profile_name!r}: transform {processor.name!r} is "
                f"not valid on the {channel.value} channel "
                f"(valid: {sorted(c.value for c in processor.channels)})"
            )
        if processor.kind is not want:
            raise ProfileConfigError(
                f"Profile {profile_name!r}: transform {processor.name!r} "
                f"consumes {processor.kind.value}, but the {channel.value} "
                f"channel supplies {want.value}"
            )
        out.append(processor)

    if want is Kind.DOCUMENT and len(out) > 1:
        # Chaining is defined for str -> str. A document processor returns
        # selected strings, which is not something the next one can consume,
        # so a two-element chain would silently run only the first.
        raise ProfileConfigError(
            f"Profile {profile_name!r}: the {channel.value} channel takes at "
            f"most one transform, got {[p.name for p in out]}"
        )
    return out
