"""Where a driver is allowed to run.

There is one driver role — the transform. Guards are fixed trust machinery,
not a pluggable driver role. This module names the thing a transform and a
guard share: the ingress each one understands.

* **Guards** decide admission to the trust perimeter. Parameter guards,
  response guards, and L1/L2/L3. Guards decide; nothing else does. A guard
  also decides what it READS, which is a guard's read policy and not a
  separate concept — ``transforms/view.py`` carries it.
* **Transforms** are everything before that. They run outside the
  perimeter, their output is exactly as untrusted as their input, and
  everything they emit crosses the guards on the way in. See
  ``transforms/base.py``.

A transform declares the channels it understands, and selecting
one on a channel it does not declare is a load-time error rather than a
runtime surprise. That matters because the failure is otherwise silent: a
Matrix extractor pointed at alert-ingress JSON would find no Matrix event
shape, fall through to generic rules, and produce a perimeter nobody had
checked against that payload. The same argument applies to a transform —
a reducer tuned for one payload shape, pointed at another, quietly declines
forever and looks like it is working.

The enum lives here, above ``transforms/`` and ``l1/``, so that neither
package has to import the other and neither has to import the gateway that
wires them. ``gateway/drivers.py`` is the single place the
locking is enforced.
"""

from __future__ import annotations

from enum import Enum


class Channel(str, Enum):
    """An ingress a driver can be bound to."""

    MATRIX = "matrix"
    ALERT = "alert"
    TOOL = "tool"
    # What a backend says about its own tools, on the tools/list path (#176).
    TOOL_DESCRIPTION = "tool_description"
    # One inbound message's plaintext, handed over by a Matrix bridge (#162).
    # TEXT: the bridge already did the decrypting, so what is scanned is what
    # is delivered. No processor declares it yet; an empty chain is the only
    # valid config until one earns its place on chat-sized payloads.
    MATRIX_BRIDGE = "matrix_bridge"


class Kind(str, Enum):
    """What a transform consumes.

    Not a second role — both kinds are transforms, with the same contract
    and the same registry. They differ only in what they are handed.

    TEXT is ``str -> str``: the processor owns the bytes, and what it returns
    is both scanned and delivered. DOCUMENT is parsed JSON in, selected
    strings out, because ``m.room.encrypted`` is a structure rather than a
    substring and there is nothing useful to do with its serialization. A
    DOCUMENT processor does not decide what reaches the wire; its call site
    does.

    Declared so the registry can refuse a DOCUMENT processor where the caller
    will hand it a string, which would otherwise be an AttributeError deep in
    a request rather than a refused config.

    Expected to be temporary. Once #162 lands and the Matrix bridge delivers
    plaintext, ``matrix`` reads exactly what it delivers — which is TEXT — and
    DOCUMENT may have no implementations left.
    """

    TEXT = "text"
    DOCUMENT = "document"
