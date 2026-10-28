"""Runtime construction tokens for the four unforgeable trust types.

``tests/test_seal.py`` is the STATIC half of the seal: an AST rule that fails if
any in-repo code constructs a sealed type outside the one factory that checks
it. That binds every caller there is until out-of-tree plugins land — and then
it stops binding, because an installed plugin's source is not in this repository
and the loader's conformance scan, not this test, is what reads it.

This module is the RUNTIME half (Trentina 3.0 plan §B.1). Each sealed type
carries a ``Seal`` token as an ``InitVar`` — an init-only pseudo-field, never
stored — and refuses construction unless the token it is handed is its factory's
own. The factory holds that token as a module-private name nothing exports, so
to forge the type an author must import a name the import boundary already
forbids (``tests/test_plugin_api.py``) — the forgery is VISIBLE, not silent, and
an ``AttributeError``/``TypeError`` at construction is the floor beneath the
scan. The hot path pays one ``is`` comparison per construction and inspects no
frames.

Why ``InitVar`` and not the §B.1 decorator: a decorator that injects a keyword
argument into ``__init__`` is invisible to the type checker, so every factory
call would need a ``# type: ignore`` — which the slop detector (rightly) refuses.
An ``InitVar`` is a real parameter mypy knows about, so the factories stay clean.
"""

from __future__ import annotations


class Seal:
    """A construction token owned by one factory.

    A sealed type admits only its factory's ``Seal``, so holding a value of the
    type is proof that factory — and therefore its check — built it. ``owner`` is
    the factory's name, used only to word the refusal; identity, not the name, is
    what is compared.
    """

    __slots__ = ("owner",)

    def __init__(self, owner: str) -> None:
        self.owner = owner


UNSEALED = Seal("<unsealed>")
"""The token a sealed type carries when no factory supplied one. Direct
construction gets this default and is refused, so a missing token fails exactly
like a wrong one."""


def require(seal: Seal, expected: Seal, type_name: str) -> None:
    """Refuse unless ``seal`` is ``expected`` — the check every sealed type's
    ``__post_init__`` runs. Raises ``TypeError`` naming the only factory that may
    build ``type_name``."""
    if seal is not expected:
        raise TypeError(f"{type_name} is constructed only by {expected.owner}")
