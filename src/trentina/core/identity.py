"""Who is asking — the one place a ``Posture`` is built.

A ``Posture`` (``core.dispose``) carries what the disposition depends on: the
mode, the policy its refusals offer, whether the source is allowlisted, whether
the caller is a honeypot, and the redact prompt. It is one of Trentina 3.0's
unforgeable trust types, so it is constructed in exactly ONE function — this
``posture()`` — and ``tests/test_seal.py`` fences every other construction.
Holding a ``Posture`` is then proof it was built from the bound request identity,
not assembled ad hoc at a call site where a field could drift.

``honeypot`` is not a caller's to assert: it is a property of the profile the
gateway bound (#357), so it is resolved HERE from the ambient request scope — the
one place every ingress agrees on it — rather than passed in by each site.
``allowlisted`` stays a per-call argument: the tool, not the identity, vouches
for a particular source (a fetched URL, a read path). ``policy`` is resolved by
the caller (an omitted per-call policy becomes ``ModePolicy((mode,), mode)`` at
the site), so a refusal's ``alternatives`` list stays exactly what that site
intends.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .dispose import _POSTURE_SEAL, Posture

if TYPE_CHECKING:
    from ..modes import Mode, ModePolicy


def posture(
    mode: Mode,
    policy: ModePolicy,
    *,
    allowlisted: bool = False,
    prompt: str | None = None,
) -> Posture:
    """Build the ``Posture`` for one judgement under the bound request identity.

    The sole constructor of the type. ``honeypot`` is read from the ambient
    scope (the same source ``tools.judged.honeypot_caller`` uses), so a honeypot
    profile is judged as one wherever it calls, and no caller can claim or
    disclaim the flag.
    """
    # Lazy: core resolves the gateway scope at call time, as ``modes.current_policy``
    # does, so ``core`` keeps no import-time dependency on ``gateway``.
    from ..gateway.scope import current_scope

    scope = current_scope()
    honeypot = scope is not None and scope.profile is not None and scope.profile.honeypot
    return Posture(
        mode=mode,
        policy=policy,
        allowlisted=allowlisted,
        honeypot=honeypot,
        prompt=prompt,
        _seal=_POSTURE_SEAL,
    )
