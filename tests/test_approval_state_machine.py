"""A state machine over the approval gate: staged actions and the approver (#859).

What it checks. ``pending`` holds at most one proposed action per ``Kind``; an
agent stages one, a person reads it on the approval page, and approving applies
it. ``approver`` decides who may approve (a configured password) and when a
first password may be set (an enrolment window). The approval route only reaches
``pending.approve`` after ``approver.verify`` is true, so this drives the two
together, the way the route does, through arbitrary interleavings of an agent
staging and re-staging, a person viewing / approving / declining, the clock
moving, the approver being configured and removed, and the enrolment window
opening and lapsing.

The properties, each asserted where it can be violated rather than at the end:

1. An approval applies only the proposal whose digest the person submitted, and
   that digest came from a page view the person actually read. The swap attack
   (read proposal A, the agent re-stages B of the same kind, the person submits
   A's digest) must never apply B. Re-staging IDENTICAL facts gives an identical
   digest, so a stale digest legitimately approves the new, equal proposal; the
   model is keyed on digest, not on "was it re-staged", so it says so honestly.
2. Nothing is applied while enrolment is open or no approver is configured.
3. An entry older than ``TTL_SECONDS`` is never applied.
4. A proposal applies at most once; a declined, expired or replaced one never
   applies later.
5. A model (kind to expected proposal) agrees with ``pending.outstanding()``
   after every step.

Why this and not the TLA+ model proposed in #859. One slot per ``Kind`` and
four transitions do not justify TLC and a Java toolchain in the pipeline, and a
model written in a second language is a second thing that drifts from the code.
This runs the real ``pending`` and ``approver`` modules under pytest.

Why derandomized. A property test that fails one run in fifty is a flaky
gate. ``derandomize=True`` with no example database makes every run explore the
same sequences, so a red build is reproducible and a green one means the same
thing tomorrow. The cost is that it never wanders into new sequences by itself:
raise ``max_examples`` locally when changing the gate.

Mechanics worth knowing. Both modules read the clock through ``import time``, so
this swaps the module attribute (never the global ``time``) for a fake the
machine drives. ``Staged.staged_at`` binds the REAL ``time.time`` at class
definition, so patching ``pending.time`` alone would leave staging stamps on
the wall clock while expiry reads the fake: ``pending.Staged`` is replaced by a
subclass whose stamp reads the fake too. Everything is restored in ``teardown``.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import tempfile
from dataclasses import dataclass, field
from typing import Any

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
)

from trentina import config as config_mod
from trentina import database as database_mod
from trentina.gateway import approver, pending
from trentina.gateway.pending import Kind

PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "incorrect horse battery staple"
HASH_ENV = "TRENTINA_APPROVAL_PASSWORD_HASH"

#: scrypt is deliberately slow; one verifier for the whole module, built once.
VERIFIER = approver.make_verifier(PASSWORD)

#: A few kinds and a few fact sets, so collisions, and re-stages with identical
#: facts (hence identical digests), happen within a short sequence.
KINDS = [Kind.OPERATOR_PROFILE, Kind.FEDERATION_TRUST, Kind.EGRESS_GRANT]
FACTS: list[dict[str, str]] = [
    {"peer": "alpha"},
    {"peer": "beta"},
    {"peer": "alpha", "scope": "read"},
]

WALL_START = 1_700_000_000.0
MONO_START = 5_000.0


class FakeTime:
    """The two clocks the gateway reads, driven by the machine."""

    def __init__(self) -> None:
        self.wall = WALL_START
        self.mono = MONO_START

    def time(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono


CLOCK = FakeTime()


@dataclass(frozen=True)
class _FakeClockStaged(pending.Staged):
    """``Staged`` stamped from the fake clock (see the module docstring)."""

    staged_at: float = field(default_factory=CLOCK.time)


@dataclass
class Proposal:
    """What the model expects to be staged: an identity, its facts, its stamp."""

    pid: int
    kind: Kind
    facts: dict[str, str]
    staged_at: float

    @property
    def digest(self) -> str:
        return pending.digest_of(self.facts)


class ApprovalMachine(RuleBasedStateMachine):
    """The real ``pending`` and ``approver`` under a model that is only a dict."""

    def __init__(self) -> None:
        super().__init__()
        self._saved_pending_time = vars(pending)["time"]
        self._saved_approver_time = vars(approver)["time"]
        self._saved_staged = pending.Staged
        self._saved_env = {
            k: os.environ.get(k) for k in (HASH_ENV, HASH_ENV + "_FILE", "QUARANTINE_DB")
        }
        self._tmp = tempfile.TemporaryDirectory()
        # A verifier or passkey store left on disk must not make configured() true.
        os.environ["QUARANTINE_DB"] = str(pathlib.Path(self._tmp.name) / "trentina.db")
        os.environ.pop(HASH_ENV, None)
        os.environ.pop(HASH_ENV + "_FILE", None)
        config_mod._config = None
        database_mod._db = None

        CLOCK.wall, CLOCK.mono = WALL_START, MONO_START
        vars(pending)["time"] = CLOCK
        vars(approver)["time"] = CLOCK
        vars(pending)["Staged"] = _FakeClockStaged
        pending.clear()
        approver.close_enrolment()

        self.model: dict[Kind, Proposal] = {}
        self.seen: dict[Kind, set[str]] = {k: set() for k in Kind}
        self.applied: list[int] = []
        self.next_pid = 0
        # Start with an approver configured: the interesting states are the ones
        # where approving can succeed, and a rule can still remove it.
        os.environ[HASH_ENV] = VERIFIER
        self.password_set = True
        self.last_open: float | None = None
        self.submitting: tuple[Kind, str] | None = None

    def teardown(self) -> None:
        pending.clear()
        approver.close_enrolment()
        vars(pending)["time"] = self._saved_pending_time
        vars(approver)["time"] = self._saved_approver_time
        vars(pending)["Staged"] = self._saved_staged
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        os.environ.pop(HASH_ENV + "_FILE", None)
        config_mod._config = None
        database_mod._db = None
        self._tmp.cleanup()

    # ---- helpers ---------------------------------------------------------

    def _sweep_model(self) -> None:
        """Drop expired entries, at the same points the real store sweeps."""
        for kind, proposal in list(self.model.items()):
            if CLOCK.wall - proposal.staged_at > pending.TTL_SECONDS:
                del self.model[kind]

    def _on_apply(self, proposal: Proposal) -> None:
        """Every safety property, checked at the instant something is applied."""
        assert approver.configured(), "applied with no approver configured"
        assert not approver.enrolling(), "applied while enrolment was open"
        assert CLOCK.wall - proposal.staged_at <= pending.TTL_SECONDS, "applied an expired entry"
        assert proposal.pid not in self.applied, "a proposal applied twice"
        assert self.submitting is not None
        kind, digest = self.submitting
        assert proposal.kind is kind
        assert proposal.digest == digest, "applied a proposal other than the one submitted"
        assert digest in self.seen[kind], "applied against a digest no page view showed"
        assert self.model.get(kind) is proposal, "applied a replaced, declined or expired proposal"
        self.applied.append(proposal.pid)

    def _view(self, kind: Kind) -> None:
        """The person reads the page: what they remember is what it showed."""
        self._sweep_model()
        shown = pending.outstanding()
        if kind in shown:
            self.seen[kind].add(pending.digest_of(shown[kind]))

    def _person_approves(self, kind: Kind, digest: str, password: str) -> None:
        """The approval route: password first, and only then ``approve``."""
        self._sweep_model()
        verified = approver.verify(password)
        assert verified == (self.password_set and password == PASSWORD)
        if not verified:
            return
        proposal = self.model.get(kind)
        should_apply = proposal is not None and proposal.digest == digest
        before = len(self.applied)
        self.submitting = (kind, digest)
        try:
            asyncio.run(pending.approve(kind, digest))
            applied = True
        except pending.PendingError:
            applied = False
        finally:
            self.submitting = None
        assert applied == should_apply, "approve disagreed with the model"
        assert len(self.applied) == before + (1 if should_apply else 0)
        if should_apply:
            del self.model[kind]

    # ---- the agent -------------------------------------------------------

    @rule(kind=st.sampled_from(KINDS), facts=st.sampled_from(FACTS), viewed=st.booleans())
    def stage(self, kind: Kind, facts: dict[str, str], viewed: bool) -> None:
        """Stage, and sometimes have a person read it straight away.

        ``viewed`` keeps "a person read it" common: Hypothesis enables only a
        subset of rules per example, so a stand-alone ``view`` is seldom
        scheduled between a stage and what follows.
        """
        proposal = Proposal(self.next_pid, kind, dict(facts), CLOCK.wall)
        self.next_pid += 1

        async def apply() -> dict[str, Any]:
            self._on_apply(proposal)
            return {"pid": proposal.pid}

        pending.stage(kind, facts, apply)
        self.model[kind] = proposal
        if viewed:
            self._view(kind)

    # ---- the person ------------------------------------------------------

    @rule(kind=st.sampled_from(KINDS))
    def view(self, kind: Kind) -> None:
        self._view(kind)

    @rule(data=st.data())
    def approve_remembered(self, data: st.DataObject) -> None:
        """Submit a digest from an earlier view, whatever is staged now."""
        remembered = [(k, d) for k in KINDS for d in sorted(self.seen[k])]
        if not remembered:
            return
        kind, digest = data.draw(st.sampled_from(remembered))
        self._person_approves(kind, digest, PASSWORD)

    def _expired_and_read(self) -> bool:
        return self.password_set and any(
            CLOCK.wall - p.staged_at > pending.TTL_SECONDS and p.digest in self.seen[p.kind]
            for p in self.model.values()
        )

    def _read_and_live(self) -> bool:
        return any(
            CLOCK.wall - p.staged_at <= pending.TTL_SECONDS and p.digest in self.seen[p.kind]
            for p in self.model.values()
        )

    @precondition(_read_and_live)
    @rule()
    def let_read_proposal_age_out(self) -> None:
        """Move past the TTL after a person read a proposal, sweeping nothing.

        Directed, like ``approve_after_expiry`` below: the order "read, expire,
        submit" is what a missing sweep needs and is rare by chance.
        """
        CLOCK.wall += pending.TTL_SECONDS + 1
        CLOCK.mono += pending.TTL_SECONDS + 1

    @precondition(_expired_and_read)
    @rule(data=st.data())
    def approve_after_expiry(self, data: st.DataObject) -> None:
        """Approve something the person read, that has since aged out unswept.

        A directed rule: reaching "read, then expired, with nothing having swept
        it in between" by chance is rare, and it is exactly where a missing
        sweep in ``approve`` would hide.
        """
        stale = [
            p
            for p in self.model.values()
            if CLOCK.wall - p.staged_at > pending.TTL_SECONDS and p.digest in self.seen[p.kind]
        ]
        proposal = data.draw(st.sampled_from(stale))
        self._person_approves(proposal.kind, proposal.digest, PASSWORD)

    @rule(kind=st.sampled_from(KINDS))
    def approve_current(self, kind: Kind) -> None:
        """Read the page, then approve exactly what it showed."""
        self._view(kind)
        if self.seen[kind]:
            shown = pending.outstanding()
            if kind in shown:
                self._person_approves(kind, pending.digest_of(shown[kind]), PASSWORD)

    @rule(kind=st.sampled_from(KINDS))
    def approve_fresh_wrong(self, kind: Kind) -> None:
        self._person_approves(kind, "0" * 64, PASSWORD)

    @rule(kind=st.sampled_from(KINDS))
    def approve_wrong_password(self, kind: Kind) -> None:
        self._view(kind)
        shown = pending.outstanding()
        if kind in shown:
            self._person_approves(kind, pending.digest_of(shown[kind]), WRONG_PASSWORD)

    @rule(kind=st.sampled_from(KINDS))
    def decline(self, kind: Kind) -> None:
        self._sweep_model()
        expected = kind in self.model
        assert pending.decline(kind) == expected
        self.model.pop(kind, None)

    # ---- time ------------------------------------------------------------

    @rule(seconds=st.sampled_from([1.0, 60.0, 300.0, 450.0, 899.0, 900.0, 901.0, 2000.0]))
    def advance_clock(self, seconds: float) -> None:
        CLOCK.wall += seconds
        CLOCK.mono += seconds

    @rule(seconds=st.sampled_from([901.0, 3601.0]))
    def advance_monotonic_past_window(self, seconds: float) -> None:
        CLOCK.mono += seconds

    # ---- the approver ----------------------------------------------------

    @rule()
    def configure_password(self) -> None:
        os.environ[HASH_ENV] = VERIFIER
        self.password_set = True

    @rule()
    def unconfigure_password(self) -> None:
        os.environ.pop(HASH_ENV, None)
        self.password_set = False

    @rule()
    def open_enrolment(self) -> None:
        approver.open_enrolment()
        self.last_open = CLOCK.mono
        if not self.password_set:
            assert approver.enrolling()

    @rule()
    def close_enrolment(self) -> None:
        approver.close_enrolment()
        self.last_open = None
        assert not approver.enrolling()

    # ---- invariants ------------------------------------------------------

    @invariant()
    def model_agrees_with_outstanding(self) -> None:
        """The store and the model hold the same proposals.

        ``outstanding()`` sweeps as a side effect, and an invariant that swept
        after every step would hide a missing sweep in ``approve`` (the entry
        would never be old when ``approve`` saw it). So while anything is
        expired the check reads the store without sweeping it; otherwise it
        goes through the public ``outstanding()``.
        """
        if any(CLOCK.wall - p.staged_at > pending.TTL_SECONDS for p in self.model.values()):
            assert set(pending._staged) == set(self.model)
            for kind, proposal in self.model.items():
                assert pending._staged[kind].facts == proposal.facts
                assert pending._staged[kind].staged_at == proposal.staged_at
            return
        shown = pending.outstanding()
        assert shown == {k: p.facts for k, p in self.model.items()}

    @invariant()
    def enrolment_only_without_an_approver(self) -> None:
        if approver.enrolling():
            assert not approver.configured()
            assert self.last_open is not None
            assert CLOCK.mono - self.last_open <= approver.DEFAULT_ENROL_WINDOW_SECONDS


TestApprovalStateMachine = ApprovalMachine.TestCase
TestApprovalStateMachine.settings = settings(
    derandomize=True,
    database=None,
    max_examples=50,
    stateful_step_count=30,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
