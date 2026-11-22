# Specification: Session Labels in Place of the Flag Bit

> **Spec ID:** 026-session-labels
> **Status:** Implemented
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-11-22
> **Ticket:** #861 (lineage #456, #457, #860)

## Overview

A session's mark was one timestamp: "was delivered flagged content"
(`session_marks.mark_flagged`), shared since #860 by decoy trips and refused
credentials. A clean read of a credential followed by a guarded `send_email`
was caught only if the judge noticed, because nothing deterministic remembered
that the session saw one. `credential_shapes.kinds` ran on outbound requests
and on no response.

**Done is:** a session carries a small closed set of labels, each set by
gateway code and never by a judge, and a semantic request or response guard
can refuse on any of them before the judge is asked.

## Decision

Ruled in the #861 triage (a916), scoped here:

- **Labels, not a score.** A closed `SessionLabel` enum, each label with its
  own last-set time. Adding one is a code change and a CHANGELOG line.
- **Deterministic setters only.** The judge's verdict never sets a label;
  that would let content steer its own taint.
- **`refuse_when_flagged` stays.** It is shorthand for
  `refuse_when: [flagged_delivery, tripped]`, not deprecated. Both keys may be
  set; the labels are joined.
- **No profile-wide fact for sessionless routes.** `/proxy/http` keeps its
  labels unknown (`gatekeeper.judge_egress`). An "any session of this profile
  marked recently" fact lets one session's read refuse another session's
  call: a trust-model change that needs its own ruling.
- **Deferred:** `private_source` (needs a backend `sensitivity` field) and
  `credentialed` (OAuth-brokered backends). Both are backend facts known at
  delivery time and fit the same enum when someone needs them.

## Behaviour

1. `SessionLabel` is `flagged_delivery` (delivered flagged or partly judged
   content, the old mark), `tripped` and `credential_seen`.
2. `tripped` is set by `decoy.mark_session`: a decoy trip, a planted
   credential, or a refused real credential in a call's arguments (#860).
   `request_edge.mark_refused_credentials` is also called where a call is
   refused before its arguments are checked (a refused mode, a held tool,
   non-object arguments), so a credential sent alongside one of those labels
   the session too.
3. `credential_seen` is set when a delivered response (outcome `OK` or
   `TOOL_ERROR`, the same gate as `_mark_session`) holds any
   `credential_shapes.kinds` match over the text the agent receives. A refused
   response delivers no content and sets nothing. The kinds are logged once
   per session with the `call_ref`, never the matched text. `_mark_session` is
   async and runs the scan with `asyncio.to_thread`, as the request-side scan
   does.
4. `session_marks` keeps one entry per session fingerprint holding
   `{label: monotonic time}`. TTL (`MARK_TTL_SECONDS`, 12h) applies per label;
   `MAX_MARKS` and the dropped-entry rule are unchanged: while a dropped entry
   could still be live, a session with no entry has unknown labels, not empty.
5. `labels(session) -> frozenset[SessionLabel] | None`. `None` means no
   session or possibly dropped. `was_flagged` stays as "a `FLAG_LABELS` label
   is live" (None preserved); `FLAG_LABELS` is `flagged_delivery` and
   `tripped`.
6. `SemanticGuardsConfig.refuse_when: list[SessionLabel]` (default empty), on
   both request and response guards. A label listed twice is a load error.
   `refusing_labels` is `refuse_when` joined with `FLAG_LABELS` when
   `refuse_when_flagged` is true.
7. `gatekeeper.session_refusal` runs before the layers and the judge. With any
   refusing label set, a session whose labels are `None` is refused as
   `session_flagged`; so is one carrying a refusing `FLAG_LABELS` label. One
   carrying a refusing `credential_seen` is refused as the new
   `session_credential_seen`. `judge_egress` ignores `refuse_when` and
   `refuse_when_flagged`.
8. `CallFacts` carries `session_labels`. The judge's facts gain "this session
   was delivered a credential: yes/no/unknown", and the audit note reads
   `first_contact=… session_flagged=… credential_seen=…`.

## Non-goals

- Changing what `judge_outbound` does: it already refuses a credential in
  outbound arguments. `credential_seen` covers what it cannot see, a secret
  the agent re-encodes before sending.
- Persisting labels across a restart. Sessions do not survive one either.

## Tests

- Per label: setter, TTL expiry, and the dropped-entry unknown window.
- `credential_seen` set by a delivered response with a credential token; not
  set by a refused one.
- `refuse_when: [credential_seen]` refuses a guarded call after such a read
  and allows it in a clean session; the judge is not called on refusal.
- `refuse_when_flagged: true` and `refuse_when: [flagged_delivery, tripped]`
  behave identically across the existing #457 tests; both together join; a
  label listed twice fails to load.
- A credential on a call refused for a refused mode, a held tool or
  non-object arguments labels the session `tripped`.
- `judge_egress` with `refuse_when` set still reaches the judge.

## Versioning

Additive: MINOR. `refuse_when_flagged` keeps its meaning, now with `tripped`
as its own label rather than a flag mark.
