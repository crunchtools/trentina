# Specification: A Trust Pin Read Off the Link

> **Spec ID:** 025-federation-attest
> **Status:** Implemented (6.12.0)
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-11-07
> **Ticket:** #640 (lineage #592, #637)

## Overview

A primary trusts a secondary's scan by pinning three values: its Ed25519 key,
its perimeter stamp and its L3 judge. Since #637 that pin is staged for a
person, but all three reached the approval page as the operator agent's claim.
Nothing on the wire let a gateway check them: a secondary signed only its
responses to real `tools/call`s.

**Done is:** an operator tool that probes the link, verifies the peer's
signature against the key the operator supplied, fills the stamp and judge in
from what the peer signed, and stages the pin through the existing approval,
with the page saying *verified at the link* rather than *as supplied*.

## Decision

Ruled on #640 (2026-11-02, with the `cto` advisor): **a new JSON-RPC method,
`trentina/attest`**, not a read-only tool on the ingress's offered set.

- A tool carrying the response envelope would sign a verdict over bytes no
  layer read: `_assemble` emits it only on the judged remote path.
- A tool drags a provisioning handshake through short names, `tool_pins`,
  `modes_policy` and the tool audit.
- Rejected too: the attestation in `initialize` or `ping` `_meta` —
  unsolicited, no challenge, signed for every client.

## Behaviour

1. `trentina/attest {nonce}` on a federation ingress with a secondary key
   returns `{assertion: {verifier, perimeter_stamp, judge, nonce, ts},
   signature}`, signed through `vsa.sign_assertion` over the stamp and judge
   `_federated_vsa` signs. Authenticated per request like `tools/call`.
2. A profile with nothing to sign answers `-32601`, exactly as an older
   gateway does. A nonce outside 32–128 lowercase hex is `-32602`.
3. `federation_trust(profile, backend, public_key, expect_hash,
   [perimeter_stamp, judge])`, operator only, probes with a fresh nonce and
   checks with `attestation.check_attestation` against the supplied key, the
   nonce, the dialled profile (the JWT audience) and `vsa.MAX_AGE_SECONDS`.
4. Verified: stage the signed stamp and judge. Supplied values that differ are
   refused, with what the peer presented.
5. Answered and not verified: stage nothing. No fallback.
6. `-32601`, unreachable or unauthorized: stage the supplied values as before,
   marked as supplied, with the peer's reported version. Never trust.
7. The tool writes nothing. `config.propose_trust` goes through the same lock,
   hash check and staging as `config_tool`, and refuses anything but the one
   `FEDERATION_TRUST` proposal whose loaded pin equals the one checked.
8. The provenance is a fact (`LEARNED_FACT`), so it is inside the digest a
   person's approval binds to. `config_tool` pins say *as supplied*.

## Versioning

Additive, on the federation preview surface (#592): MINOR, 6.12.0. Either side
upgrades first; removing the method restores `-32601` and today's path.
