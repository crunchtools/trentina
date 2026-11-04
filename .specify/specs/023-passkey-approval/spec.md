# Specification: Approve With a Passkey, Brought Up On Request

> **Spec ID:** 023-passkey-approval
> **Status:** Implemented (6.5.0)
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-11-04
> **Ticket:** #639 (follows #637)

## Overview

Approving a staged grant took a password someone had to set, re-typed for
every decision and reflected back into the review page as a hidden field. #639
asked for approval by passkey instead, with no secret on the gateway. Scott
added the front door: "let me set my passkey in Trentina" or "let me change my
password in Trentina" to the operator agent brings up the page in his browser,
locally or remotely, with standard start, stop and timeouts.

**Done is:** a person enrols a passkey from a link the operator agent hands
them, signs in with it to approve, manages passkeys and the password from a
signed-in page, and can run the gateway with no password at all.

## Decision

Product (Scott, 2026-11-04): passkey plus the agent-opened page; an elegant UX.
Google sign-in, the issue's other method, is deferred to its own issue.

Technical (Josui, `cto` ruling): no new dependency and no CBOR parser; the
origin is pinned at registration and compared exactly; server-side sessions
replace the reflected password.

## Behaviour

1. `approval_enrol(action="open")` with nothing set opens the enrolment window
   (unchanged rules) and returns `open_url`: `TRENTINA_OAUTH_BASE_URL`, else the
   origin the call arrived on, plus `/approve/setup#code=<code>`. The fragment
   never reaches the server. With something set it returns the same page with
   no code. `action="close"` shuts the window.
2. `/approve/setup` offers **Create a passkey** first and a password second.
   Enrolling signs the person straight in.
3. `/approve` signed out offers **Sign in with a passkey**, the password tucked
   under it. Signed in, it shows what is staged, or "Nothing is waiting".
4. A session is in memory only (sha256 of the token kept), five minutes idle,
   fifteen absolute, at most eight, SameSite=Strict, CSRF token on every form,
   counted down on the page, ended by Sign out or a restart.
5. Managing (add/remove passkey, change/remove password) needs a sign-in from
   the last five minutes. The last way to approve cannot be removed. Removing a
   credential or changing the password signs out every other session. Every
   change writes an audit row naming a credential digest, never the id.
6. Every unauthenticated failure — form or JSON — answers identically, with no
   cookie.

## Passkey check (`gateway/webauthn.py`)

- Registration takes the browser's `getPublicKey()` SPKI and
  `getAuthenticatorData()`; attestation `none`, resident key and user
  verification required; ES256, EdDSA, RS256 (2048–4096) only.
- Authenticator data is read by fixed offset to the credential id and no
  further; client data is length-capped before `json.loads`. In process: fixed
  slicing and a capped parse cannot hang or grow (constitution VII).
- The origin comes from the signed client data at registration, its host must
  be the host the page was served as, https or `http://localhost` only, and it
  is stored with the rpId. An assertion is held to both, never to the request.
- Counter: refused when the stored one is nonzero and the presented one does
  not climb.
- Challenges: single use, 120 s, bound to ceremony and (registration) to the
  session or code, pool of 256 evicting the oldest.

## Rate limits

Requests that test something keep the 10-burst, 30/hour bucket; page loads,
challenges and sign-out share a 60-burst, 600/hour one, so a visit does not
spend the guesses.

## Not in scope

Google sign-in (deferred); attestation; cross-checking the SPKI against the
COSE key (needs CBOR; the registrant is already authorised).
