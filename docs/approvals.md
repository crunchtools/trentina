# Approvals

Your agent runs this gateway. Six things it cannot do alone:

- **Move the operator profile** — who is root here, and which of them this
  gateway reports as itself.
- **Turn on federation trust** — serve another gateway's answers without
  scanning them.
- **Let another gateway in** — add a peer that may authenticate to a profile you
  share, and use that profile's sign-ins.
- **Stand a perimeter down** — let a profile detect injections without
  refusing them.
- **Open a way out** — let an agent's traffic reach somewhere new on the
  internet.
- **Let a peer administer this gateway** — widen the admin tools reachable
  through a profile that is both shared and the operator, so the gateway on the
  other end of that link can call them.

For those it asks, and you decide in a browser. Everything else — backends,
guards, thresholds, credentials, whole new profiles — it just does.

**Taking any of them away never asks.** Removing a peer, turning enforcement
back on, dropping an egress host: your agent does that on its own, because
each one only makes the gateway stricter. You are asked when something is being
*granted*.

## Why these five

Your operator agent has the authority; it is root on its gateway. The problem
is that it is a *model*, so the question was never whether it may, but whether
it can be talked into it. These are the changes where a plausible-sounding
request does the most damage: one hands root to someone else, one turns off the
scanning this product exists to do, one hands a profile — and the accounts it is signed in to —
to a gateway you have never met, one leaves a profile detecting attacks and permitting them, and one
gives an agent a route off your network.

That last one has the widest blast radius of the five, which is easy to get
backwards. A gateway you trust has at least *scanned* the answer it hands you.
A tunnel out has no scan at all — nothing reads what crosses it, by design,
because it is someone else's TLS.

## What to tell your agent

Once per gateway, before anything else:

> Let me set my passkey in Trentina.

Your agent opens a page in your browser with a one-time code already filled in.
Choose **Create a passkey**, unlock it with your fingerprint, face or PIN, and
you are done: the gateway keeps only a public key, so there is no secret on it
to steal. A password is there too, under "Set a password instead", for a
browser that cannot make a passkey.

Your agent cannot do this part. A passkey needs your device, and a password is
a form submission none of Trentina's own tools makes. That asymmetry is the
whole mechanism, and it is why asking is safe to hand to an agent. It holds as
long as the operator profile's backends are Trentina's own tools; see below.

Later, the same request gets you the same page, and you sign in first:

> Let me change my password in Trentina.

> Add a passkey for my phone.

There you add or remove passkeys, change the password, or drop it entirely once
a passkey is enrolled. The last way to approve can never be removed. Removing a
passkey or changing the password signs out everyone else.

The enrolment window is short (five minutes by default), closes as soon as
something is set, and your agent can close it early. Passkeys need https, or a
gateway reached as `localhost`.

After that, just say what you want:

> Trust the peer gateway's verdicts for this backend.

> Move the operator profile to <profile>.

> Make <profile> an operator too.

> Let a peer federate into the shared ingress.

> This agent's client needs to reach api.example.com.

It makes the change, the gateway stages it instead of applying it, and your
agent hands you a URL.

**One question at a time.** If a single change would need two of your
approvals — moving the operator role *and* trusting a peer, say — the gateway refuses it
outright and tells your agent to do them separately. A page can only put one
decision in front of you, and the other would have ridden along unread.

## Deciding

Open the URL, sign in with your passkey (or the password), and read what it
shows — only things you can actually check:

- **Operator role** — which profile holds it now, which would hold it after.
- **Federation trust** — which backend, the peer's key as a short fingerprint,
  and the peer's scanner and judge beside your own, to compare, and how those
  two were learned. *Verified at the link* means the peer signed them with that
  key a moment ago (`federation_trust`); *as supplied* means your agent wrote
  them and nothing checked them, which is what you get from a peer older than
  6.12.0. Pinning the key binds which scanner and judge it must keep
  presenting; it does not bind how that peer actually defends, so a weaker
  setting on its side is not something this page can catch.
- **Federation peers** — each gateway being let in, by name, with its key as a
  short fingerprint. A peer whose *name* you already approved but whose key
  has changed shows up here too: same name, different gateway. Beside the keys,
  what the link actually hands over: which of that profile's backends cross, and
  which of those **run as your sign-in**. A federated call runs as the profile, so
  the profile's OAuth grants serve the link — admitting a peer to a profile signed in
  to a mailbox means that peer's calls read and write that mailbox. Both rows
  are always there, "none" included, so a missing one never has to be read as
  "the page did not mention it".
- **Defense downgrade** — which profile, and each setting's before and after.
  `flag` means that profile still detects an injection and no longer refuses
  one.
- **Egress grant** — each destination being opened. A `client_egress` row
  names the profile it belongs to, and there are two kinds: a host that
  profile's client may be tunnelled to, and a network its clients may connect
  *from*. An `egress_upstreams` or `llm_providers` row is the whole gateway's,
  not one profile's — any profile configured to use it reaches it. An
  `llm_providers` entry also says it will not be live until the gateway
  restarts, because that section is read only at startup.

Approve or decline. Declining changes nothing, and so does ignoring it: a
proposal expires on its own and a restart cancels it.

Signing in lasts five minutes idle and fifteen at most, the page counts it
down, and **Sign out** ends it at once. Your password is never written back into
the page.

**If you do not recognise the fingerprint or the peer, decline.** That is the
one check only you can make. Your agent believed whatever the other end told
it; you are the part that does not have to.

## Two things worth knowing

**Set it up promptly on a new gateway.** Until a passkey or password is set
nothing can be approved, so all of these stay blocked — but the enrolment
window is also the one moment this gateway's approver could be claimed by
whoever holds the code.

**Keep code execution off the operator profile.** An agent with a backend that can
run code or fetch arbitrary URLs can submit the form itself — or, while the
enrolment window is open, register a software passkey of its own — and can rewrite
the configuration directly anyway, so no setting inside the gateway binds it.
If you want the guarantee unconditionally, pin the password in the gateway's
own configuration, where the gateway cannot set it at all —
`TRENTINA_APPROVAL_PASSWORD_HASH_FILE`, and
[configuration](configuration.md) has both forms and the script that prints
one.

## If the page seems unhelpful

Before you sign in, every failure looks the same: a wrong password, a passkey
this gateway does not know, an expired attempt. That is deliberate — a stranger
who finds the page learns nothing from it, including whether anything is
pending. Once you are signed in it tells you plainly, including "Nothing is
waiting"; if you expected something, ask your agent, since a proposal expires.

If the passkey button is greyed out, the browser has no passkeys here: use
https, or reach a local gateway as `localhost` rather than `127.0.0.1`.

---

For maintainers: the mechanism is `gateway/pending.py` (what is staged),
`gateway/approver.py` (who may approve), `gateway/webauthn.py` (the passkey
check, no CBOR), `gateway/approval_session.py` (sign-in sessions and
challenges), `gateway/approval_routes.py` (the pages) and
`gateway/config_guard.py` (which writes need one). The rule they
follow is in the project constitution, under Human Approval.
