# Approvals

Your agent runs this gateway. Two things it cannot do alone:

- **Move the operator seat** — who is root here.
- **Turn on federation trust** — serve another gateway's answers without
  scanning them.

For those it asks, and you decide in a browser. Everything else — backends,
guards, defense settings, credentials, whole new profiles — it just does.

## Why those two

Your operator agent has the authority; it is root on its gateway. The problem
is that it is a *model*, so the question was never whether it may, but whether
it can be talked into it. These are the two changes where a plausible-sounding
request does the most damage: one hands root to someone else, the other turns
off the scanning this product exists to do.

## What to tell your agent

Once per gateway, before anything else:

> Ask me to set the approval password.

You get a URL and a one-time code. Open it, paste the code, choose a password.
Your agent cannot do this part — setting a password is a form submission, and
none of Trentina's own tools makes one. That asymmetry is the whole mechanism,
and it is why asking is safe to hand to an agent. It holds as long as the
operator seat's backends are Trentina's own tools; see below.

After that, just say what you want:

> Trust lotor's verdicts for this backend.

> Move the operator seat to <profile>.

It makes the change, the gateway stages it instead of applying it, and your
agent hands you a URL.

## Deciding

Open the URL, enter the password, read what it shows — only things you can
actually check:

- **Operator seat** — who holds it now, who would hold it after.
- **Federation trust** — which backend, the peer's key as a short fingerprint,
  and the peer's scanner and judge beside your own, to compare. Those last two
  are the peer's claims about itself. Pinning the key binds which scanner and
  judge it must keep presenting; it does not bind how that peer actually
  defends, so a weaker setting on its side is not something this page can
  catch.

Approve or decline. Declining changes nothing, and so does ignoring it: a
proposal expires on its own and a restart cancels it.

**If you do not recognise the fingerprint or the peer, decline.** That is the
one check only you can make. Your agent believed whatever the other end told
it; you are the part that does not have to.

## Two things worth knowing

**Set the password promptly on a new gateway.** Until it is set nothing can be
approved, so both changes stay blocked — but the enrolment window is also the
one moment this gateway's approver could be claimed by whoever holds the code.

**Keep code execution off the operator seat.** An agent with a backend that can
run code or fetch arbitrary URLs can submit the form itself — and can rewrite
the configuration directly anyway, so no setting inside the gateway binds it.
If you want the guarantee unconditionally, pin the password in the gateway's
own configuration, where the gateway cannot set it at all —
`TRENTINA_APPROVAL_PASSWORD_HASH_FILE`, and
[configuration](configuration.md) has both forms and the script that prints
one.

## If the page seems unhelpful

It answers identically whether the password was wrong, nothing is staged, or
this gateway has no password at all. That is deliberate — a stranger who finds
the page learns nothing from it, including whether anything is pending right
now. If you are sure the password is right and still see nothing, ask your
agent whether anything is actually staged; it may have expired.

---

For maintainers: the mechanism is `gateway/pending.py` (what is staged),
`gateway/approver.py` (who may approve), `gateway/approval_routes.py` (the
pages) and `gateway/config_guard.py` (which writes need one). The rule they
follow is in the project constitution, under Human Approval.
