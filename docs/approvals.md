# Approvals

Two changes on a Trentina gateway are not an operator agent's to make alone:
**who holds the operator seat**, and **turning on federation trust**, which
makes this gateway serve another gateway's response without running its own
three layers over it.

Not because the operator lacks the authority. It is root on its gateway: it can
rewrite any profile's backends, guards, defense settings and credentials. These
two are different because the operator is a *model*, so the question was never
whether it may but whether it can be talked into it — and these are the two
changes whose consequences are out of all proportion to how plausible the
request would look.

Until 3.3.x both were simply refused, which meant the two of them needed a text
editor and a shell: the thing this product exists to remove. Now the agent
**proposes** and a person **agrees**.

## How it goes

1. The agent writes the change as it would any other, through `config_tool`.
2. The gateway renders it, validates it by loading it, and finds that it
   touches one of the two. Nothing is written.
3. The agent is told the change is staged, and what a person will be shown.
4. A person opens `/approve`, enters the approval password, reads what is about
   to change, and approves or declines.
5. Only then is the file replaced and the change applied.

A proposal expires on its own if nobody acts on it, and a restart cancels
every one — nothing is kept on disk. A staged change that outlives the process
that proposed it is a change nobody is watching.

**One decision per write.** A single config write could move the operator seat
and pin federation trust, or pin two backends at once. A page can only put one
decision in front of a person, so the rest would be applied unseen on the back
of the one they read — which is exactly what the constitution's requirement
about stating what is being changed forbids. Such a write is refused, naming
the decisions it mixed, and the operator proposes them one at a time.

## The password

The capability to approve has to be something the agent cannot read. That rules
out a link in the tool result, a file the gateway hands back, and anything else
returned by the call that staged the proposal: an agent reads its own results,
and an operator profile that holds a code-execution backend can make an HTTP
request. So it is a password a person holds and the gateway only verifies.

The gateway stores a **scrypt verifier, never the password**. A config mount is
readable by anything running in the container, so storing the password there
would hand it to the caller this is defending against; a verifier yields
nothing that can be submitted.

**Setting it needs no shell.** An operator agent calls `approval_enrol`, which
opens a short window and returns a URL. A person opens it and chooses the
password. The agent can *ask* for that prompt and cannot *answer* it — setting
a password is a form submission, and none of Trentina's tools makes one. That
asymmetry is the whole property, and it is why asking is safe to hand to an
agent.

The window matters, and so does the code that comes with it. A gateway sitting
with no password would otherwise be a standing offer to whoever reached the
page first — and the page is on the public internet, so that is not a
hypothetical. `approval_enrol` returns a one-time code, and setting the
password needs it.

The code goes back to the agent, which is the opposite of the rule about the
approval password itself, so it is worth being explicit about why. They defend
against different callers, and each is closed by a different half. A scanner on
the internet can POST but does not have the code. The operator agent has the
code and cannot POST — `fetch` is GET-only, and `/proxy/http` reaches only
operator-named upstreams bound at startup. So the code is not the capability to
approve; it is proof that a person was pointed at the page by this gateway's
own operator.

The window is opened only on request, it is short, the code changes each time
it opens, and it closes the moment a password is set. It can never replace a
working password — changing an existing one takes the current one.

**The limit of this, stated plainly.** An operator profile that holds a backend
able to make arbitrary HTTP requests — anything that runs code, shells out, or
fetches a URL of its choosing with a method of its choosing — has the code and
can submit the form, so it could enrol itself before a person does. That is not
a flaw this mechanism can close: such a profile can already read the gateway's
own configuration and rewrite `profiles.yaml` directly, so no in-gateway
control binds it. The guarantee here is scoped to an operator whose tools are
Trentina's own.

Two things follow. Set the password promptly on a new gateway — the window is
the exposure, and it closes. And treat the operator seat's backend list as part
of this boundary: a seat that needs arbitrary code execution is a seat that
cannot be held to any of this. A deployment that wants the guarantee
unconditionally should pin the verifier in its configuration instead, where the
gateway cannot set it at all.

A deployment can pin a verifier in the gateway's configuration instead
(`TRENTINA_APPROVAL_PASSWORD_HASH`, or better its `_FILE` form in the read-only
config mount). That wins over anything set in a browser, and the page says so
rather than offering to change it. `scripts/approval_password.py` prints a
verifier for that path.

**With no approver configured, nothing can be approved**, so both changes stay
refused exactly as they were before any of this existed. The absence of a way
to approve is never an approval anyone can give.

## What the page shows

Only values a person can actually check, and nothing a peer chose reaches it
unbounded.

For the **operator seat**: who holds it now, who would hold it after, and that
whoever holds it is root on this gateway.

For **federation trust**: which backend, the pinned key as a fingerprint rather
than a wall of base64, the peer's scanner and judge, and what this gateway
scans under, so the two can be compared. It also states plainly that the pin
does not bind the peer's own defense settings — only its scanner and judge.

A federated peer chooses its own scanner and judge strings. Rendering a peer's
text to the person deciding whether to believe that peer is the one place this
feature could be turned against its own purpose, so those values are held to a
plain displayable shape *before* a proposal is staged, and escaped again when
the page is built.

## What is deliberately not here

**Tool pins.** A gateway holds hundreds of tool descriptions and a restart can
re-hold every remote tool at once. A browser click per tool would push people
toward turning pinning off, which costs more than it protects, so pins stay an
operator decision.

**The OAuth consent page.** That is part of the OAuth protocol rather than an
internal decision, and it keeps its own flow — though this page follows its
look and its guards, so a person meets one idiom on a gateway rather than
three.

## Adding another

The mechanism is deliberately one mechanism. A new action with a blast radius
like these two gets a kind in `gateway/pending.py` and the facts to display —
not a flow of its own. It is the same rule that keeps one egress guard and one
driver registry: a second copy is a second thing to get wrong.

## Where it is

| What | Where |
|---|---|
| What is staged, and applying it once | `gateway/pending.py` |
| Who may approve | `gateway/approver.py` |
| The pages | `gateway/approval_routes.py` |
| Which writes need one, and the facts shown | `gateway/config_guard.py`, `tools/config.py` |
| Asking a person to set the password | `tools/enrol.py` |

The rule these follow is in the project constitution, under Human Approval.
