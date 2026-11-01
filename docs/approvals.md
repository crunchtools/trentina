# Approvals

Two changes on a Trentina gateway are not an operator agent's to make alone:
**who holds the operator seat**, and **turning on federation trust**, which
makes this gateway serve another gateway's response without running its own
three layers over it.

Not because the operator lacks the authority — it is root on its gateway and
can rewrite any profile's backends, guards, defense settings and credentials.
These two are different because the operator is a *model*. The question was
never whether it may, but whether it can be talked into it, and these are the
two changes whose consequences are furthest out of proportion to how plausible
the request would look.

Until 3.3.x both were simply refused, which meant both needed a text editor and
a shell: the thing this product exists to remove. Now the agent **proposes** and
a person **agrees**.

## How it goes

The agent writes the change through `config_tool` like any other. The gateway
renders it, validates it by loading it, finds it touches one of the two, and
writes nothing — the agent is told it is staged and what a person will be
shown. A person opens `/approve`, enters the approval password, reads the
change, and approves or declines. Only then is the file replaced.

A proposal expires on its own, and a restart cancels every one. Nothing is kept
on disk: a staged change that outlives the process that proposed it is a change
nobody is watching.

**One decision per write.** A page can put only one decision in front of a
person, so a write mixing two is refused, naming them. Otherwise the second
would be applied unseen on the back of the one they read.

## The password

The capability to approve has to be something the agent cannot read. That rules
out a link in the tool result, or anything else the staging call returns: an
agent reads its own results, and an operator holding a code-execution backend
can make an HTTP request. So it is a password a person holds, stored as a
**scrypt verifier, never the password** — a config mount is readable in the
container, and a verifier yields nothing submittable.

**Setting it needs no shell.** `approval_enrol` opens a short window
(`gateway.approval_enrol_window_seconds`, default 300, clamped to 60–3600) and
returns a URL and a one-time code. A person opens it and chooses the password.
The agent can *ask* for that prompt and cannot *answer* it — setting a password
is a form submission, and no Trentina tool makes one. That asymmetry is the
whole property, and it is why asking is safe to hand to an agent.

The code goes back to the agent, which is the opposite of the rule about the
password itself, and deliberately: the two defend against different callers. A
scanner on the internet can POST but has no code. The operator has the code and
cannot POST — `fetch` is GET-only, and `/proxy/http` reaches only
operator-named upstreams bound at startup. The code is not the capability to
approve; it is proof that a person was pointed at the page by this gateway's
own operator.

A deployment can pin a verifier instead (`TRENTINA_APPROVAL_PASSWORD_HASH`, or
its `_FILE` form in the read-only config mount). That wins over anything set in
a browser, and the page says so. `scripts/approval_password.py` prints one.

**With no approver configured, nothing can be approved**, so both changes stay
refused. The absence of a way to agree is never an agreement.

### The limit, stated plainly

An operator profile holding a backend that can make arbitrary HTTP requests —
anything that runs code, shells out, or fetches a URL of its choosing with a
method of its choosing — has the code and can submit the form, so it could
enrol itself before a person does. No in-gateway control binds such a profile:
it can already rewrite `profiles.yaml` directly. So set the password promptly
on a new gateway, and treat the operator seat's backend list as part of this
boundary. A deployment that wants the guarantee unconditionally pins the
verifier in configuration, where the gateway cannot set it at all.

## The page

One sheet, the Trentina mark, and the hostname the browser asked for. That is
not decoration: a password prompt carrying nothing recognisable is
indistinguishable from one phishing for the same password, and anyone running
federation holds two approval passwords with nothing to tell them apart.

It answers identically in every state. Which field was offered, which one was
wrong, and whether this gateway has a password at all are one answer, so an
unauthenticated visitor learns nothing — and the route stays mounted when
nothing is staged, because a page that vanished when idle would make its own
existence the signal for when to attack.

It shows only what a person can check: for the seat, who holds it now and who
would after; for trust, the backend, the pinned key as a fingerprint, and the
peer's scanner and judge beside this gateway's own, with the warning that the
pin does not bind the peer's `defense` block. A peer chooses those strings, so
they are held to a displayable shape before staging and escaped again at render.

Reachability is the deployment's layer. The page is rate limited — ten burst,
thirty an hour per address, scrypt behind each — but behind a proxy with
`TRENTINA_FORWARDED_ALLOW_IPS` unset every caller shares one bucket and anyone
who can reach the page can lock the person out. A gateway with no inbound route
of its own should not hold a standing public door; `contrib/tunnel/` ships a
reverse tunnel for that, deliberately not enabled.

**Deliberately not here:** tool pins (a gateway holds hundreds, and a click each
would push people toward turning pinning off) and the OAuth consent page (part
of the protocol, though it follows this look). A new action with a blast radius
like these two gets a kind in `gateway/pending.py`, not a flow of its own.

## Where it is

| What | Where |
|---|---|
| What is staged, and applying it once | `gateway/pending.py` |
| Who may approve | `gateway/approver.py` |
| The pages | `gateway/approval_routes.py`, `gateway/page.py` |
| Which writes need one, and the facts shown | `gateway/config_guard.py`, `tools/config.py` |
| Asking a person to set the password | `tools/enrol.py` |

The rule these follow is in the project constitution, under Human Approval.
