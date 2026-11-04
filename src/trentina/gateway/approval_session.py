"""Who is signed in to the approval page, and the passkey challenges in flight (#639).

Before this, deciding meant presenting the password on every POST, so the
review page carried it forward in a hidden field: in the DOM, in form history,
on whatever screen the person was sharing. A session replaces that. A person
proves who they are once — a passkey or the password — and holds a cookie for a
few minutes; the secret is never written back into a page.

**Short, and in memory only.** Five minutes idle, fifteen at most, and a
restart signs everyone out, which is the fail-closed direction: a session that
outlives the process that issued it is one nobody is watching. At most
``MAX_SESSIONS`` exist, the oldest giving way, so a stream of sign-ins cannot
grow this.

**The token is not kept.** Only its sha256 is, so reading this process's
memory yields nothing that can be presented — the same reason the password is
an scrypt verifier.

**Fresh, for anything that changes how approval works.** Adding or removing a
passkey, or changing the password, needs a sign-in from the last
``FRESH_SECONDS``; an older session is asked to confirm first. A borrowed,
unlocked laptop with a tab left open should not be enough to replace the
person who opened it.

Challenges live here rather than in ``webauthn`` because they are state:
single use, ``CHALLENGE_SECONDS`` long, bound to their ceremony and, for a
registration, to the session or enrolment code that asked. The pool evicts its
oldest rather than refusing when full: a pool that refused would let anyone who
can reach the page lock the real person out by asking for challenges.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..logsafe import hold

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

IDLE_SECONDS = 300.0
ABSOLUTE_SECONDS = 900.0
FRESH_SECONDS = 300.0
MAX_SESSIONS = 8

CHALLENGE_SECONDS = 120.0
MAX_CHALLENGES = 256

_TOKEN_BYTES = 32

#: ``__Host-`` makes the browser refuse the cookie unless it is Secure, has no
#: Domain and has Path=/, so no sibling host or path can plant or read it.
#: Plain http is only ever ``localhost``, where that prefix is unavailable.
SECURE_COOKIE = "__Host-trentina-approval"
PLAIN_COOKIE = "trentina-approval"
PLAIN_PATH = "/approve"


@dataclass
class Session:
    created: float
    last_seen: float
    authenticated: float
    method: str
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(_TOKEN_BYTES))

    def live(self, now: float) -> bool:
        return now - self.last_seen <= IDLE_SECONDS and now - self.created <= ABSOLUTE_SECONDS


_sessions: OrderedDict[str, Session] = OrderedDict()


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def start(method: str, *, now: float | None = None) -> str:
    """Sign a person in and return the token for their cookie."""
    moment = time.monotonic() if now is None else now
    _sweep(moment)
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    session = Session(created=moment, last_seen=moment, authenticated=moment, method=method)
    hold(token, "APPROVAL_SESSION")
    hold(session.csrf, "APPROVAL_CSRF")
    _sessions[_digest(token)] = session
    while len(_sessions) > MAX_SESSIONS:
        _sessions.popitem(last=False)
    return token


def _sweep(now: float) -> None:
    for key in [key for key, session in _sessions.items() if not session.live(now)]:
        del _sessions[key]


def find(token: str | None, *, now: float | None = None, touch: bool = True) -> Session | None:
    """The live session for ``token``, its idle clock restarted, or None."""
    if not token:
        return None
    moment = time.monotonic() if now is None else now
    session = _sessions.get(_digest(token))
    if session is None:
        return None
    if not session.live(moment):
        del _sessions[_digest(token)]
        return None
    if touch:
        session.last_seen = moment
    return session


def remaining(session: Session, *, now: float | None = None) -> int:
    """Whole seconds until this session ends if nothing more is done."""
    moment = time.monotonic() if now is None else now
    left = min(
        IDLE_SECONDS - (moment - session.last_seen),
        ABSOLUTE_SECONDS - (moment - session.created),
    )
    return max(0, int(left))


def fresh(session: Session, *, now: float | None = None) -> bool:
    """Whether the person signed in recently enough to change how approval works."""
    moment = time.monotonic() if now is None else now
    return moment - session.authenticated <= FRESH_SECONDS


def csrf_ok(session: Session, presented: object) -> bool:
    """Whether ``presented`` is this session's CSRF token, compared in constant time."""
    return isinstance(presented, str) and hmac.compare_digest(
        presented.encode("utf-8"), session.csrf.encode("utf-8")
    )


def end(token: str | None) -> None:
    """Sign out the session ``token`` names, if it is live."""
    if token:
        _sessions.pop(_digest(token), None)


def end_others(token: str | None) -> None:
    """End every session but ``token``'s: a credential was removed, and whoever
    signed in with it must not still be in."""
    keep = _digest(token) if token else None
    for key in [key for key in _sessions if key != keep]:
        del _sessions[key]


def clear() -> None:
    """Sign everyone out. For tests, and as what a restart does anyway."""
    _sessions.clear()
    _challenges.clear()


def _secure(request: Request) -> bool:
    return request.url.scheme == "https"


def cookie_name(request: Request) -> str:
    """``__Host-`` prefixed on https; a plain name on http, which is only localhost."""
    return SECURE_COOKIE if _secure(request) else PLAIN_COOKIE


def token_of(request: Request) -> str | None:
    """The session token this request's cookie carries, if any."""
    return request.cookies.get(cookie_name(request))


def current(request: Request, *, touch: bool = True) -> Session | None:
    """The live session behind this request's cookie, its idle clock restarted."""
    return find(token_of(request), touch=touch)


def set_cookie(response: Response, request: Request, token: str) -> None:
    """Hand the browser ``token``: HttpOnly, SameSite=Strict, Secure and Path=/ on
    https, Path=/approve on localhost http, lasting no longer than a session can."""
    secure = _secure(request)
    response.set_cookie(
        cookie_name(request),
        token,
        max_age=int(ABSOLUTE_SECONDS),
        path="/" if secure else PLAIN_PATH,
        secure=secure,
        httponly=True,
        samesite="strict",
    )


def clear_cookie(response: Response, request: Request) -> None:
    """Tell the browser to drop the cookie, with the attributes it was set with."""
    secure = _secure(request)
    response.delete_cookie(
        cookie_name(request),
        path="/" if secure else PLAIN_PATH,
        secure=secure,
        httponly=True,
        samesite="strict",
    )


@dataclass(frozen=True)
class _Challenge:
    value: bytes
    ceremony: str
    binding: str
    issued: float


_challenges: OrderedDict[str, _Challenge] = OrderedDict()


def issue_challenge(ceremony: str, binding: str = "", *, now: float | None = None) -> bytes:
    """A fresh challenge for ``ceremony``, bound to ``binding`` (a session
    digest or an enrolment code's digest, empty for sign-in)."""
    moment = time.monotonic() if now is None else now
    value = secrets.token_bytes(32)
    key = hashlib.sha256(value).hexdigest()
    _challenges[key] = _Challenge(value, ceremony, binding, moment)
    while len(_challenges) > MAX_CHALLENGES:
        _challenges.popitem(last=False)
    return value


def take_challenge(
    value: bytes, ceremony: str, binding: str = "", *, now: float | None = None
) -> bool:
    """Whether ``value`` is a live challenge this gateway issued for this
    ceremony and binding. Consumed whether or not it matches, so a challenge
    is tried once."""
    moment = time.monotonic() if now is None else now
    found = _challenges.pop(hashlib.sha256(value).hexdigest(), None)
    return (
        found is not None
        and found.ceremony == ceremony
        and hmac.compare_digest(found.binding.encode(), binding.encode())
        and moment - found.issued <= CHALLENGE_SECONDS
    )


def binding_for_session(token: str) -> str:
    return "session:" + _digest(token)


def binding_for_code(code: str) -> str:
    return "code:" + _digest(code)
