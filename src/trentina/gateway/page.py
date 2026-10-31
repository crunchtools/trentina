"""The one look every page a person sees on this gateway wears (#637).

Three routes put a page in front of a human: the backend sign-in pages, the
approval page, and the page where the approval password is set. Each carried
its own inline styles and none of them said whose gateway it was, which is a
problem of trust before it is one of taste. A page that asks for a password
and shows nothing recognisable is indistinguishable from a page that is
phishing for one, and somebody running two gateways -- which is the ordinary
case here, since federation takes two -- has nothing to tell their passwords
apart with.

So: one parchment sheet, the mark, and the host the browser asked for.

**Why the host and not a configured name.** It is the only identity the
gateway can show without being told one, and showing it discloses nothing:
it is the visitor's own address bar read back to them. A configured name
would be better and is a config field someone has to set, which means the
common case is that it is unset and the page is anonymous again.

**No script, nothing fetched.** Every page here is one response. The mark is
a data URI (see ``mark.py``), the styles are one inline block, and the policy
below is ``default-src 'none'`` plus exactly what that needs -- so an
approval page makes no second request for anything watching the network to
count, and nothing on it can run.

The OAuth *consent* page is not here: it is fastmcp's markup, patched on the
way out by ``consent_ui.py``, and rewriting someone else's page into this
sheet would mean recognising markup we do not own. It stays as it is.
"""

from __future__ import annotations

import html
import re
from typing import TYPE_CHECKING

from .mark import MARK_DATA_URI

if TYPE_CHECKING:
    from starlette.requests import Request

#: Sampled from the engraving in ``docs/images/trentina-mark.png``: ``--sheet``
#: is the mark's own ground, so it sits on the page with no visible edge.
#: ``--ink`` on ``--sheet`` is about 11:1 and ``--soft`` about 5:1, so the
#: quieter text still clears AA at this size.
_STYLES = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem;background:#e6d9bc;color:#3b2f18;
font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:34rem;margin:0 auto;padding:1.5rem 1.75rem 2rem;
background:#f4e6c7;border:1px solid #cdbd98}
header{text-align:center;border-bottom:1px solid #cdbd98;
padding-bottom:1rem;margin-bottom:1.5rem}
header img{display:block;margin:0 auto;width:96px;height:96px}
header p{margin:.6rem 0 0;font-size:.8125rem;letter-spacing:.05em;
color:#6b5a3a;word-break:break-all}
h1{font-size:1.3rem;line-height:1.3;margin:0 0 .75rem}
h2{font-size:1rem;margin:1.75rem 0 .25rem}
p{margin:.75rem 0}
code{font:.9375rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;
word-break:break-all}
label{display:block;margin:1rem 0}
input{font:inherit;width:100%;max-width:22rem;margin-top:.25rem;
padding:.45rem .5rem;background:#fbf4e2;border:1px solid #a8926a;color:inherit}
input:focus{outline:2px solid #755b30;outline-offset:1px}
button{font:inherit;padding:.5rem 1.1rem;cursor:pointer;
background:#755b30;color:#f4e6c7;border:1px solid #5d4826}
button:hover{background:#5d4826}
button[value=decline]{background:transparent;color:#5d4826}
button[value=decline]:hover{background:#e6d9bc}
table{border-collapse:collapse;margin:1rem 0}
th{text-align:left;vertical-align:top;padding:.25rem 1rem .25rem 0}
td{padding:.25rem 0}
.note{color:#6b5a3a;font-size:.9375rem}
"""

_BASE_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

#: A hostname and nothing else: letters, digits, dots and hyphens, starting
#: and ending on an alphanumeric, within DNS's 253. Anything else -- a port
#: that did not split off, a bracketed IPv6 literal, an absent header, a
#: header somebody filled with prose -- fails and the line is simply omitted.
_HOSTNAME = re.compile(r"\A[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\Z")


# TRUST: a caller-chosen header rendered into a page a person reads
#   untrusted: the Host header, picked by anyone who reaches this origin
#   judged-by: _HOSTNAME, a closed character set under a length bound, then
#     html.escape in render
#   on-failure: fail-closed; a non-hostname shows no line, so no fragment of
#     what a caller wrote reaches the page
#   owner: page.served_as, the only reader of the header here
#   evidence: T1 \A..\Z anchors it; T4 never logged, stored or routed on
def served_as(request: Request) -> str | None:
    """The hostname this request asked for, when it is one, else ``None``."""
    host = (request.headers.get("host") or "").rsplit(":", 1)[0]
    return host.lower() if _HOSTNAME.match(host) else None


def headers(*directives: str) -> dict[str, str]:
    """Response headers for a page, with ``directives`` added to its policy.

    ``img-src data:`` is here rather than per page because the mark is inline
    on every one of them; a page that needs to submit a form adds
    ``form-action 'self'`` itself, so no page is permitted more than it uses.
    """
    policy = "; ".join(
        ("default-src 'none'", "style-src 'unsafe-inline'", "img-src data:", *directives)
    )
    return {**_BASE_HEADERS, "Content-Security-Policy": policy}


def render(title: str, body: str, *, host: str | None = None) -> str:
    """The document for ``body``, which the caller built from escaped values."""
    served = f"<p>{html.escape(host)}</p>" if host else ""
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_STYLES}</style>"
        f'<body><main><header><img src="{MARK_DATA_URI}" alt="Trentina" '
        f'width="96" height="96">{served}</header>{body}</main>'
    )
