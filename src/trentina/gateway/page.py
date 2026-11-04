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

**No script but one, nothing fetched.** Every page here is one response. The mark is
a data URI (see ``mark.py``), the styles are one inline block, and the policy
below is ``default-src 'none'`` plus exactly what that needs -- so an
approval page makes no second request for anything watching the network to
count. The one exception is the approval pages' passkey ceremony (#639), a
fixed script allowed by its hash and nothing else, which talks only to its own
origin.

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
label{display:block;margin:1.1rem 0 0;font-size:.9375rem;font-weight:600}
.hint{display:block;font-weight:400;font-size:.8125rem;color:#6b5a3a}
input{display:block;font:inherit;font-weight:400;width:100%;margin-top:.35rem;
padding:.55rem .65rem;background:#fbf4e2;border:1px solid #a8926a;
border-radius:4px;color:inherit}
input:focus{outline:2px solid #755b30;outline-offset:1px}
button{font:inherit;padding:.55rem 1.15rem;cursor:pointer;border-radius:4px;
background:#755b30;color:#f4e6c7;border:1px solid #5d4826}
button:hover{background:#5d4826}
button[value=decline]{background:transparent;color:#5d4826}
button[value=decline]:hover{background:#e6d9bc}
table{border-collapse:collapse;margin:1rem 0}
th{text-align:left;vertical-align:top;padding:.25rem 1rem .25rem 0}
td{padding:.25rem 0}
.note{color:#6b5a3a;font-size:.9375rem}
.lead{font-size:1.05rem}
.actions{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin-top:1.25rem}
.wide{width:100%;padding:.75rem 1rem;font-weight:600}
.row{display:flex;gap:.5rem;margin-top:.35rem}
.row input{margin:0;flex:1;min-width:0}
.row button{white-space:nowrap}
.status{margin:.6rem 0 0;color:#6b5a3a;font-size:.9375rem}
.status:empty{display:none}
.done{margin:0 0 1.25rem;padding:.6rem .85rem;background:#fbf4e2;
border-left:3px solid #755b30}
section{margin-top:1.75rem;padding-top:1.25rem;border-top:1px solid #cdbd98}
section h2{margin:0 0 .25rem}
section>p:first-of-type{margin-top:0}
.keys{list-style:none;margin:.75rem 0 0;padding:0}
.keys li{display:flex;justify-content:space-between;align-items:center;gap:1rem;
padding:.7rem 0;border-top:1px solid #e0d0ab}
.keys li:last-child{border-bottom:1px solid #e0d0ab}
.keys strong{display:block;font-weight:600}
.meta{font-size:.8125rem;color:#6b5a3a}
.keys form{margin:0}
details{margin:1.5rem 0 0;padding-top:1rem;border-top:1px solid #e0d0ab}
summary{cursor:pointer;color:#5d4826;font-size:.9375rem}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #cdbd98;
font-size:.875rem;color:#6b5a3a;display:flex;flex-wrap:wrap;gap:.25rem 1rem;
align-items:center}
footer .who{margin-right:auto}
footer a{color:#5d4826}
footer form{display:inline;margin:0}
footer button,.quiet{padding:0;background:none;border:0;border-radius:0;
color:#5d4826;text-decoration:underline;font-size:inherit}
footer button:hover,.quiet:hover{background:none;color:#3b2f18}
button:disabled{opacity:.55;cursor:default}
"""

_BASE_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

#: A hostname and nothing else: letters, digits, dots and hyphens, starting
#: and ending on an alphanumeric, within DNS's 253. Anything else -- a
#: bracketed IPv6 literal, an absent header, a header somebody filled with
#: prose -- fails and the line is simply omitted. A port is taken off at the
#: FIRST colon and must itself be decimal: splitting at the last one instead
#: would quietly accept `gw.example:anything` as `gw.example`.
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
    host, colon, port = (request.headers.get("host") or "").partition(":")
    if colon and not (port.isascii() and port.isdigit()):
        return None
    return host.lower() if _HOSTNAME.match(host) else None


#: The highest TCP port; a Host header naming a larger one is not an address.
_MAX_PORT = 65535


def served_origin(request: Request) -> str | None:
    """``scheme://host[:port]`` this request reached us on, when the host is a
    hostname, else None (#639).

    ``127.0.0.1`` is spelled ``localhost``: a browser will make a passkey for a
    localhost origin over plain http, and for an IP address never.
    """
    host = served_as(request)
    if host is None:
        return None
    _, colon, port = (request.headers.get("host") or "").partition(":")
    # served_as already refused a non-decimal port; held here again because
    # this value becomes a link, and `gw.example:443@evil.example` must never
    # reach one.
    if colon and not (port.isascii() and port.isdigit() and 0 < int(port) <= _MAX_PORT):
        return None
    if host == "127.0.0.1":
        host = "localhost"
    return f"{request.url.scheme}://{host}{':' + port if colon else ''}"


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


def render(title: str, body: str, *, host: str | None = None, script: str | None = None) -> str:
    """The document for ``body``, which the caller built from escaped values.

    ``script`` is a FIXED text the caller allows by its hash in the policy
    (the approval page's passkey ceremony, #639). Nothing a request carried
    may ever be part of it: values reach the script through escaped
    ``data-`` attributes in ``body``.
    """
    served = f"<p>{html.escape(host)}</p>" if host else ""
    tail = f"<script>{script}</script>" if script else ""
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_STYLES}</style>"
        f'<body><main><header><img src="{MARK_DATA_URI}" alt="Trentina" '
        f'width="96" height="96">{served}</header>{body}</main>{tail}'
    )
