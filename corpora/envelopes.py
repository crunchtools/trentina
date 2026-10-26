"""Tool responses in their real envelopes, around any text (gap 24/28/31 class).

L2 does not read prose, it reads a backend's reply: the GitHub issue with its
user object, label list, reactions and two dozen API URLs; the Miniflux entry
with its hash and feed object; Metsuke's sweep page. Measured 2026-10-25 on
the shipped model, a GitHub issue whose body alone scores 0.001 scores 0.999
in its API reply, and real RSS articles that score at most 0.08 as text score
up to 0.755 as Miniflux entries. ``benign_ops`` builds the slim shapes
(``issue_list``: number, title, state, url), which score 0.000, so the gate
never saw the reply that is refused.

Each maker here takes one ``text`` and returns the payload its backend would
return with that text in the field the backend puts human writing in. The
same maker wraps a benign text or an attack, so a model trained or gated on
them learns what is said, not which envelope it arrived in. The text is
never cut: a label that depends on what is said must see all of it. Every value
around the text is invented from the caller's seeded ``random.Random``: no
line comes from a production host (constitution XVII).
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import random
    from collections.abc import Callable

_ORGS = ("example-org", "acme-labs", "opsworks", "infra-tools")
_REPOS = ("gateway", "wiki", "scheduler", "agent", "dashboard", "registry", "backup")
_USERS = ("alice-dev", "bobsmith", "carol-ops", "dave42", "erin-sec", "frank-k", "grace-h")
_LABELS = ("bug", "documentation", "enhancement", "security", "triaged", "good first issue")
_FEEDS = (
    ("LWN.net", "https://lwn.net"),
    ("Example Tech News", "https://news.example.com"),
    ("Security Weekly Digest", "https://secweekly.example.org"),
    ("Platform Engineering Blog", "https://blog.example.net"),
    ("Policy Watch", "https://policy.example.org"),
)
_HOSTS = ("web01", "db02", "edge03", "build04", "mail05")
_SERVICES = (
    "HTTPS",
    "Disk Usage",
    "Memory",
    "PostgreSQL",
    "Backup Freshness",
    "Load",
    "TLS Expiry",
)
_CHANNELS = ("C04ABCD1234", "C05EFGH5678", "C06IJKL9012")
_TOPICS = (
    "token refresh",
    "OAuth revocation",
    "TLS certificate rotation",
    "CVE triage",
    "prompt-injection classifier threshold",
    "signing key rollover",
    "backup retention",
    "rate limiter",
    "container image digest pinning",
    "audit log export",
    "SSH host key check",
    "secret scanning",
)
_PACKAGES = ("openssl", "glibc", "curl", "libxml2")
_VERBS = ("Fix", "Docs:", "Add", "Pin", "Harden", "Revert", "Bump", "Test", "Refactor")


def _dev_title(r: random.Random) -> str:
    """An issue or release title of the kind a repo inbox lists: technical,
    often about security, never an instruction to the reader."""
    topic = r.choice(_TOPICS)
    return r.choice(
        (
            f"{r.choice(_VERBS)} {topic} for {r.choice(_REPOS)}",
            f"{topic}: best-effort fallback when the upstream is down",
            f"{r.choice(_VERBS)} {topic} (follow-up to #{r.randint(10, 600)})",
            f"CVE-2026-{r.randint(1000, 49999)}: bump {r.choice(_PACKAGES)}",
        )
    )


def _plugin_output(r: random.Random, state: str) -> str:
    """A monitoring plugin's one-line output for ``state``."""
    n = r.randint(1, 95)
    return r.choice(
        (
            f"{state} - {n}% used on /var",
            f"{state} - await {r.randint(1, 900) / 10}ms on sda",
            f"{state} - {r.randint(1, 12)} plugins drift from released image",
            f"{state} - certificate expires in {n} days",
            f"{state} - last backup {r.randint(1, 72)}h ago",
            f"{state}: {r.randint(1, 30)} failed logins in 5 minutes",
        )
    )


def slug(text: str, words: int = 9) -> str:
    """A URL slug the way a CMS writes one: the first words, lowercased."""
    return "-".join(re.findall(r"[a-z0-9]+", text.lower())[:words]) or "post"


def _hex(r: random.Random, n: int) -> str:
    return "".join(r.choice("0123456789abcdef") for _ in range(n))


def _b64ish(r: random.Random, n: int) -> str:
    return "".join(
        r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n)
    )


def _ts(r: random.Random) -> str:
    day = f"2026-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}"
    return f"{day}T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}Z"


def _among(r: random.Random, text: str, others: list[str]) -> list[str]:
    """``text`` shuffled in among ``others``, as one item of a listing."""
    items = [text, *others]
    r.shuffle(items)
    return items


def _whole(text: str) -> str:
    """``text`` on one line, all of it: a field the case's label depends on is never cut."""
    return " ".join(text.split())


def _sweep_page(r: random.Random, section: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Metsuke's ``get_sweep`` page around one section's records."""
    return {
        "run_id": f"weekly-report@2026{r.randint(1, 12):02d}{r.randint(1, 28):02d}T020446Z",
        "section": section,
        "status": "ok",
        "errors": [],
        "page": 1,
        "page_count": 1,
        "total": len(records),
        "records": records,
    }


def _title(text: str) -> str:
    first = text.strip().splitlines()[0] if text.strip() else "Untitled"
    return first[:90]


def _gh_user(r: random.Random, login: str) -> dict[str, Any]:
    uid = r.randint(10_000, 9_999_999)
    base = f"https://api.github.com/users/{login}"
    return {
        "login": login,
        "id": uid,
        "node_id": "MDQ6VXNlcj" + _b64ish(r, 10),
        "avatar_url": f"https://avatars.githubusercontent.com/u/{uid}?v=4",
        "gravatar_id": "",
        "url": base,
        "html_url": f"https://github.com/{login}",
        "followers_url": f"{base}/followers",
        "following_url": f"{base}/following{{/other_user}}",
        "gists_url": f"{base}/gists{{/gist_id}}",
        "starred_url": f"{base}/starred{{/owner}}{{/repo}}",
        "subscriptions_url": f"{base}/subscriptions",
        "organizations_url": f"{base}/orgs",
        "repos_url": f"{base}/repos",
        "events_url": f"{base}/events{{/privacy}}",
        "received_events_url": f"{base}/received_events",
        "type": "User",
        "user_view_type": "public",
        "site_admin": False,
    }


def github_issue(r: random.Random, text: str) -> dict[str, Any]:
    """``get_issue``: the REST reply, body = ``text``, title = its first line."""
    org, repo, n = r.choice(_ORGS), r.choice(_REPOS), r.randint(1, 900)
    api = f"https://api.github.com/repos/{org}/{repo}"
    labels = [
        {
            "id": r.randint(10**9, 10**10),
            "node_id": "LA_kwDO" + _b64ish(r, 18),
            "url": f"{api}/labels/{name}",
            "name": name,
            "color": _hex(r, 6),
            "default": name in {"bug", "documentation", "enhancement"},
            "description": None,
        }
        for name in r.sample(_LABELS, r.randint(0, 3))
    ]
    kinds = ("total_count", "+1", "-1", "laugh", "hooray", "confused", "heart", "rocket", "eyes")
    reactions = dict.fromkeys(kinds, 0)
    return {
        "url": f"{api}/issues/{n}",
        "repository_url": api,
        "labels_url": f"{api}/issues/{n}/labels{{/name}}",
        "comments_url": f"{api}/issues/{n}/comments",
        "events_url": f"{api}/issues/{n}/events",
        "html_url": f"https://github.com/{org}/{repo}/issues/{n}",
        "id": r.randint(10**9, 10**10),
        "node_id": "I_kwDO" + _b64ish(r, 22),
        "number": n,
        "title": _title(text),
        "user": _gh_user(r, r.choice(_USERS)),
        "labels": labels,
        "state": r.choice(("open", "closed")),
        "locked": False,
        "assignees": [],
        "milestone": None,
        "comments": r.randint(0, 12),
        "created_at": _ts(r),
        "updated_at": _ts(r),
        "closed_at": None,
        "author_association": r.choice(("MEMBER", "CONTRIBUTOR", "NONE")),
        "type": None,
        "active_lock_reason": None,
        "sub_issues_summary": {"total": 0, "completed": 0, "percent_completed": 0},
        "body": text,
        "closed_by": None,
        "reactions": {"url": f"{api}/issues/{n}/reactions", **reactions},
        "timeline_url": f"{api}/issues/{n}/timeline",
        "performed_via_github_app": None,
        "state_reason": None,
    }


def github_comments(r: random.Random, text: str) -> list[dict[str, Any]]:
    """``list_issue_comments``: a few comments, one of them ``text``."""
    org, repo, n = r.choice(_ORGS), r.choice(_REPOS), r.randint(1, 900)
    out = []
    replies = ["Thanks, I'll take a look.", "Merged, closing.", "Can you add a test?"]
    bodies = _among(r, text, replies[: r.randint(0, 3)])
    for body in bodies:
        cid = r.randint(10**9, 10**10)
        out.append(
            {
                "url": f"https://api.github.com/repos/{org}/{repo}/issues/comments/{cid}",
                "html_url": f"https://github.com/{org}/{repo}/issues/{n}#issuecomment-{cid}",
                "issue_url": f"https://api.github.com/repos/{org}/{repo}/issues/{n}",
                "id": cid,
                "node_id": "IC_kwDO" + _b64ish(r, 22),
                "user": _gh_user(r, r.choice(_USERS)),
                "created_at": _ts(r),
                "updated_at": _ts(r),
                "author_association": r.choice(("MEMBER", "CONTRIBUTOR", "NONE")),
                "body": body,
                "reactions": {"total_count": 0, "+1": 0, "-1": 0},
                "performed_via_github_app": None,
            }
        )
    return out


def _article_html(r: random.Random, site: str, text: str) -> str:
    """``text`` as a feed item's HTML body: paragraphs, and sometimes a lead
    image, an inline link and a "Read more" footer, as real feeds send them."""
    paras = [f"<p>{p}</p>" for p in text.split("\n") if p.strip()]
    if r.random() < 0.4:
        img = f"{site}/wp-content/uploads/{r.randint(2024, 2026)}/{_hex(r, 8)}.jpg"
        paras.insert(0, f'<figure><img src="{img}" alt="" width="1200" height="630"/></figure>')
    if r.random() < 0.4:
        paras.append(f'<p>Related: <a href="{site}/{slug(_dev_title(r))}">{_dev_title(r)}</a></p>')
    if r.random() < 0.5:
        paras.append(f'<p><a href="{site}/{_hex(r, 6)}" rel="nofollow">Read more</a></p>')
    return "".join(paras)


def miniflux_entry(r: random.Random, text: str) -> dict[str, Any]:
    """``read_entry``: Miniflux's entry with its feed. Its content is ``text`` as
    HTML paragraphs, sometimes with a lead image, a related link and a "Read
    more" footer, as feed articles arrive (``_article_html``)."""
    feed_title, site = r.choice(_FEEDS)
    fid = r.randint(1, 80)
    title = _title(text)
    url = f"{site}/{r.randint(2024, 2026)}/{r.randint(1, 12):02d}/{slug(title)}"
    html = _article_html(r, site, text)
    return {
        "id": r.randint(1000, 99999),
        "user_id": 1,
        "feed_id": fid,
        "status": r.choice(("unread", "read")),
        "hash": hashlib.sha256(url.encode()).hexdigest(),
        "title": title,
        "url": url,
        "comments_url": "",
        "published_at": _ts(r),
        "created_at": _ts(r),
        "changed_at": _ts(r),
        "content": html,
        "author": r.choice(("", "Staff", "Jane Doe", "J. Corbet")),
        "share_code": "",
        "starred": False,
        "reading_time": r.randint(1, 12),
        "enclosures": None,
        "tags": [],
        "feed": {
            "id": fid,
            "user_id": 1,
            "feed_url": f"{site}/feed",
            "site_url": site,
            "title": feed_title,
            "checked_at": _ts(r),
            "parsing_error_message": "",
            "parsing_error_count": 0,
            "disabled": False,
            "category": {
                "id": r.randint(1, 7),
                "title": r.choice(("Professional", "Politics & News", "Security")),
                "user_id": 1,
            },
            "icon": {"feed_id": fid, "icon_id": r.randint(1, 90)},
        },
    }


def sweep_rss_page(r: random.Random, text: str) -> dict[str, Any]:
    """Metsuke ``get_sweep`` rss page: entry records, ``text`` the title of one.

    Some records arrive withheld (``flagged: true``, title and feed null) with
    only their URL, as Metsuke stores an entry Trentina flagged at collection.
    """
    records = []
    others = [_dev_title(r) for _ in range(r.randint(2, 30))]
    for t in _among(r, text, others):
        feed_title, site = r.choice(_FEEDS)
        withheld = t is not text and r.random() < 0.3
        records.append(
            {
                "entry_id": r.randint(1000, 9999),
                "category_id": r.randint(1, 7),
                "title": None if withheld else _whole(t),
                "url": f"{site}/{r.randint(2024, 2026)}/{r.randint(1, 12):02d}/{slug(t)}",
                "feed": None if withheld else feed_title,
                "published": _ts(r).replace("Z", "+00:00"),
                "flagged": withheld,
            }
        )
    return _sweep_page(r, "rss", records)


def sweep_inbox_page(r: random.Random, text: str) -> dict[str, Any]:
    """Metsuke ``get_sweep`` inbox page: issue records, ``text`` the title of one."""
    records = []
    others = [_dev_title(r) for _ in range(r.randint(2, 15))]
    for t in _among(r, text, others):
        repo, n = r.choice(_REPOS), r.randint(1, 600)
        records.append(
            {
                "part": r.choice(
                    (
                        "Fixed by the bot, past 7 days",
                        "Triaged, past 7 days, still open",
                        "Pull requests from outside contributors",
                    )
                ),
                "label": f"{repo}#{n}",
                "url": f"https://github.com/{r.choice(_ORGS)}/{repo}/issues/{n}",
                "title": _whole(t),
                "author": r.choice(_USERS),
                "opened": _ts(r)[:10],
                "recommendation": r.choice(("merge", "request changes", "close", "")),
                "repo": repo,
                "number": n,
                "labels": ", ".join(r.sample(_LABELS, r.randint(0, 2))),
                "closed": _ts(r)[:10],
                "triaged": _ts(r)[:10],
                "last_run": _ts(r),
                "conclusion": r.choice(("success", "failure", "skipped")),
            }
        )
    return _sweep_page(r, "inbox", records)


def sweep_infra_page(r: random.Random, text: str) -> dict[str, Any]:
    """Metsuke ``get_sweep`` infra page: monitoring records, ``text`` one plugin output."""
    records = []
    states = ("OK", "WARNING", "CRITICAL", "UNKNOWN")
    stated = [r.choice(states) for _ in range(r.randint(3, 40))]
    said = {_plugin_output(r, state): state for state in stated}  # an output says its state
    for o in _among(r, text, list(said)):
        host, svc = f"{r.choice(_HOSTS)}.example.org", r.choice(_SERVICES)
        q = f"host={host}&service={svc.replace(' ', '+')}"
        state, last = said.get(o) or r.choice(states), r.choice(states)
        records.append(
            {
                "host": host,
                "service": svc,
                "open_now": r.random() < 0.3,
                "pages": r.randint(0, 3),
                "events": r.randint(0, 80),
                "status_url": f"https://monitor.example.org/cgi-bin/extinfo.cgi?type=2&{q}",
                "history_url": f"https://monitor.example.org/cgi-bin/history.cgi?{q}",
                "state_now": state,
                "since": _ts(r),
                "duration": f"{r.randint(0, 9)}d {r.randint(0, 23)}h",
                "hard_now": r.random() < 0.5,
                "acknowledged": r.random() < 0.2,
                "output_now": o,
                "counts": {s: r.randint(1, 20) for s in r.sample(states[1:], r.randint(1, 2))},
                "hard_events": r.randint(0, 20),
                "first": _ts(r),
                "last": _ts(r),
                "last_state": last,
                "last_output": o if r.random() < 0.5 else _plugin_output(r, last),
                "last_page": _ts(r),
            }
        )
    return _sweep_page(r, "infra", records)


def gmail_message(r: random.Random, text: str) -> str:
    """``get_gmail_message_content``: the text the Workspace backend returns."""
    sender = f"{r.choice(_USERS).replace('-', '.')}@example.com"
    return (
        f"Message ID: {_hex(r, 16)}\nThread ID: {_hex(r, 16)}\nSubject: {_title(text)}\n"
        f"From: {sender}\nTo: me@example.net\nDate: {_ts(r)}\n\n--- BODY ---\n{text}\n"
    )


def jira_comment(r: random.Random, text: str) -> dict[str, Any]:
    """``jira_add_comment`` reply: the created comment, body = ``text``."""
    key = f"{r.choice(('OPS', 'PLAT', 'SEC', 'WEB'))}-{r.randint(1, 4000)}"
    cid = r.randint(10_000, 999_999)
    return {
        "id": str(cid),
        "self": f"https://issues.example.com/rest/api/2/issue/{key}/comment/{cid}",
        "author": {
            "name": r.choice(_USERS),
            "displayName": r.choice(_USERS).title(),
            "active": True,
            "timeZone": "America/New_York",
        },
        "body": text,
        "created": _ts(r).replace("Z", ".000+0000"),
        "updated": _ts(r).replace("Z", ".000+0000"),
        "issue": key,
    }


def slack_history(r: random.Random, text: str) -> dict[str, Any]:
    """``slack_get_channel_history``: messages, one of them ``text``."""
    chatter = ["sounds good", "deploy is done", "I'll pick this up tomorrow", "+1"]
    msgs = _among(r, text, chatter[: r.randint(1, 4)])
    return {
        "ok": True,
        "channel": r.choice(_CHANNELS),
        "messages": [
            {
                "type": "message",
                "user": "U0" + _b64ish(r, 9).upper(),
                "text": m,
                "ts": f"{r.randint(1_700_000_000, 1_800_000_000)}.{r.randint(100000, 999999)}",
                "client_msg_id": "-".join(_hex(r, n) for n in (8, 4, 4, 4, 12)),
            }
            for m in msgs
        ],
        "has_more": r.random() < 0.5,
        "response_metadata": {"next_cursor": "bmV4dF90czox" + _b64ish(r, 12)},
    }


def search_results(r: random.Random, text: str) -> dict[str, Any]:
    """web ``search_tool``: ranked results, ``text`` the snippet of one."""
    others = [
        f"Overview of the {r.choice(_SERVICES).lower()} changes in this release."
        for _ in range(r.randint(3, 9))
    ]
    snippets = _among(r, text, others)
    out = []
    for i, s in enumerate(snippets):
        _, site = r.choice(_FEEDS)
        out.append(
            {
                "rank": i + 1,
                "title": _title(s),
                "url": f"{site}/{slug(s)}",
                "snippet": s,
                "published": _ts(r)[:10],
            }
        )
    return {"query": _title(text)[:40], "results": out}


def fetched_page(r: random.Random, text: str) -> str:
    """web ``fetch_tool``: an article as Markdown with its site furniture."""
    _, site = r.choice(_FEEDS)
    title = _title(text)
    nav = " | ".join(
        f"[{w}]({site}/{w.lower()})" for w in ("Home", "News", "Topics", "About", "Subscribe")
    )
    footer = (
        f"[Share]({site}/share?u={slug(title)}) · [RSS]({site}/feed) · © {r.randint(2010, 2026)}"
    )
    return f"{nav}\n\n# {title}\n\n*{_ts(r)[:10]}*\n\n{text}\n\n---\n{footer}\n"


def journal_lines(r: random.Random, text: str) -> dict[str, Any]:
    """systemd ``journal_query``: entries, ``text`` the message of one."""
    msgs = _among(
        r, text, [f"Started {r.choice(_REPOS)}.service." for _ in range(r.randint(3, 25))]
    )
    return {
        "entries": [
            {
                "__REALTIME_TIMESTAMP": str(
                    r.randint(1_700_000_000_000_000, 1_800_000_000_000_000)
                ),
                "_HOSTNAME": r.choice(_HOSTS),
                "SYSLOG_IDENTIFIER": r.choice(("systemd", "podman", "sshd", "crond")),
                "_PID": str(r.randint(1, 99999)),
                "_BOOT_ID": _hex(r, 32),
                "MESSAGE": m,
                "PRIORITY": str(r.randint(3, 6)),
            }
            for m in msgs
        ],
        "count": len(msgs),
    }


MAKERS: dict[str, Callable[[random.Random, str], Any]] = {
    "github_issue": github_issue,
    "github_comments": github_comments,
    "miniflux_entry": miniflux_entry,
    "sweep_rss_page": sweep_rss_page,
    "sweep_inbox_page": sweep_inbox_page,
    "sweep_infra_page": sweep_infra_page,
    "gmail_message": gmail_message,
    "jira_comment": jira_comment,
    "slack_history": slack_history,
    "search_results": search_results,
    "fetched_page": fetched_page,
    "journal_lines": journal_lines,
}
"""Every envelope, by the shape name a result is reported under."""
