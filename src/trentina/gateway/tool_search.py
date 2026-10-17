"""Search over a profile's served tools, for ``find_tools`` and ``load_tools`` (#473).

Deterministic and local: no model, no network, nothing a caller's query can
make slow. Two rankers, lexical first:

- BM25F over three fields: the served name and the tool's category and
  backend, weighted above its description. A name says what a tool does
  more reliably than prose, and a category is what an agent most often
  knows ("something in mail"). Query words are stemmed and widened by a
  short table of synonyms agents use for the same action.
- Character trigrams of the query against the name and category catch what
  words miss, a typo or a fragment of a name. They only fill the places
  BM25 leaves empty: fused by reciprocal rank, they pushed right answers
  down on every weighting the benchmark tried.

Every entry comes from the served aggregate, which the perimeter has already
judged; the index reads that text and hands back positions in it, nothing
else. Accuracy is measured by ``benchmarks/tool_search.py``.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

_WORD = re.compile(r"[A-Za-z]+|[0-9]+")
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")

# Field weights: name, category and backend, description.
_W_NAME = 2.0
_W_GROUP = 2.0
_W_DESC = 1.0
_K1 = 1.2
_B = 0.75
# Below this a trigram match is noise, and would rank every tool.
_TRIGRAM_FLOOR = 0.25
# Longest query read: a query is a few words, and the work is linear in it.
MAX_QUERY_CHARS = 256

_STOP = frozenset(
    {
        *("a", "an", "and", "the", "of", "to", "for", "in", "on", "by", "with"),
        *("from", "my", "me", "i", "is", "are", "be", "it", "this", "that"),
        *("what", "which", "how", "do", "does", "can", "please", "want", "need"),
        *("some", "any", "all", "now", "right"),
    }
)

# Words agents use for the same action or object. Kept small and general: a
# backend's own vocabulary belongs in its names and descriptions.
_SYNONYMS: dict[str, tuple[str, ...]] = {
    "find": ("search", "query", "lookup"),
    "search": ("find", "query"),
    "lookup": ("get", "search"),
    "show": ("get", "list", "read"),
    "view": ("get", "read"),
    "read": ("get",),
    "fetch": ("get", "read"),
    "get": ("read", "fetch"),
    "list": ("search",),
    "create": ("add", "new", "make"),
    "add": ("create",),
    "new": ("create",),
    "make": ("create",),
    "write": ("create", "update"),
    "update": ("edit", "modify", "change", "set"),
    "edit": ("update", "modify"),
    "change": ("update", "set"),
    "set": ("update",),
    "save": ("store", "create"),
    "remember": ("store", "memory"),
    "recall": ("search", "memory"),
    "forget": ("delete",),
    "download": ("fetch", "get"),
    "web": ("fetch", "search"),
    "internet": ("web", "search"),
    "broken": ("problem", "fail"),
    "fail": ("problem", "error"),
    "open": ("create",),
    "close": ("resolve",),
    "assign": ("owner",),
    "recent": ("history", "tail"),
    "delete": ("remove",),
    "remove": ("delete",),
    "send": ("post", "reply"),
    "post": ("send", "publish"),
    "publish": ("post",),
    "email": ("mail", "gmail", "message"),
    "mail": ("email", "gmail", "message"),
    "message": ("mail", "chat"),
    "ticket": ("issue",),
    "issue": ("ticket",),
    "bug": ("issue", "ticket"),
    "page": ("wiki", "doc"),
    "doc": ("document", "page"),
    "document": ("doc",),
    "file": ("document", "drive"),
    "meeting": ("event", "calendar"),
    "event": ("calendar", "meeting"),
    "schedule": ("event", "calendar"),
    "log": ("journal", "logs"),
    "logs": ("log", "journal"),
    "restart": ("start", "stop"),
    "status": ("health", "state"),
    "container": ("podman",),
    "dns": ("record", "zone"),
    "repo": ("repository",),
    "pr": ("pull", "request"),
}


def _stem(word: str) -> str:
    """A light suffix strip, so ``issues``/``issue`` and ``listing``/``list`` meet.

    Plural ``-es`` only after the letters that take it (``boxes``,
    ``searches``), and never the ``s`` of ``status`` or ``class``.
    """
    if len(word) <= 4:
        return word
    if word.endswith("ies"):
        word = word[:-3] + "y"
    elif word.endswith(("sses", "shes", "ches", "xes", "zes")):
        word = word[:-2]
    elif word.endswith("s") and not word.endswith(("ss", "us", "is")):
        word = word[:-1]
    else:
        for suffix in ("ing", "ed"):
            if len(word) > len(suffix) + 3 and word.endswith(suffix):
                word = word[: -len(suffix)]
                # running -> run, stopped -> stop
                if len(word) > 3 and word[-1] == word[-2] and word[-1] not in "lsz":
                    word = word[:-1]
                break
    # change, changes and changed all end as chang
    return word[:-1] if len(word) > 4 and word.endswith("e") else word


def tokens(text: str) -> list[str]:
    """Lower-cased, stemmed words of ``text``: snake, kebab and camel case split."""
    words = _WORD.findall(_CAMEL.sub(" ", text))
    return [_stem(w.lower()) for w in words if w.lower() not in _STOP]


def _trigrams(text: str) -> set[str]:
    grams: set[str] = set()
    for word in _WORD.findall(text.lower()):
        padded = f" {word} "
        grams.update(padded[i : i + 3] for i in range(len(padded) - 2))
    return grams


@dataclass(frozen=True)
class Entry:
    """One served tool as the index sees it."""

    name: str
    category: str
    backend: str
    description: str


@dataclass
class _Doc:
    tf: dict[str, float]
    length: float
    grams: set[str]
    category: str


@dataclass
class ToolIndex:
    """An index over one served aggregate. Build once, search many times."""

    entries: list[Entry]
    _docs: list[_Doc] = field(init=False)
    _df: Counter[str] = field(init=False)
    _avg: float = field(init=False)

    def __post_init__(self) -> None:
        self._docs = []
        self._df = Counter()
        for entry in self.entries:
            tf: dict[str, float] = {}
            group = f"{entry.category} {entry.backend}"
            for weight, text in (
                (_W_NAME, entry.name),
                (_W_GROUP, group),
                (_W_DESC, entry.description),
            ):
                for token in tokens(text):
                    tf[token] = tf.get(token, 0.0) + weight
            self._df.update(tf.keys())
            self._docs.append(
                _Doc(
                    tf=tf,
                    length=sum(tf.values()),
                    grams=_trigrams(f"{entry.name} {group}"),
                    category=entry.category,
                )
            )
        self._avg = sum(d.length for d in self._docs) / len(self._docs) if self._docs else 1.0

    def search(self, query: str, limit: int, category: str | None = None) -> list[int]:
        """Positions in ``entries`` of the best ``limit`` matches, best first."""
        query = query[:MAX_QUERY_CHARS]
        allowed = [
            i for i, d in enumerate(self._docs) if category is None or d.category == category
        ]
        if not allowed or limit < 1:
            return []
        ranked = self._bm25(query, allowed)[:limit]
        if len(ranked) < limit:
            seen = set(ranked)
            ranked += [p for p in self._trigram(query, allowed) if p not in seen]
        return ranked[:limit]

    def _query_weights(self, query: str) -> dict[str, float]:
        weights: dict[str, float] = {}
        for token in tokens(query):
            weights[token] = max(weights.get(token, 0.0), 1.0)
            for synonym in _SYNONYMS.get(token, ()):
                stemmed = _stem(synonym)
                weights[stemmed] = max(weights.get(stemmed, 0.0), 0.4)
        return weights

    def _bm25(self, query: str, allowed: list[int]) -> list[int]:
        weights = self._query_weights(query)
        total = len(self._docs)
        scores: dict[int, float] = {}
        for position in allowed:
            doc = self._docs[position]
            score = 0.0
            for token, weight in weights.items():
                tf = doc.tf.get(token)
                if not tf:
                    continue
                df = self._df[token]
                idf = math.log(1 + (total - df + 0.5) / (df + 0.5))
                norm = tf * (_K1 + 1) / (tf + _K1 * (1 - _B + _B * doc.length / self._avg))
                score += weight * idf * norm
            if score > 0:
                scores[position] = score
        return sorted(scores, key=lambda p: (-scores[p], p))

    def _trigram(self, query: str, allowed: list[int]) -> list[int]:
        grams = _trigrams(query)
        if not grams:
            return []
        scores: dict[int, float] = {}
        for position in allowed:
            doc_grams = self._docs[position].grams
            # Containment of the query, not Jaccard: a short query against a
            # long name should score on how much of the query it finds.
            overlap = len(grams & doc_grams) / len(grams)
            if overlap >= _TRIGRAM_FLOOR:
                scores[position] = overlap
        return sorted(scores, key=lambda p: (-scores[p], p))
