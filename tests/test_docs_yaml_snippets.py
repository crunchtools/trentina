"""Every YAML snippet we publish must load.

`docs/defense-pipeline.md` published a `defense:` block with `sanitize`,
`classify` and `quarantine` keys. `DefenseConfig` removed those deliberately
(owner's call, 2026-09-13) and is `extra="forbid"`, and a profile that fails
to load is fatal — `__init__.py` refuses to start rather than expose a gateway
whose policy it could not read. So an operator copy-pasting our own
documentation took the perimeter down, and nothing in CI said a word.

That is the failure this file exists to make impossible. The doc fix was a
two-line edit; this test is the actual deliverable, because the edit only
fixes the snippets that were wrong today.

Scope, and why it stops where it does:

* Blocks whose top level is ``profiles:`` go through the real loader. That is
  the whole path an operator's file takes, env-var indirection included.
* Blocks whose top level is ``backends:`` are validated per entry against
  ``Backend``. They are the other shape we publish enough of to get wrong.
* Anything else — a bare ``tools_allow:`` list, a ``request_guards:``
  fragment — is skipped and SAID SO in the test id. A fragment has no single
  model to check it against, and quietly passing over it would make this file
  look like it covers more than it does.

Secrets are the one thing a snippet cannot carry, so every ``*_env:`` name a
snippet mentions is set to a dummy for the duration. That is not a
compromise: what is being checked is the SCHEMA, and a snippet naming an env
var nobody has set is still a snippet an operator can use.

PROPOSED SCHEMA. A design document may legitimately show config for something
that is not built — ``docs/token-routing.md``'s ``delegation:`` section is a
worked proposal, and no commit has ever added a ``DelegationConfig``. Such a
block is marked ``<!-- trentina:proposed -->`` in the source, which both tells
a reader it will not load and tells this file to skip it.

The marker is counted, not merely honoured. ``test_proposed_blocks_are_the_ones_we_know_about``
pins the exact set, so marking a snippet as proposed is a visible change to
this file rather than a quiet way to silence a failure. That is the whole
point: the escape hatch has to cost something, or it becomes the fix.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import pytest
import yaml

from trentina.gateway.loader import load_profiles
from trentina.gateway.profile import Backend

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO = Path(__file__).resolve().parents[1]

_FENCE = re.compile(r"^```ya?ml\n(.*?)^```", re.MULTILINE | re.DOTALL)
_PROPOSED = "<!-- trentina:proposed"

# Config shown for something that is not built. Each entry is a promise that a
# reader has been told so in the document itself.
PROPOSED: frozenset[str] = frozenset(
    {
        # docs/token-routing.md's `delegation:` section: a worked design for
        # worker-model delegation. No DelegationConfig has ever existed.
        "docs/token-routing.md#delegation-schema",
        "docs/token-routing.md#delegation-per-profile",
    }
)
# Two spellings reach the loader: a `*_env:` field naming a variable, and a
# `${VAR}` interpolation inside a backend header. Both fail closed on an unset
# name, so both have to be satisfied here.
_ENV_REF = re.compile(
    r"^\s*\w*_env:\s*([A-Z][A-Z0-9_]*)\s*$|\$\{([A-Z][A-Z0-9_]*)\}",
    re.MULTILINE,
)


class Snippet(NamedTuple):
    """One publishable YAML block, and where a reader found it."""

    where: str
    body: str
    kind: str  # "profiles", "backends", "fragment", or "proposed"

    def __str__(self) -> str:
        return f"{self.where} [{self.kind}]"


def _sources() -> Iterator[Path]:
    """Everything we publish that a reader might copy out of."""
    yield from sorted(REPO.joinpath("docs").rglob("*.md"))
    yield REPO / "README.md"
    yield REPO / "CLAUDE.md"
    yield from sorted(REPO.joinpath("examples").glob("*.yaml"))


def _classify(body: str) -> str:
    """Which model, if any, owns this block's top level."""
    top = {
        line.split(":", 1)[0]
        for line in body.splitlines()
        if line and not line[0].isspace() and ":" in line
    }
    if "profiles" in top:
        return "profiles"
    if top == {"backends"}:
        return "backends"
    return "fragment"


def _collect() -> list[Snippet]:
    out: list[Snippet] = []
    for path in _sources():
        rel = path.relative_to(REPO)
        if path.suffix in (".yaml", ".yml"):
            body = path.read_text(encoding="utf-8")
            out.append(Snippet(str(rel), body, _classify(body)))
            continue
        text = path.read_text(encoding="utf-8")
        for match in _FENCE.finditer(text):
            body = match.group(1)
            line = text[: match.start()].count("\n") + 1
            # The marker sits on the line before the fence.
            preceding = text[: match.start()].rstrip().rsplit("\n", 1)[-1].strip()
            kind = "proposed" if preceding.startswith(_PROPOSED) else _classify(body)
            label = (
                preceding[len(_PROPOSED) :].removesuffix("-->").strip()
                if kind == "proposed"
                else ""
            )
            where = f"{rel}#{label}" if label else f"{rel}:{line}"
            out.append(Snippet(where, body, kind))
    return out


SNIPPETS = _collect()


def _with_env(snippet: Snippet, monkeypatch: pytest.MonkeyPatch) -> None:
    """Satisfy every env var the snippet names. Schema is what is under test."""
    for field_form, brace_form in _ENV_REF.findall(snippet.body):
        name = field_form or brace_form
        monkeypatch.setenv(name, f"dummy-{name.lower()}")


class TestEverySnippetWeShipLoads:
    def test_there_are_snippets_to_check(self) -> None:
        """A collector that silently found nothing would pass every test below."""
        kinds = {s.kind for s in SNIPPETS}
        assert "profiles" in kinds, "no profiles: snippets found — collector is broken"
        assert "backends" in kinds, "no backends: snippets found — collector is broken"

    @pytest.mark.parametrize(
        "snippet",
        [s for s in SNIPPETS if s.kind == "profiles"],
        ids=str,
    )
    def test_profiles_snippet_loads(
        self, snippet: Snippet, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The full operator path: parse, validate, resolve secrets, build drivers.

        A failure here is not a documentation nit. It is a block someone can
        paste into /etc/trentina/profiles.yaml that refuses to start the
        gateway.
        """
        _with_env(snippet, monkeypatch)
        path = tmp_path / "profiles.yaml"
        path.write_text(snippet.body, encoding="utf-8")

        config = load_profiles(path)

        # Loading is the point, but assert on the result too: a snippet that
        # parses to zero profiles is a block an operator would paste and then
        # wonder why nothing is routed.
        assert config.profiles, f"{snippet.where}: loaded, but defines no profiles"

    @pytest.mark.parametrize(
        "snippet",
        [s for s in SNIPPETS if s.kind == "backends"],
        ids=str,
    )
    def test_backends_snippet_validates(self, snippet: Snippet) -> None:
        """A bare `backends:` block, checked per entry against the model."""
        parsed = yaml.safe_load(snippet.body)
        assert isinstance(parsed, dict), f"{snippet.where}: not a mapping"
        for name, body in (parsed.get("backends") or {}).items():
            assert isinstance(body, dict), f"{snippet.where}: backend {name!r}"
            Backend(**body)

    def test_proposed_blocks_are_the_ones_we_know_about(self) -> None:
        """Marking a block `proposed` must be a visible edit to this file.

        Otherwise the marker becomes the fix: the next snippet that fails to
        load gets labelled instead of corrected, and the suite stays green
        while the docs go on publishing config nobody can use.
        """
        found = {s.where for s in SNIPPETS if s.kind == "proposed"}
        assert found == PROPOSED, (
            "proposed-block set changed. If you marked a new block, add it to "
            "PROPOSED with a note saying what is not built and why the doc "
            "still shows it. If you BUILT one, remove the marker and the entry."
        )

    def test_fragments_really_are_unclassifiable(self) -> None:
        """Say out loud what this file does not cover, and check it is honest.

        Fragments are real snippets an operator reads; they simply have no one
        model to validate against. The risk is the reverse of the proposed
        marker: a block that COULD have been checked gets classified as a
        fragment by accident and silently drops out of coverage. So assert
        that every fragment genuinely lacks a checkable top level.
        """
        fragments = [s for s in SNIPPETS if s.kind == "fragment"]
        assert fragments, "no fragments found — the classifier is miscounting"
        for snippet in fragments:
            parsed = yaml.safe_load(snippet.body)
            if not isinstance(parsed, dict):
                continue  # a bare list, e.g. a tools_allow: block's contents
            assert "profiles" not in parsed, (
                f"{snippet.where}: has a profiles: key but was classified a "
                f"fragment — it should be loaded, not skipped"
            )
