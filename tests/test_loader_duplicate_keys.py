"""A key written twice in `profiles.yaml` is refused, not silently resolved.

`yaml.safe_load` keeps the LAST of a repeated key and says nothing. One of mine
reached production: lotor's `josui` carried `defense:` twice, the gateway ran
the second, and the comment on the first explained a block that had already
lost. The two happened to agree, so nothing was misconfigured — and nothing
would have said so if they had not. Not the loader, not `profile_lint`, not a
pre-flight that loads the file.

`config_tool`'s whole contract is that the file a human reads is the file that
runs. A duplicate key breaks that quietly, which is the worst way, so the
loader refuses rather than warns.

The two tests that matter most here are the ones about anchors. A key that
arrives through `<<: *anchor` and is also written explicitly is NOT a
duplicate — it is the override the merge key exists for — and a check that
flagged it would make anchors unusable in a file that leans on them. The first
version of this scan died on a real file with `could not determine a
constructor for the tag ':merge'`, which is why the implementation walks nodes
instead of constructing them.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import GatewayConfig, duplicate_keys, load_profiles
from trentina.gateway.profile_lint import lint_file


def _load(tmp_path: Path, body: str, monkeypatch: pytest.MonkeyPatch) -> GatewayConfig:
    monkeypatch.setenv("TOK", "a-token")
    path = tmp_path / "profiles.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return load_profiles(path)


ONE_GOOD_PROFILE = """\
profiles:
  alpha:
    auth:
      bearer_token_env: TOK
    backends:
      wiki:
        url: https://wiki.example/mcp
"""


def test_a_clean_file_still_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _load(tmp_path, ONE_GOOD_PROFILE, monkeypatch)
    assert set(config.profiles) == {"alpha"}


class TestADuplicateIsRefused:
    def test_a_repeated_key_on_a_profile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The production shape: two `defense:` blocks, the second winning."""
        with pytest.raises(ProfileConfigError) as caught:
            _load(
                tmp_path,
                """\
                profiles:
                  alpha:
                    auth:
                      bearer_token_env: TOK
                    defense:
                      enforcement: block
                    backends:
                      wiki:
                        url: https://wiki.example/mcp
                    defense:
                      enforcement: flag
                """,
                monkeypatch,
            )
        message = str(caught.value)
        assert "Duplicate key" in message
        assert "'defense'" in message
        # The LINE of the repeat, so a reader can go straight to the one to cut.
        assert "line 10" in message, message

    def test_a_repeated_key_nested_in_backends(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nested, because the walk has to reach every mapping, not just the top."""
        with pytest.raises(ProfileConfigError, match=r"Duplicate key.*'url'"):
            _load(
                tmp_path,
                """\
                profiles:
                  alpha:
                    auth:
                      bearer_token_env: TOK
                    backends:
                      wiki:
                        url: https://wiki.example/mcp
                        url: https://elsewhere.example/mcp
                """,
                monkeypatch,
            )

    def test_a_repeated_profile_name(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The worst case: a whole profile silently replaced by a later one."""
        with pytest.raises(ProfileConfigError, match=r"Duplicate key.*'alpha'"):
            _load(
                tmp_path,
                """\
                profiles:
                  alpha:
                    auth:
                      bearer_token_env: TOK
                    backends:
                      wiki:
                        url: https://wiki.example/mcp
                  alpha:
                    auth:
                      bearer_token_env: TOK
                    backends:
                      other:
                        url: https://other.example/mcp
                """,
                monkeypatch,
            )

    def test_every_duplicate_is_named_in_source_order(self) -> None:
        """Two of them, reported together: fixing one at a time is a bad loop."""
        found = duplicate_keys(
            textwrap.dedent(
                """\
                profiles:
                  alpha:
                    role: agent
                    role: operator
                  beta:
                    enabled: true
                    enabled: false
                """
            )
        )
        assert found == [("role", 4), ("enabled", 7)]


class TestAnchorsAndMergeKeysStillWork:
    """The rules that keep this from making real files unloadable."""

    def test_a_merge_key_is_not_a_duplicate_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`<<: *anchor` plus an explicit override is the point of anchors.

        lotor's file does this throughout. An earlier version of the scan
        constructed the mapping to inspect it and raised `could not determine a
        constructor for the tag ':merge'` on a real file, reporting a YAML
        error where it had been asked about a duplicate.
        """
        config = _load(
            tmp_path,
            """\
            profiles:
              alpha: &base
                auth:
                  bearer_token_env: TOK
                backends:
                  wiki:
                    url: https://wiki.example/mcp
              beta:
                <<: *base
                backends:
                  other:
                    url: https://other.example/mcp
            """,
            monkeypatch,
        )
        profiles = config.profiles
        assert set(profiles) == {"alpha", "beta"}
        # The override won, which is what the merge key is for.
        assert set(profiles["beta"].backends) == {"other"}

    def test_a_shared_anchor_reached_twice_is_scanned_once(self) -> None:
        """An alias resolves to the SAME node, so a shared anchor is reachable
        by several paths. Visiting it per path would report its keys twice."""
        assert (
            duplicate_keys(
                textwrap.dedent(
                    """\
                    common: &shared
                      timeout_seconds: 30
                    one:
                      <<: *shared
                    two:
                      <<: *shared
                    """
                )
            )
            == []
        )


class TestNotOurJob:
    def test_a_syntax_error_is_left_to_safe_load(self) -> None:
        """`safe_load` already reports it, with a message that is careful about
        quoting source lines (a line here can hold a secret). Returning nothing
        keeps one error for one problem."""
        assert duplicate_keys("profiles:\n  alpha: [unclosed\n") == []

    def test_an_empty_file_is_not_a_duplicate(self) -> None:
        assert duplicate_keys("") == []


class TestProfileLintReportsItToo:
    """The command an operator reaches for first has to agree with the loader.

    A lint that comes back clean on a file the gateway will refuse to start on
    is worse than no lint, and that is not hypothetical: I ran `profile_lint`
    on lotor's config, read "0 findings", and deployed a file with two
    `defense:` blocks.
    """

    def test_the_lint_names_the_key_and_the_line(self, tmp_path: Path) -> None:
        path = tmp_path / "profiles.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                profiles:
                  alpha:
                    auth:
                      bearer_token_env: TOK
                    defense:
                      enforcement: block
                    defense:
                      enforcement: flag
                """
            ),
            encoding="utf-8",
        )

        codes = [f.code for f in lint_file(path)]
        assert "duplicate-key" in codes

        (finding,) = [f for f in lint_file(path) if f.code == "duplicate-key"]
        assert "'defense'" in finding.message
        assert "line 7" in finding.message, finding.message

    def test_a_clean_file_reports_no_duplicate_finding(self, tmp_path: Path) -> None:
        path = tmp_path / "profiles.yaml"
        path.write_text(ONE_GOOD_PROFILE, encoding="utf-8")
        assert [f for f in lint_file(path) if f.code == "duplicate-key"] == []
