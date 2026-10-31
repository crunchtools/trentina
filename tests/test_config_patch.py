"""config_patch (#633): edit profiles.yaml without rewriting what you did not touch.

``profiles.yaml`` is a file a human maintains, reviews in a diff and keeps in
git. A write that reflowed a list or dropped a comment would turn one intended
change into an unreadable diff, and on lotor it would show up as git drift in
sections nobody edited. So the property under test is not "the YAML is
equivalent" but "the bytes are the same".
"""

from __future__ import annotations

import difflib
import pathlib
import time

import pytest
import yaml

from trentina.gateway import config_patch as cp

REPO = pathlib.Path(__file__).resolve().parent.parent

#: Every profiles.yaml the repo ships, which is the only corpus of real ones.
REAL_FILES = ["docs/demo/profiles.yaml", "examples/profiles-agent1.yaml"]

COMMENTED = """\
# The gateway's profiles.
profiles:
  myagent:
    # This agent may read mail and draft, but never send.
    auth:
      bearer_token_env: TOKEN  # from the unit file
    backends:
      web:
        url: "internal://web"
        tools_allow:
          - fetch_tool
          - read_tool
    defense:
      enforcement: block
"""


class TestRoundTrip:
    @pytest.mark.parametrize("name", REAL_FILES)
    def test_a_real_file_survives_a_no_op_byte_for_byte(self, name: str) -> None:
        text = (REPO / name).read_text(encoding="utf-8")
        assert cp.round_trips(text)

    def test_a_comment_above_an_edited_key_survives(self) -> None:
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "defense", "enforcement"), "redact")

        assert "# This agent may read mail and draft, but never send." in out
        assert "# The gateway's profiles." in out
        assert "enforcement: redact" in out

    def test_an_end_of_line_comment_survives(self) -> None:
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "defense", "enforcement"), "flag")
        assert "bearer_token_env: TOKEN  # from the unit file" in out

    def test_an_untouched_list_is_not_reflowed(self) -> None:
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "defense", "enforcement"), "flag")
        assert "          - fetch_tool\n          - read_tool\n" in out

    def test_only_the_edited_line_changes(self) -> None:
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "defense", "enforcement"), "flag")
        changed = [
            (a, b) for a, b in zip(COMMENTED.splitlines(), out.splitlines(), strict=True) if a != b
        ]
        assert changed == [("      enforcement: block", "      enforcement: flag")]


class TestSetting:
    def test_it_creates_intermediate_mappings(self) -> None:
        out = cp.set_at(
            COMMENTED,
            ("profiles", "myagent", "backends", "lotor", "federated", "primary_key_name"),
            "edge-to-lotor",
        )
        assert (
            cp.get_at(
                out, ("profiles", "myagent", "backends", "lotor", "federated", "primary_key_name")
            )
            == "edge-to-lotor"
        )

    def test_a_list_is_replaced_whole(self) -> None:
        path = ("profiles", "myagent", "backends", "web", "tools_allow")
        out = cp.set_at(COMMENTED, path, ["fetch_tool"])
        assert list(cp.get_at(out, path)) == ["fetch_tool"]

    def test_a_path_through_a_scalar_is_refused(self) -> None:
        """Overwriting a scalar because a path ran through it would discard it
        silently."""
        with pytest.raises(cp.ConfigPatchError, match="mapping"):
            cp.set_at(COMMENTED, ("profiles", "myagent", "defense", "enforcement", "deeper"), 1)

    def test_the_result_is_still_loadable(self) -> None:
        out = cp.set_at(COMMENTED, ("profiles", "other", "defense", "enforcement"), "block")
        assert cp.get_at(out, ("profiles", "other", "defense", "enforcement")) == "block"


class TestUnsetting:
    def test_it_removes_a_key(self) -> None:
        path = ("profiles", "myagent", "defense", "enforcement")
        out = cp.unset_at(COMMENTED, path)
        with pytest.raises(cp.ConfigPatchError):
            cp.get_at(out, path)

    def test_removing_what_is_not_there_is_an_error(self) -> None:
        """A typo in a path must not read as a successful no-op."""
        with pytest.raises(cp.ConfigPatchError, match="not set"):
            cp.unset_at(COMMENTED, ("profiles", "myagent", "defence"))


class TestPaths:
    @pytest.mark.parametrize(
        "key",
        ["a.b", "a/b", "../etc", "", "x" * 65, "a b", "a:b"],
    )
    def test_a_segment_that_is_not_a_key_is_refused(self, key: str) -> None:
        with pytest.raises(cp.ConfigPatchError, match="not a config key"):
            cp.set_at(COMMENTED, ("profiles", key), 1)

    def test_an_empty_path_is_refused(self) -> None:
        with pytest.raises(cp.ConfigPatchError, match="at least one key"):
            cp.set_at(COMMENTED, (), 1)


class TestBadInput:
    def test_invalid_yaml_is_refused_without_quoting_the_file(self) -> None:
        """The parser's own message quotes the offending line, which is file
        content and not ours to echo (#262)."""
        with pytest.raises(cp.ConfigPatchError) as failed:
            cp.load("profiles:\n  a: [unclosed\n  secret: hunter2\n")
        assert "hunter2" not in str(failed.value)
        assert failed.value.__cause__ is None

    def test_an_empty_file_loads_as_an_empty_mapping(self) -> None:
        assert cp.dump(cp.load("   \n"), like="   \n") in ("{}\n", "")


class TestYamlOneOneStrings:
    """Writing is ruamel (YAML 1.2) and reading is pyyaml (YAML 1.1), and they
    disagree about bare `yes`, `no`, `on`, `off` and `1:30`. A value set here
    has to mean the same thing to the reader, or a tool named `no` comes back
    as `False`."""

    @pytest.mark.parametrize("value", ["yes", "no", "on", "off", "1:30"])
    def test_a_string_the_reader_would_reinterpret_is_quoted(self, value: str) -> None:
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "token"), value)
        assert yaml.safe_load(out)["profiles"]["myagent"]["token"] == value

    @pytest.mark.parametrize("value", ["plain", "null", "~", "True", "2026-10-31", ""])
    def test_a_string_that_round_trips_is_left_bare(self, value: str) -> None:
        """Nothing is noisily quoted: only what would actually change."""
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "token"), value)
        assert yaml.safe_load(out)["profiles"]["myagent"]["token"] == value

    def test_it_reaches_strings_nested_in_a_mapping_or_list(self) -> None:
        written = {"tools_allow": ["no", "yes"], "mode": "off"}
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "backends", "b"), written)
        assert yaml.safe_load(out)["profiles"]["myagent"]["backends"]["b"] == written

    @pytest.mark.parametrize("key", ["no", "on", "yes", "off"])
    def test_a_mapping_key_the_reader_would_reinterpret_is_quoted(self, key: str) -> None:
        """A backend or peer named `no` is a valid config key, and written bare
        it comes back as the boolean False — a different key than the one
        asked for."""
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "backends"), {key: {"url": "x"}})
        assert list(yaml.safe_load(out)["profiles"]["myagent"]["backends"]) == [key]

    def test_non_strings_are_untouched(self) -> None:
        out = cp.set_at(COMMENTED, ("profiles", "myagent", "n"), True)
        assert yaml.safe_load(out)["profiles"]["myagent"]["n"] is True


OFFSET_ZERO = """\
# A list style where the dash sits under its key.
profiles:
  myagent:
    backends:
      web:
        url: "internal://web"
        tools_allow:
        - fetch_tool
        - read_tool
"""

MIXED = """\
profiles:
  a:
    one:
    - x
  b:
    two:
      - y
"""


class TestSequenceStyle:
    """ruamel emits ONE sequence style per document, and real files differ. The
    first production config this was pointed at indented 882 of its 885 lists
    with the dash under its key; the repo's own examples indent it two further.
    Guessing turns a one-key edit into a diff over the whole file."""

    @pytest.mark.parametrize("text", [COMMENTED, OFFSET_ZERO])
    def test_both_styles_round_trip(self, text: str) -> None:
        assert cp.round_trips(text)

    def test_a_write_keeps_the_style_it_found(self) -> None:
        out = cp.set_at(OFFSET_ZERO, ("profiles", "myagent", "defense", "enforcement"), "block")
        assert "        - fetch_tool\n        - read_tool\n" in out

    def test_a_file_of_mixed_styles_does_not_round_trip(self) -> None:
        """No single setting reproduces it, so the write path refuses instead of
        reformatting the lists it did not touch."""
        assert not cp.round_trips(MIXED)

    def test_a_real_repo_file_round_trips(self) -> None:
        text = (REPO / "docs/demo/profiles.yaml").read_text(encoding="utf-8")
        assert cp.round_trips(text)


def test_style_detection_is_linear_in_a_long_list() -> None:
    """A backward scan per item is quadratic in the list length, and a real
    config has lists of several hundred tool names."""
    big = "profiles:\n  a:\n    tools_allow:\n" + "".join(f"    - tool_{i}\n" for i in range(4000))

    started = time.perf_counter()
    assert cp._sequence_offset(big) == 0
    assert time.perf_counter() - started < 1.0


#: The shape lotor's live config actually has, and the reason `normalize`
#: exists: machine-written `&idNNN` anchors that ruamel renumbers, hand-named
#: anchors beside them, a merge key, an alias carrying a trailing comment, and
#: one sequence indented against the file's own majority.
LOTOR_SHAPED = """\
# The gateway's profiles.
defaults: &id001
  enforcement: block  # the default posture
fences: &repo_fence
  owner: crunchtools
profiles:
  one:
    auth:
      bearer_token_env: ONE
    defense: *id001  # inherited, deliberately
    backends:
      web:
        url: "internal://web"
        tools_allow:
        - fetch_tool
        - read_tool
  two:
    <<: *id001
    auth:
      bearer_token_env: TWO
    fences: *repo_fence
    client_egress:
      hosts:
          - example.com
          - example.org
"""


class TestNormalize:
    def test_the_lotor_shape_does_not_round_trip_to_begin_with(self) -> None:
        """Otherwise the rest of this class proves nothing."""
        assert cp.round_trips(LOTOR_SHAPED) is False

    def test_normalizing_makes_it_round_trip(self) -> None:
        candidate, _ = cp.normalized(LOTOR_SHAPED)
        assert cp.round_trips(candidate) is True

    def test_it_is_idempotent(self) -> None:
        """A second pass must be a no-op, or `normalize` would be a treadmill."""
        once, _ = cp.normalized(LOTOR_SHAPED)
        assert cp.dump(cp.load(once), like=once) == once

    def test_the_meaning_is_unchanged(self) -> None:
        candidate, _ = cp.normalized(LOTOR_SHAPED)
        assert yaml.safe_load(candidate) == yaml.safe_load(LOTOR_SHAPED)

    def test_the_merge_key_survives(self) -> None:
        candidate, _ = cp.normalized(LOTOR_SHAPED)
        assert yaml.safe_load(candidate)["profiles"]["two"]["enforcement"] == "block"

    def test_every_comment_survives(self) -> None:
        candidate, _ = cp.normalized(LOTOR_SHAPED)
        for comment in ("# The gateway's profiles.", "# the default posture", "# inherited"):
            assert comment in candidate

    def test_it_reports_what_it_moved(self) -> None:
        _, reshaped = cp.normalized(LOTOR_SHAPED)
        assert reshaped["lines"] > 0
        assert reshaped["hunks"] > 0

    def test_a_write_after_normalizing_is_a_small_diff(self) -> None:
        """The whole point: one key changed should read as one key changed."""
        candidate, _ = cp.normalized(LOTOR_SHAPED)
        after = cp.set_at(candidate, ("profiles", "one", "auth", "bearer_token_env"), "ONE_V2")
        changed = [
            line
            for line in difflib.unified_diff(
                candidate.splitlines(), after.splitlines(), n=0, lineterm=""
            )
            if line[:1] in "+-" and line[:3] not in ("+++", "---")
        ]
        assert len(changed) == 2  # the old line and the new one, nothing else

    def test_a_file_that_already_round_trips_normalizes_to_itself(self) -> None:
        """The tool refuses this case; the text layer just has nothing to do."""
        candidate, reshaped = cp.normalized(COMMENTED)
        assert candidate == COMMENTED
        assert reshaped == {"lines": 0, "hunks": 0}

    def test_a_duplicate_key_is_refused_by_the_parser(self) -> None:
        """ruamel raises on a duplicate key, which is the right refusal: the
        file says two things and nothing here may choose between them."""
        with pytest.raises(cp.ConfigPatchError):
            cp.normalized("profiles:\n  one:\n    a: 1\n    a: 2\n")
