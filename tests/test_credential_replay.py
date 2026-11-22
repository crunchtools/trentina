"""trentina-credential-replay: what the credential guard would refuse (#862)."""

from __future__ import annotations

import io
import json
import sqlite3
from typing import TYPE_CHECKING, Any

import pytest

from trentina.credential_replay import main

if TYPE_CHECKING:
    from pathlib import Path

# Built at runtime so no key-shaped literal sits in the source.
KEY = "gh" + "p_" + "a" * 36
AWS = "AK" + "IA" + "IOSFODNN7EXAMPLE"

PROFILES = """\
profiles:
  exedore-max:
    backends:
      github:
        url: http://github:8000/mcp
        credentials_allowed:
          update_issue: [github_token]
      aws:
        url: http://aws:8000/mcp
  longform:
    short_names: false
    backends:
      github:
        url: http://github:8000/mcp
"""


@pytest.fixture
def profiles(tmp_path: Path) -> Path:
    path = tmp_path / "profiles.yaml"
    path.write_text(PROFILES)
    return path


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "gw.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE tool_names (profile, issued, backend, tool, issued_at)")
    conn.executemany(
        "INSERT INTO tool_names VALUES (?, ?, ?, ?, 'now')",
        [
            ("exedore-max", "create_issue", "github", "create_issue"),
            ("exedore-max", "update_issue", "github", "update_issue"),
            ("exedore-max", "put_object", "aws", "put_object"),
        ],
    )
    conn.commit()
    conn.close()
    return path


def write(tmp_path: Path, *records: Any) -> Path:
    path = tmp_path / "calls.jsonl"
    path.write_text("\n".join(r if isinstance(r, str) else json.dumps(r) for r in records) + "\n")
    return path


def run(
    capsys: pytest.CaptureFixture[str], profiles: Path, db: Path, *argv: str
) -> tuple[int, str]:
    code = main([*argv, "--profiles", str(profiles), "--db", str(db)])
    return code, capsys.readouterr().out


def direct(tool: str, text: str, backend: str = "github") -> dict[str, Any]:
    return {
        "profile": "exedore-max",
        "backend": backend,
        "tool": tool,
        "arguments": {"body": text},
    }


def test_direct_shape_yaml(tmp_path, profiles, db, capsys):
    f = write(tmp_path, direct("create_issue", KEY), direct("create_issue", KEY), direct("x", "hi"))
    code, out = run(capsys, profiles, db, str(f))
    assert code == 1
    assert "# profile: exedore-max  (3 calls replayed, 2 would be refused, 0 unresolved)" in out
    assert (
        "github:\n    credentials_allowed:\n      create_issue: [github_token]   # 2 calls" in out
    )


def test_no_value_ever_printed(tmp_path, profiles, db, capsys):
    f = write(tmp_path, direct("create_issue", KEY), direct("put_object", AWS, "aws"))
    for extra in ([], ["--json"], ["--all"]):
        _, out = run(capsys, profiles, db, str(f), *extra)
        assert KEY not in out
        assert AWS not in out
        assert "body" not in out


def test_served_name_shape(tmp_path, profiles, db, capsys):
    f = write(tmp_path, {"profile": "exedore-max", "name": "put_object", "arguments": {"k": AWS}})
    code, out = run(capsys, profiles, db, str(f), "--json")
    assert code == 1
    doc = json.loads(out)
    assert doc["profiles"]["exedore-max"]["needs"] == {"aws": {"put_object": {"aws_access_key": 1}}}


def test_long_form_name_when_short_names_off(tmp_path, profiles, db, capsys):
    f = write(tmp_path, {"profile": "longform", "name": "github__make", "arguments": {"k": KEY}})
    code, out = run(capsys, profiles, db, str(f), "--json")
    assert code == 1
    assert json.loads(out)["profiles"]["longform"]["needs"] == {
        "github": {"make": {"github_token": 1}}
    }


def transcript(*blocks: dict[str, Any]) -> dict[str, Any]:
    return {"type": "assistant", "message": {"content": list(blocks)}}


def test_transcript_shape(tmp_path, profiles, db, capsys):
    f = write(
        tmp_path,
        transcript(
            {"type": "text", "text": "hi"},
            {"type": "tool_use", "name": "mcp__trentina__create_issue", "input": {"b": KEY}},
            {"type": "tool_use", "name": "mcp__other__create_issue", "input": {"b": KEY}},
            {"type": "tool_use", "name": "Bash", "input": {"command": KEY}},
        ),
        {"type": "user", "message": {"content": "x"}},
    )
    code, out = run(capsys, profiles, db, str(f), "--profile", "exedore-max")
    assert code == 1
    assert "(1 calls replayed, 1 would be refused, 0 unresolved)" in out
    assert "1 line(s) skipped" in out


def test_transcript_server_flag(tmp_path, profiles, db, capsys):
    f = write(
        tmp_path,
        transcript({"type": "tool_use", "name": "mcp__other__put_object", "input": {"b": AWS}}),
    )
    code, out = run(
        capsys, profiles, db, str(f), "--profile", "exedore-max", "--mcp-server", "other"
    )
    assert code == 1
    assert "aws:" in out


def test_transcript_without_profile_is_skipped(tmp_path, profiles, db, capsys):
    f = write(
        tmp_path,
        transcript({"type": "tool_use", "name": "mcp__trentina__put_object", "input": {"b": AWS}}),
    )
    code, out = run(capsys, profiles, db, str(f))
    assert code == 0
    assert "1 line(s) skipped" in out


def test_profile_flag_fills_missing_profile(tmp_path, profiles, db, capsys):
    rec = {"backend": "aws", "tool": "put_object", "arguments": {"k": AWS}}
    code, _ = run(capsys, profiles, db, str(write(tmp_path, rec)), "--profile", "exedore-max")
    assert code == 1


def test_current_vs_all(tmp_path, profiles, db, capsys):
    f = write(tmp_path, direct("update_issue", KEY))
    code, out = run(capsys, profiles, db, str(f))  # --current is the default
    assert code == 0
    assert "credentials_allowed:" not in out
    code, out = run(capsys, profiles, db, str(f), "--current")
    assert code == 0
    code, out = run(capsys, profiles, db, str(f), "--all")
    assert code == 1
    assert "update_issue: [github_token]   # 1 call\n" in out + "\n"


def test_clean_run_exits_zero(tmp_path, profiles, db, capsys):
    code, out = run(capsys, profiles, db, str(write(tmp_path, direct("create_issue", "hello"))))
    assert code == 0
    assert "(1 calls replayed, 0 would be refused, 0 unresolved)" in out


def test_skipped_and_unresolved(tmp_path, profiles, db, capsys):
    f = write(
        tmp_path,
        "not json",
        '["list"]',
        {"profile": "exedore-max", "arguments": {}},
        {"profile": "exedore-max", "name": "nope", "arguments": {"k": KEY}},
        {"profile": "ghost", "backend": "github", "tool": "t", "arguments": {}},
    )
    code, out = run(capsys, profiles, db, str(f), "--json")
    assert code == 0
    doc = json.loads(out)
    assert doc["skipped"] == 3
    assert doc["profiles"]["exedore-max"]["unresolved"] == 1
    assert doc["profiles"]["ghost"]["unresolved"] == 1


def test_stdin(profiles, db, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(direct("create_issue", KEY)) + "\n"))
    code, _ = run(capsys, profiles, db, "-")
    assert code == 1


def test_missing_profiles_file_exits_two(tmp_path, db, capsys):
    f = write(tmp_path, direct("create_issue", "x"))
    assert main([str(f), "--profiles", str(tmp_path / "none.yaml"), "--db", str(db)]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_missing_input_exits_two(tmp_path, profiles, db):
    assert main([str(tmp_path / "none.jsonl"), "--profiles", str(profiles), "--db", str(db)]) == 2


def test_unknown_profile_flag_exits_two(tmp_path, profiles, db):
    f = write(tmp_path, direct("create_issue", "x"))
    assert main([str(f), "--profile", "ghost", "--profiles", str(profiles), "--db", str(db)]) == 2


def test_bad_credentials_allowed_exits_two(tmp_path, db, capsys):
    p = tmp_path / "p.yaml"
    p.write_text("profiles:\n  a:\n    backends:\n      b:\n        credentials_allowed: [nope]\n")
    f = write(tmp_path, direct("t", "x"))
    assert main([str(f), "--profiles", str(p), "--db", str(db)]) == 2
    assert "unknown kind" in capsys.readouterr().err


def test_profiles_is_required(tmp_path, db):
    f = write(tmp_path, direct("create_issue", KEY))
    with pytest.raises(SystemExit) as exc:
        main([str(f), "--db", str(db)])
    assert exc.value.code == 2


def test_an_unreadable_db_exits_two(tmp_path, profiles, capsys):
    f = write(tmp_path, {"profile": "exedore-max", "name": "create_issue", "arguments": {"q": KEY}})
    assert main([str(f), "--profiles", str(profiles), "--db", str(tmp_path / "none.db")]) == 2
    assert "tool_names" in capsys.readouterr().err


def test_a_yaml_error_names_the_line_not_the_text(tmp_path, db, capsys):
    p = tmp_path / "p.yaml"
    p.write_text("profiles:\n  a: [unclosed " + KEY + "\n")
    f = write(tmp_path, direct("t", "x"))
    assert main([str(f), "--profiles", str(p), "--db", str(db)]) == 2
    err = capsys.readouterr().err
    assert "line" in err
    assert KEY not in err
