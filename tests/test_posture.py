"""Startup containment checks (#268)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from trentina import posture
from trentina.errors import ConfigError

if TYPE_CHECKING:
    from pathlib import Path

HARDENED_STATUS = "Name:\tpython\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\nSeccomp:\t2\n"
OPEN_STATUS = "Name:\tpython\nNoNewPrivs:\t0\nCapEff:\t00000000a80425fb\nSeccomp:\t0\n"


def _proc(tmp_path: Path, status: str, environ: bytes = b"PATH=/usr/bin\0") -> Path:
    (tmp_path / "status").write_text(status)
    (tmp_path / "environ").write_bytes(environ)
    return tmp_path


@pytest.fixture
def contained_fs() -> object:
    """Read-only rootfs, safe path and no writable sys.path entry."""

    class _Vfs:
        f_flag = posture._ST_RDONLY

    with (
        patch.object(posture.os, "statvfs", return_value=_Vfs()),
        patch.object(posture.os, "access", return_value=False),
        patch.object(posture, "sys") as fake_sys,
    ):
        fake_sys.flags.safe_path = True
        fake_sys.path = ["/usr/lib/python3.14"]
        yield


@pytest.mark.usefixtures("contained_fs")
def test_hardened_process_has_no_gaps(tmp_path: Path) -> None:
    assert posture.inspect(_proc(tmp_path, HARDENED_STATUS)).gaps == []


@pytest.mark.usefixtures("contained_fs")
def test_each_kernel_gap_is_named(tmp_path: Path) -> None:
    gaps = posture.inspect(_proc(tmp_path, OPEN_STATUS)).gaps
    assert gaps == ["no_new_privs_off", "capabilities_held", "seccomp_off"]


def test_import_path_and_rootfs_gaps(tmp_path: Path) -> None:
    class _Vfs:
        f_flag = 0

    with (
        patch.object(posture.os, "statvfs", return_value=_Vfs()),
        patch.object(posture.os, "access", return_value=True),
        patch.object(posture, "sys") as fake_sys,
    ):
        fake_sys.flags.safe_path = False
        fake_sys.path = [str(tmp_path)]
        gaps = posture.inspect(_proc(tmp_path, HARDENED_STATUS)).gaps
    assert gaps == ["cwd_on_import_path", "import_path_writable", "rootfs_writable"]


@pytest.mark.usefixtures("contained_fs")
def test_secret_in_initial_environment_is_named_not_valued(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    proc = _proc(tmp_path, HARDENED_STATUS, b"PATH=/x\0OPENROUTER_API_KEY=sk-canary-value\0")
    with caplog.at_level(logging.WARNING):
        result = posture.check_startup_posture(proc)
    assert result.env_secrets == ["OPENROUTER_API_KEY"]
    assert "secret_in_environment" in result.gaps
    assert "OPENROUTER_API_KEY" in caplog.text
    assert "sk-canary-value" not in caplog.text


@pytest.mark.usefixtures("contained_fs")
def test_require_hardened_refuses_to_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
    with pytest.raises(ConfigError, match="no_new_privs_off"):
        posture.check_startup_posture(_proc(tmp_path, OPEN_STATUS))
    # And a contained process starts.
    assert posture.check_startup_posture(_proc(tmp_path, HARDENED_STATUS)).gaps == []


def test_no_proc_is_unverifiable_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert posture.inspect(tmp_path / "absent").gaps == ["unverifiable"]
    monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
    with pytest.raises(ConfigError, match="unverifiable"):
        posture.check_startup_posture(tmp_path / "absent")
    with pytest.raises(ConfigError, match="unverifiable"):
        posture.check_secret_sources({"X"}, tmp_path / "absent")


@pytest.mark.parametrize(
    ("name", "attr"),
    [
        ("GEMINI_API_KEY", "api_key"),
        ("OPENAI_API_KEY", "openai_api_key"),
        ("ANTHROPIC_API_KEY", "anthropic_api_key"),
        ("OPENROUTER_API_KEY", "openrouter_api_key"),
    ],
)
def test_llm_keys_take_a_file_form_that_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, attr: str
) -> None:
    from trentina.config import Config

    secret = tmp_path / "key"
    secret.write_text("from-file\n")
    secret.chmod(0o600)
    monkeypatch.setenv(name, "from-env")
    monkeypatch.setenv(f"{name}_FILE", str(secret))
    value = getattr(Config(), attr)
    assert (value if isinstance(value, str) else value.get_secret_value()) == "from-file"


@pytest.mark.usefixtures("contained_fs")
def test_secret_sources_cover_names_configuration_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A profile's ${VAR} or a bridge token is checked once it has been read."""
    proc = _proc(tmp_path, HARDENED_STATUS, b"BACKEND_TOKEN=x\0BRIDGE_TOKEN=y\0")
    result = posture.check_secret_sources({"BACKEND_TOKEN", "BRIDGE_TOKEN", "UNSET"}, proc)
    assert result.env_secrets == ["BACKEND_TOKEN", "BRIDGE_TOKEN"]
    monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
    with pytest.raises(ConfigError, match="secret_in_environment"):
        posture.check_secret_sources({"BACKEND_TOKEN"}, proc)
    assert posture.check_secret_sources({"UNSET"}, proc).gaps == []


def test_read_secret_env_records_every_name(monkeypatch: pytest.MonkeyPatch) -> None:
    from trentina.gateway import loader

    monkeypatch.setattr(loader, "_secret_env_names", set())
    loader.read_secret_env("SOME_PROFILE_SECRET")
    loader.read_secret_env("SOME_STARTUP_SECRET", record=False)
    assert loader.secret_env_names() == {"SOME_PROFILE_SECRET", "SOME_STARTUP_SECRET"}


def test_writable_zip_on_import_path_is_a_gap(tmp_path: Path) -> None:
    archive = tmp_path / "lib.zip"
    archive.write_bytes(b"PK")
    with patch.object(posture, "sys") as fake_sys:
        fake_sys.path = [str(archive)]
        assert posture._writable_import_path()


@pytest.mark.parametrize(("transport", "checked"), [("stdio", False), ("streamable-http", True)])
def test_entrypoint_checks_network_transports_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, transport: str, checked: bool
) -> None:
    import trentina as pkg
    from trentina import server

    class _RefusedError(Exception):
        pass

    def _refuse() -> None:
        raise _RefusedError

    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "q.db"))
    monkeypatch.delenv("TRENTINA_GATEWAY_ENABLED", raising=False)
    monkeypatch.setattr(posture, "check_startup_posture", _refuse)
    monkeypatch.setattr(server.mcp, "run", lambda **_kw: None)
    monkeypatch.setattr("sys.argv", ["trentina", "--transport", transport, "--no-dbus"])
    if checked:
        with pytest.raises(_RefusedError):
            pkg.main()
    else:
        pkg.main()


def test_missing_import_entry_under_writable_parent_is_a_gap(tmp_path: Path) -> None:
    with patch.object(posture, "sys") as fake_sys:
        fake_sys.path = [str(tmp_path / "not" / "yet")]
        assert posture._writable_import_path()


def test_bridge_run_checks_posture_before_running(monkeypatch: pytest.MonkeyPatch) -> None:
    from trentina.bridge import main as bridge_main

    class _RefusedError(Exception):
        pass

    calls: list[str] = []

    def _refuse(*_args: object) -> None:
        calls.append("checked")
        raise _RefusedError

    monkeypatch.setattr(bridge_main.BridgeSettings, "from_env", staticmethod(object))
    monkeypatch.setattr(posture, "check_startup_posture", _refuse)
    monkeypatch.setattr(bridge_main.asyncio, "run", lambda *_a: calls.append("ran"))
    with pytest.raises(_RefusedError):
        bridge_main.main(["run"])
    assert calls == ["checked"]


def test_ready_to_serve_checks_configured_secret_names(monkeypatch: pytest.MonkeyPatch) -> None:
    import trentina as pkg
    from trentina.gateway import envscrub, loader

    seen: list[set[str]] = []
    monkeypatch.setattr(loader, "_secret_env_names", {"BACKEND_TOKEN", "OPENROUTER_API_KEY"})
    monkeypatch.setattr(posture, "check_secret_sources", lambda names: seen.append(set(names)))
    monkeypatch.setattr(pkg, "_warm_classifier", lambda: None)
    monkeypatch.setattr(envscrub, "scrub_startup_secrets", lambda _names: [])
    pkg._ready_to_serve({})
    # The fixed names were checked at startup; this adds the rest, including
    # the approval hash, now read before the check rather than per request.
    assert seen == [{"BACKEND_TOKEN", "TRENTINA_APPROVAL_PASSWORD_HASH"}]


def test_ready_to_serve_fails_on_an_unreadable_approval_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#767: a broken _FILE is a startup failure, not a surprise at the first approval."""
    import trentina as pkg
    from trentina.gateway.errors import ProfileConfigError

    monkeypatch.setenv("TRENTINA_APPROVAL_PASSWORD_HASH_FILE", str(tmp_path / "missing"))
    monkeypatch.setattr(pkg, "_warm_classifier", lambda: None)
    with pytest.raises(ProfileConfigError, match="TRENTINA_APPROVAL_PASSWORD_HASH_FILE"):
        pkg._ready_to_serve({})


def test_otlp_headers_take_a_file_form_that_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#767: the collector credential has a _FILE form like every other secret."""
    from trentina.config import Config
    from trentina.gateway.errors import ProfileConfigError

    secret = tmp_path / "otlp-headers"
    secret.write_text("Authorization=Basic%20ZnJvbS1maWxl\n")
    monkeypatch.setenv("TRENTINA_OTLP_HEADERS", "Authorization=Basic%20ZnJvbS1lbnY=")
    monkeypatch.setenv("TRENTINA_OTLP_HEADERS_FILE", str(secret))
    assert Config().otlp_headers == {"Authorization": "Basic ZnJvbS1maWxl"}
    assert "TRENTINA_OTLP_HEADERS" in posture.FILE_FORM_SECRETS
    monkeypatch.setenv("TRENTINA_OTLP_HEADERS_FILE", str(tmp_path / "missing"))
    with pytest.raises(ProfileConfigError, match="TRENTINA_OTLP_HEADERS_FILE"):
        _ = Config().otlp_headers


@pytest.mark.usefixtures("contained_fs")
def test_inline_secret_count_accumulates_names_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#767: both passes feed the count the health probe reports; a secret
    found twice counts once."""
    monkeypatch.setattr(posture, "_inline", set())
    proc = _proc(tmp_path, HARDENED_STATUS, b"OPENAI_API_KEY=x\0BRIDGE_TOKEN=y\0")
    posture.check_startup_posture(proc)
    assert posture.inline_secret_count() == 1
    posture.check_secret_sources({"BRIDGE_TOKEN", "OPENAI_API_KEY", "UNSET"}, proc)
    assert posture.inline_secret_count() == 2
