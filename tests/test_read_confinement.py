"""read_tool and dir_tool reach only what confinement admits (#261).

The incident path was ``read_tool /config/profiles.yaml``: every profile's
topology and two credentials, delivered. These tests pin the rule that
closed it: roots when configured, refuse-all behind a live gateway without
them, a denylist no root overrides, and an open that refuses a path swapped
between the check and the read.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.refusal_shape import refused
from trentina import config as config_mod
from trentina.errors import BlockedSourceError, ConfigError, FileReadError
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.modes import Mode
from trentina.tools import confine
from trentina.tools import read as read_mod
from trentina.tools.dir import MAX_DIR_ENTRIES, list_dir
from trentina.tools.read import MAX_FILE_SIZE, _read_confined

GATEWAY_YAML = """\
profiles:
  alpha:
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends: {}
"""


def _set_roots(monkeypatch: pytest.MonkeyPatch, *roots: Path | str) -> None:
    if roots:
        monkeypatch.setenv("TRENTINA_READ_ROOTS", os.pathsep.join(str(r) for r in roots))
    else:
        monkeypatch.delenv("TRENTINA_READ_ROOTS", raising=False)
    config_mod._config = None


def _refusal(path: str | Path) -> FileReadError:
    with pytest.raises(FileReadError) as caught:
        _read_confined(str(path))
    return caught.value


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """One read root holding one readable file, with a sibling outside it."""
    inside = tmp_path / "root"
    inside.mkdir()
    (inside / "notes.txt").write_text("inside the root\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside the root\n", encoding="utf-8")
    _set_roots(monkeypatch, inside)
    return inside


@pytest.fixture
def live_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A registered gateway config, the way a running gateway has one."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "alpha-secret")
    gw = tmp_path / "gw"
    gw.mkdir()
    path = gw / "profiles.yaml"
    path.write_text(GATEWAY_YAML, encoding="utf-8")
    register_active_config(path, load_profiles(path), {})
    return path


class TestRoots:
    def test_file_in_root_is_read(self, root: Path) -> None:
        content, resolved = _read_confined(str(root / "notes.txt"))
        assert content == "inside the root\n"
        assert resolved == str(root / "notes.txt")

    def test_dotdot_escape_is_refused(self, root: Path) -> None:
        assert _refusal(root / ".." / "outside.txt").reason == "outside_read_roots"

    def test_symlink_out_of_root_is_refused(self, root: Path) -> None:
        (root / "link.txt").symlink_to(root.parent / "outside.txt")
        assert _refusal(root / "link.txt").reason == "outside_read_roots"

    def test_symlink_to_proc_environ_is_denied(self, root: Path) -> None:
        (root / "env.txt").symlink_to("/proc/self/environ")
        assert _refusal(root / "env.txt").reason == "denied_path"

    def test_non_absolute_root_fails_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_READ_ROOTS", "relative/dir")
        with pytest.raises(ConfigError):
            config_mod.Config()


class TestDenylist:
    def test_proc_self_environ_is_denied_even_under_root_slash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch, "/")
        assert _refusal("/proc/self/environ").reason == "denied_path"

    @pytest.mark.parametrize(
        "path",
        ["/config/profiles.yaml", "/config/trentina-trust.json", "/data/quarantine.db"],
    )
    def test_gateway_config_and_state_are_denied_under_root_slash(
        self, path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # check() is the rule applied to a resolved path; these need not exist here.
        _set_roots(monkeypatch, "/")
        with pytest.raises(FileReadError) as caught:
            confine.check(Path(path))
        assert caught.value.reason == "denied_path"

    def test_trentina_state_dir_is_denied_inside_a_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = tmp_path / "state"
        state.mkdir()
        (state / "profiles.yaml").write_text("secret: x\n", encoding="utf-8")
        monkeypatch.setenv("QUARANTINE_DB", str(state / "trentina.db"))
        _set_roots(monkeypatch, tmp_path)
        assert _refusal(state / "profiles.yaml").reason == "denied_path"

    @pytest.mark.parametrize(
        ("env_name", "filename"),
        [("TRENTINA_PERIMETER_DB", "perimeter.db"), ("QUARANTINE_TRUST_CONFIG", "trust.json")],
    )
    def test_each_state_path_denies_its_own_dir(
        self, env_name: str, filename: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        own = tmp_path / env_name.lower()
        own.mkdir()
        (own / "secret.txt").write_text("secret\n", encoding="utf-8")
        monkeypatch.setenv(env_name, str(own / filename))
        _set_roots(monkeypatch, tmp_path)
        assert _refusal(own / "secret.txt").reason == "denied_path"

    def test_live_profiles_dir_is_denied_inside_a_root(
        self, tmp_path: Path, live_gateway: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch, tmp_path)
        assert _refusal(live_gateway).reason == confine.GATEWAY_REASON

    def test_refusal_names_no_path(self, root: Path) -> None:
        err = _refusal(root / ".." / "outside.txt")
        assert err.reason == "outside_read_roots"
        assert str(root.parent) not in str(err)
        assert "outside.txt" not in str(err)


class TestGatewayMode:
    def test_live_gateway_without_roots_refuses_everything(
        self, tmp_path: Path, live_gateway: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch)
        target = tmp_path / "plain.txt"
        target.write_text("anything\n", encoding="utf-8")
        assert _refusal(target).reason == confine.GATEWAY_REASON

    def test_live_gateway_with_roots_reads_inside_them(
        self, root: Path, live_gateway: Path
    ) -> None:
        assert _read_confined(str(root / "notes.txt"))[0] == "inside the root\n"

    async def test_dir_refused_behind_live_gateway_without_roots(
        self, tmp_path: Path, live_gateway: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch)
        with pytest.raises(BlockedSourceError) as caught:
            await list_dir(str(tmp_path), Mode.FLAG)
        assert caught.value.refusal["reason"] == f"confinement refused ({confine.GATEWAY_REASON})"


class TestStandalone:
    def test_no_roots_reads_a_tmp_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch)
        target = tmp_path / "plain.txt"
        target.write_text("standalone\n", encoding="utf-8")
        assert _read_confined(str(target))[0] == "standalone\n"

    def test_no_roots_still_denies_proc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_roots(monkeypatch)
        assert _refusal("/proc/self/environ").reason == "denied_path"


def _swap_before_open(monkeypatch: pytest.MonkeyPatch, swap: Callable[[], None]) -> None:
    """Run ``swap`` after the check and the stat, immediately before the open."""
    real_open = os.open

    def racing_open(path: Any, flags: int, *args: Any) -> int:
        swap()
        monkeypatch.setattr(confine.os, "open", real_open)
        return real_open(path, flags, *args)

    monkeypatch.setattr(confine.os, "open", racing_open)


class TestSwapAfterCheck:
    def test_final_component_swapped_for_symlink(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = root / "notes.txt"

        def swap() -> None:
            target.unlink()
            target.symlink_to("/proc/self/environ")

        _swap_before_open(monkeypatch, swap)
        assert _refusal(target).reason == "changed_during_read"

    def test_file_replaced_by_another(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = root / "notes.txt"

        def swap() -> None:
            # Created while the original still holds its inode, then renamed
            # over it: unlink-then-create can reuse the same inode number.
            replacement = root / "replacement.txt"
            replacement.write_text("a different inode\n", encoding="utf-8")
            os.replace(replacement, target)

        _swap_before_open(monkeypatch, swap)
        assert _refusal(target).reason == "changed_during_read"

    def test_intermediate_directory_swapped_for_symlink(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sub = root / "sub"
        sub.mkdir()
        (sub / "notes.txt").write_text("inside\n", encoding="utf-8")
        elsewhere = root.parent / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "notes.txt").write_text("outside\n", encoding="utf-8")

        def swap() -> None:
            sub.rename(root.parent / "moved")
            sub.symlink_to(elsewhere)

        _swap_before_open(monkeypatch, swap)
        assert _refusal(sub / "notes.txt").reason == "changed_during_read"

    def test_kernel_name_of_the_opened_fd_is_checked(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The post-open check stands on its own, whatever the inode compare saw."""
        monkeypatch.setattr(confine, "_opened_path", lambda fd: Path("/proc/self/environ"))
        assert _refusal(root / "notes.txt").reason == "denied_path"


class TestSwapIsARefusal:
    """#278: a swap caught mid-read is a refusal too, not a read failure."""

    async def test_changed_during_read_reaches_the_caller_as_a_refusal(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = root / "notes.txt"

        def swap() -> None:
            target.unlink()
            target.symlink_to("/proc/self/environ")

        _swap_before_open(monkeypatch, swap)
        with pytest.raises(BlockedSourceError) as caught:
            await read_mod.read_file(str(target), Mode.BLOCK)
        assert caught.value.refusal == {
            "reason": "confinement refused (changed_during_read)",
            "mode": "block",
            "flagged_by": "confinement",
            "alternatives": [],
        }

    def test_it_audits_as_blocked_defense(self) -> None:
        from trentina.gateway.errors import BackendCallError
        from trentina.outcomes import Outcome, classify_exception

        refusal = confine.refused(FileReadError("changed_during_read"), Mode.BLOCK)
        wrapped = BackendCallError("internal tool 'read_tool' call failed")
        wrapped.__cause__ = refusal
        assert classify_exception(wrapped) is Outcome.BLOCKED_DEFENSE

    async def test_other_read_failures_stay_read_failures(self, root: Path) -> None:
        (root / "blob.txt").write_bytes(b"\x00binary")
        with pytest.raises(FileReadError) as caught:
            await read_mod.read_file(str(root / "blob.txt"), Mode.BLOCK)
        assert caught.value.reason == "binary"


class TestFileGrowth:
    def test_file_grown_past_cap_after_fstat_is_refused(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = root / "notes.txt"
        real_open_confined = read_mod.open_confined

        def open_then_grow(path: str, kind: confine.FileKind) -> Any:
            opened = real_open_confined(path, kind)
            with target.open("ab") as fh:
                fh.write(b"x" * (MAX_FILE_SIZE + 1))
            return opened

        monkeypatch.setattr(read_mod, "open_confined", open_then_grow)
        assert _refusal(target).reason == "too_large"


class TestDirListing:
    async def test_too_many_entries_is_refused_without_listing_them_all(self, root: Path) -> None:
        big = root / "big"
        big.mkdir()
        for i in range(MAX_DIR_ENTRIES + 1):
            (big / f"f{i}.txt").touch()
        with pytest.raises(FileReadError) as caught:
            await list_dir(str(big), Mode.FLAG)
        assert caught.value.reason == "too_many_entries"

    async def test_dir_symlink_out_of_root_is_refused(self, root: Path) -> None:
        (root / "out").symlink_to(root.parent)
        with pytest.raises(BlockedSourceError) as caught:
            await list_dir(str(root / "out"), Mode.FLAG)
        assert caught.value.refusal["reason"] == "confinement refused (outside_read_roots)"

    async def test_file_is_not_a_directory(self, root: Path) -> None:
        with pytest.raises(FileReadError) as caught:
            await list_dir(str(root / "notes.txt"), Mode.FLAG)
        assert caught.value.reason == "not_a_directory"


class TestLexicalBeforeResolve:
    """#263: the path as written is judged before the filesystem is asked anything."""

    def test_a_missing_denied_path_is_denied_not_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch, "/")
        assert _refusal("/proc/no-such-entry/at-all").reason == "denied_path"

    def test_a_missing_path_outside_the_roots_is_outside_not_missing(self, root: Path) -> None:
        assert _refusal(root.parent / "no-such-file.txt").reason == "outside_read_roots"

    def test_nothing_is_resolved_for_a_lexically_denied_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch, "/")
        resolved: list[str] = []
        real_resolve = Path.resolve

        def recording_resolve(self: Path, *a: Any, **k: Any) -> Path:
            resolved.append(str(self))
            return real_resolve(self, *a, **k)

        monkeypatch.setattr(confine.Path, "resolve", recording_resolve)
        with pytest.raises(FileReadError):
            confine.confine("/config/../config/profiles.yaml")
        assert not [p for p in resolved if p.endswith("profiles.yaml")]

    def test_a_root_spelled_through_a_symlink_still_admits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """/home on a host where it is /var/home: the written root must admit."""
        real = tmp_path / "real"
        real.mkdir()
        (real / "notes.txt").write_text("via the link\n", encoding="utf-8")
        link = tmp_path / "link"
        link.symlink_to(real)
        _set_roots(monkeypatch, link)
        assert _read_confined(str(link / "notes.txt"))[0] == "via the link\n"

    def test_dotdot_through_a_symlink_is_checked_again_once_resolved(self, root: Path) -> None:
        """Lexically ``root/sub/../x`` is inside; really it is wherever sub points."""
        elsewhere = root.parent / "elsewhere"
        (elsewhere / "deep").mkdir(parents=True)
        (elsewhere / "secret.txt").write_text("outside\n", encoding="utf-8")
        (root / "sub").symlink_to(elsewhere / "deep")
        path = f"{root}/sub/../secret.txt"
        assert Path(os.path.normpath(path)).is_relative_to(root)
        assert _refusal(path).reason == "outside_read_roots"


async def _read_refusal(path: str | Path) -> str:
    """read_tool's refusal as the caller receives it, byte for byte."""
    with pytest.raises(BlockedSourceError) as caught:
        await read_mod.read_file(str(path), Mode.BLOCK)
    return json.dumps({"message": str(caught.value), "refusal": caught.value.refusal})


class TestNoExistenceOracle:
    """#263: behind a gateway, a missing path and a denied one read the same."""

    async def test_missing_and_denied_are_identical(
        self, root: Path, live_gateway: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = tmp_path / "state"
        state.mkdir()
        (state / "trentina.db").write_text("x", encoding="utf-8")
        monkeypatch.setenv("QUARANTINE_DB", str(state / "trentina.db"))
        config_mod._config = None
        # Inside the root: one link to a denied file that exists, one to one
        # that does not, one plain missing file. Only resolving tells them apart.
        (root / "exists").symlink_to(state / "trentina.db")
        (root / "absent").symlink_to(state / "no-such.db")
        refusals = {
            await _read_refusal(root / "exists"),
            await _read_refusal(root / "absent"),
            await _read_refusal(root / "missing.txt"),
            await _read_refusal("/config/profiles.yaml"),
            await _read_refusal("/no/such/place.txt"),
        }
        assert len(refusals) == 1
        assert confine.GATEWAY_REASON in refusals.pop()

    async def test_standalone_keeps_the_reasons_apart(self, root: Path) -> None:
        missing = await _read_refusal(root / "missing.txt")
        outside = await _read_refusal(root.parent / "outside.txt")
        assert "not_found" in missing
        assert "outside_read_roots" in outside

    async def test_the_refusal_names_no_path_and_offers_nothing(
        self, root: Path, live_gateway: Path
    ) -> None:
        refusal = await _read_refusal(root / "missing.txt")
        assert str(root) not in refusal
        assert json.loads(refusal)["refusal"] == {
            "reason": f"confinement refused ({confine.GATEWAY_REASON})",
            "mode": "block",
            "flagged_by": "confinement",
            "alternatives": [],
        }


@pytest.fixture
def real_server() -> Iterator[None]:
    from trentina.gateway import internal
    from trentina.server import mcp

    saved = internal._server
    internal.register_internal_server(mcp)
    try:
        yield
    finally:
        internal._server = saved


@pytest.mark.usefixtures("env", "real_server")
class TestAudit:
    """#278: a confinement refusal is the defense working, and is audited as one."""

    @pytest.mark.parametrize(
        ("tool", "path"),
        [
            ("read_tool", "/config/profiles.yaml"),
            ("read_tool", "/no/such/file.txt"),
            ("dir_tool", "/config"),
        ],
    )
    async def test_it_audits_as_blocked_defense(
        self, tool: str, path: str, live_gateway: Path
    ) -> None:
        from pydantic import SecretStr

        from trentina.database import get_db
        from trentina.gateway.names import NAMESPACE_SEP
        from trentina.gateway.profile import AuthConfig, Backend, Profile
        from trentina.gateway.router import route_jsonrpc

        profile = Profile(
            short_names=False,
            name="alpha",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={"web": Backend(url="internal://web", tools_allow=["*"])},
        )
        assert profile.auth is not None
        profile.auth.bearer_token = SecretStr("x")

        resp = await route_jsonrpc(
            profile,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": f"web{NAMESPACE_SEP}{tool}", "arguments": {"path": path}},
            },
        )
        row = get_db().execute("SELECT outcome, error_message FROM gateway_calls").fetchone()

        assert row["outcome"] == "blocked_defense"
        assert path not in (row["error_message"] or "")
        assert refused(resp)["flagged_by"] == "confinement"
        assert refused(resp)["alternatives"] == []
