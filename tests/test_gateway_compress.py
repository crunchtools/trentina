"""Tests for gateway/compress.py — tool description compression."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from trentina.errors import QuarantineAgentError
from trentina.gateway import compress as compress_mod
from trentina.gateway.compress import (
    _cache,
    _call_compress_model,
    _hash_description,
    _precompress_backend,
    compress_tools,
    maybe_trigger_compression,
    set_profiles,
)
from trentina.quarantine.providers.base import ProviderResult


def _tool(name: str, description: str, schema: dict | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": schema or {"type": "object", "properties": {}},
    }


pytestmark = pytest.mark.usefixtures("standalone_l3")

SUMMARIZE = {"processors": ["summarize"]}


class TestCompressTools:
    """Sync cache-lookup tests for compress_tools()."""

    def setup_method(self) -> None:
        _cache.clear()

    def test_cache_hit_replaces_description(self) -> None:
        original = "This is a very long verbose description that goes on and on"
        h = _hash_description(original)
        _cache[h] = "Short version."

        tools = [_tool("my_tool", original)]
        result = compress_tools(tools)

        assert result[0]["description"] == "Short version."

    def test_cache_miss_passes_through(self) -> None:
        tools = [_tool("my_tool", "Some description not in cache")]
        result = compress_tools(tools)

        assert result[0]["description"] == "Some description not in cache"

    def test_empty_cache_returns_original(self) -> None:
        tools = [_tool("a", "desc a"), _tool("b", "desc b")]
        result = compress_tools(tools)

        assert len(result) == 2
        assert result[0]["description"] == "desc a"
        assert result[1]["description"] == "desc b"

    def test_preserves_input_schema(self) -> None:
        schema = {"type": "object", "properties": {"url": {"type": "string"}}}
        original = "Fetch a URL and return content"
        h = _hash_description(original)
        _cache[h] = "Fetch URL."

        tools = [_tool("fetch", original, schema)]
        result = compress_tools(tools)

        assert result[0]["inputSchema"] == schema
        assert result[0]["name"] == "fetch"

    def test_preserves_extra_fields(self) -> None:
        original = "Some verbose description"
        h = _hash_description(original)
        _cache[h] = "Short."

        tool = _tool("t", original)
        tool["title"] = "My Title"
        tool["annotations"] = {"readOnly": True}

        result = compress_tools([tool])
        assert result[0]["title"] == "My Title"
        assert result[0]["annotations"] == {"readOnly": True}
        assert result[0]["description"] == "Short."

    def test_empty_description_passed_through(self) -> None:
        tools = [_tool("t", "")]
        result = compress_tools(tools)
        assert result[0]["description"] == ""

    def test_does_not_mutate_original_tool(self) -> None:
        original = "Long description here"
        h = _hash_description(original)
        _cache[h] = "Short."

        tool = _tool("t", original)
        compress_tools([tool])
        assert tool["description"] == original


class TestHashDescription:
    def test_deterministic(self) -> None:
        assert _hash_description("hello") == _hash_description("hello")

    def test_different_inputs_different_hashes(self) -> None:
        assert _hash_description("a") != _hash_description("b")

    def test_sha256(self) -> None:
        expected = hashlib.sha256(b"test").hexdigest()
        assert _hash_description("test") == expected


class TestDatabaseRoundTrip:
    """Test save/load cycle through SQLite."""

    def test_save_and_load(self, tmp_path: Any) -> None:
        from trentina import database as db_module
        from trentina.database import (
            get_all_compressions,
            get_db,
            save_compression,
        )

        db_path = str(tmp_path / "test.db")
        db_module._db = None
        get_db(db_path)

        save_compression("hash1", "original text", "short", "gemini-2.5-flash-lite")
        save_compression("hash2", "another original", "brief", "gemini-2.5-flash-lite")

        result = get_all_compressions()
        assert result["hash1"] == "short"
        assert result["hash2"] == "brief"

        db_module._db = None

    def test_compression_stats(self, tmp_path: Any) -> None:
        from trentina import database as db_module
        from trentina.database import (
            get_compression_stats,
            get_db,
            save_compression,
        )

        db_path = str(tmp_path / "test.db")
        db_module._db = None
        get_db(db_path)

        save_compression("h1", "a" * 200, "a" * 100, "model")
        save_compression("h2", "b" * 300, "b" * 150, "model")

        stats = get_compression_stats()
        assert stats["tools_compressed"] == 2
        assert stats["original_chars"] == 500
        assert stats["compressed_chars"] == 250
        assert stats["savings_percent"] == 50
        assert stats["estimated_tokens_saved"] == 62

        db_module._db = None


class TestCallCompressModel:
    """Test the provider-based compression call."""

    @pytest.mark.asyncio
    async def test_successful_compression(self) -> None:
        compressed_json = json.dumps(
            {"compressed": [{"id": "abc123", "text": "Short description."}]}
        )
        mock_prov = MagicMock()
        mock_prov.generate = AsyncMock(
            return_value=ProviderResult(
                text=compressed_json,
                input_tokens=10,
                output_tokens=5,
            )
        )
        with patch(
            "trentina.gateway.compress.get_provider",
            return_value=mock_prov,
        ):
            result = await _call_compress_model(
                [("abc123", "Long verbose description")],
            )
        assert len(result) == 1
        assert result[0] == ("abc123", "Short description.")

    @pytest.mark.asyncio
    async def test_provider_failure_returns_empty(self) -> None:
        mock_prov = MagicMock()
        mock_prov.generate = AsyncMock(
            side_effect=QuarantineAgentError("provider error"),
        )
        with patch(
            "trentina.gateway.compress.get_provider",
            return_value=mock_prov,
        ):
            result = await _call_compress_model([("h1", "desc")])
        assert result == []


class TestPrecompressBackend:
    """Test the backend pre-compression flow."""

    @pytest.mark.asyncio
    async def test_skips_already_cached(self) -> None:
        _cache.clear()
        desc = "Already cached description"
        h = _hash_description(desc)
        _cache[h] = "Cached."

        mock_tools = [_tool("t1", desc)]

        with patch(
            "trentina.gateway.backend.list_backend_tools",
            new_callable=AsyncMock,
            return_value=mock_tools,
        ):
            from trentina.gateway.profile import Backend

            backend = Backend(url="http://test:8000/mcp")
            count = await _precompress_backend("test", backend)

        assert count == 0

    @pytest.mark.asyncio
    async def test_model_returns_longer_discarded(self) -> None:
        _cache.clear()
        original = "Short."

        mock_tools = [_tool("t1", original)]

        longer_result = [
            (_hash_description(original), "This is actually longer than the original text")
        ]

        with (
            patch(
                "trentina.gateway.backend.list_backend_tools",
                new_callable=AsyncMock,
                return_value=mock_tools,
            ),
            patch(
                "trentina.gateway.compress._call_compress_model",
                new_callable=AsyncMock,
                return_value=longer_result,
            ),
            patch("trentina.gateway.compress.save_compression"),
        ):
            from trentina.gateway.profile import Backend

            backend = Backend(url="http://test:8000/mcp")
            count = await _precompress_backend("test", backend)

        assert count == 0
        assert _hash_description(original) not in _cache


class TestMaybeTriggerCompression:
    """Tests for the lazy compression trigger."""

    def setup_method(self) -> None:
        _cache.clear()
        compress_mod._compress_triggered = False
        compress_mod._compress_task = None
        compress_mod._profiles = None

    @pytest.mark.asyncio
    async def test_triggers_once_only(self) -> None:
        from trentina.gateway.profile import AuthConfig, Backend, Profile

        auth = AuthConfig(bearer_token_env="TEST_TOKEN")
        profile = Profile(
            name="test",
            auth=auth,
            backends={
                "b": Backend(
                    url="http://x:8000/mcp",
                    preprocess_tool_descriptions={"processors": ["summarize"]},
                )
            },
        )
        set_profiles({"test": profile})

        with patch(
            "trentina.gateway.compress.precompress_all",
            new_callable=AsyncMock,
            return_value={},
        ) as mock_precompress:
            await maybe_trigger_compression()
            await maybe_trigger_compression()

        mock_precompress.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_profiles_is_noop(self) -> None:
        compress_mod._profiles = None
        with patch(
            "trentina.gateway.compress.precompress_all",
            new_callable=AsyncMock,
        ) as mock_precompress:
            await maybe_trigger_compression()

        mock_precompress.assert_not_called()
        assert not compress_mod._compress_triggered

    @pytest.mark.asyncio
    async def test_creates_background_task(self) -> None:
        from trentina.gateway.profile import AuthConfig, Backend, Profile

        auth = AuthConfig(bearer_token_env="TEST_TOKEN")
        profile = Profile(
            name="test",
            auth=auth,
            backends={
                "b": Backend(
                    url="http://x:8000/mcp",
                    preprocess_tool_descriptions={"processors": ["summarize"]},
                )
            },
        )
        set_profiles({"test": profile})

        with patch(
            "trentina.gateway.compress.precompress_all",
            new_callable=AsyncMock,
            return_value={},
        ):
            await maybe_trigger_compression()

        assert compress_mod._compress_task is not None
        assert compress_mod._compress_triggered is True


class TestRetryLogic:
    """Tests for provider retry on transient errors."""

    def _success_result(self) -> ProviderResult:
        compressed_json = json.dumps({"compressed": [{"id": "h1", "text": "Short."}]})
        return ProviderResult(text=compressed_json, input_tokens=10, output_tokens=5)

    @pytest.mark.asyncio
    async def test_retries_on_503(self) -> None:
        mock_prov = MagicMock()
        mock_prov.generate = AsyncMock(
            side_effect=[
                QuarantineAgentError("HTTP 503", status_code=503),
                self._success_result(),
            ]
        )
        with (
            patch(
                "trentina.gateway.compress.get_provider",
                return_value=mock_prov,
            ),
            patch("trentina.gateway.compress.RETRY_BASE_DELAY", 0.01),
        ):
            result = await _call_compress_model([("h1", "Long description")])
        assert len(result) == 1
        assert mock_prov.generate.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_429(self) -> None:
        mock_prov = MagicMock()
        mock_prov.generate = AsyncMock(
            side_effect=[
                QuarantineAgentError("HTTP 429", status_code=429),
                self._success_result(),
            ]
        )
        with (
            patch(
                "trentina.gateway.compress.get_provider",
                return_value=mock_prov,
            ),
            patch("trentina.gateway.compress.RETRY_BASE_DELAY", 0.01),
        ):
            result = await _call_compress_model([("h1", "Long description")])
        assert len(result) == 1
        assert mock_prov.generate.call_count == 2

    @pytest.mark.asyncio
    async def test_gives_up_after_max_retries(self) -> None:
        mock_prov = MagicMock()
        mock_prov.generate = AsyncMock(
            side_effect=QuarantineAgentError("HTTP 503", status_code=503),
        )
        with (
            patch(
                "trentina.gateway.compress.get_provider",
                return_value=mock_prov,
            ),
            patch("trentina.gateway.compress.RETRY_BASE_DELAY", 0.01),
        ):
            result = await _call_compress_model([("h1", "desc")])
        assert result == []
        assert mock_prov.generate.call_count == 3

    @pytest.mark.asyncio
    async def test_no_retry_on_400(self) -> None:
        mock_prov = MagicMock()
        mock_prov.generate = AsyncMock(
            side_effect=QuarantineAgentError("HTTP 400"),
        )
        with patch(
            "trentina.gateway.compress.get_provider",
            return_value=mock_prov,
        ):
            result = await _call_compress_model([("h1", "desc")])
        assert result == []
        assert mock_prov.generate.call_count == 1


class TestParameterDescriptions:
    """0.38.0: parameter descriptions are trimmed, then compressed when long."""

    def setup_method(self) -> None:
        _cache.clear()

    @pytest.mark.parametrize(
        ("text", "required", "default", "expected"),
        [
            ("Optional. The page size.", False, 10, "The page size."),
            ("The page size (optional)", False, ..., "The page size"),
            ("Optional. The page size.", True, ..., "Optional. The page size."),
            ("Max results. Defaults to 10.", False, 10, "Max results."),
            ("Max results (default: 10)", False, 10, "Max results."),
            ("Max results. Defaults to 10.", False, 20, "Max results. Defaults to 10."),
            ("Include archived. Default is false.", False, False, "Include archived."),
            ("Optional", False, ..., "Optional"),
        ],
    )
    def test_trim_drops_only_what_the_schema_says(
        self, text: str, required: bool, default: Any, expected: str
    ) -> None:
        assert compress_mod._trim(text, required=required, default=default) == expected

    def test_cached_parameter_descriptions_are_served(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 10, "description": "Max. Defaults to 10."},
                "q": {"type": "string", "description": "Query."},
            },
            "$defs": {"F": {"properties": {"x": {"description": "Long x."}}}},
        }
        _cache[compress_mod._param_key("Max. Defaults to 10.", 10)] = "Max."
        _cache[compress_mod._param_key("Long x.", ...)] = "X."
        out = compress_tools([_tool("t", "", schema)])[0]["inputSchema"]
        assert out["properties"]["limit"]["description"] == "Max."
        assert out["properties"]["q"]["description"] == "Query."
        assert out["$defs"]["F"]["properties"]["x"]["description"] == "X."
        assert schema["properties"]["limit"]["description"] == "Max. Defaults to 10."

    def test_the_default_is_part_of_the_key(self) -> None:
        """Same words, different default: the trim read different schemas."""
        assert compress_mod._param_key("Max. Defaults to 10.", 10) != compress_mod._param_key(
            "Max. Defaults to 10.", 20
        )

    @pytest.mark.asyncio
    async def test_short_ones_are_trimmed_and_long_ones_go_to_the_model(self) -> None:
        long_desc = "The maximum number of results to return in a single page of output. " * 2
        schema = {
            "type": "object",
            "properties": {
                "page": {"type": "integer", "description": "Optional. Page number."},
                "limit": {"type": "integer", "description": long_desc},
            },
        }
        long_key = compress_mod._param_key(long_desc, ...)
        model = AsyncMock(return_value=[(long_key, "Page size.")])
        with (
            patch.object(compress_mod, "_call_compress_model", model),
            patch.object(compress_mod, "save_compression"),
            patch.object(compress_mod, "DELAY_BETWEEN_BATCHES", 0),
        ):
            stored = await compress_mod._precompress_params("b", [_tool("list", "", schema)])
        assert stored == 2
        assert _cache[compress_mod._param_key("Optional. Page number.", ...)] == "Page number."
        assert _cache[long_key] == "Page size."
        assert model.call_args.kwargs["kind"] == "parameter"
        assert model.call_args.kwargs["context"][long_key] == {"tool": "list", "parameter": "limit"}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("reply", [[], "longer"])
    async def test_a_model_that_fails_or_grows_it_leaves_the_trim(self, reply: Any) -> None:
        long_desc = "Optional. " + "The maximum number of results in one page of output. " * 2
        schema = {"type": "object", "properties": {"limit": {"description": long_desc}}}
        key = compress_mod._param_key(long_desc, ...)
        answer = [(key, long_desc + " and more")] if reply == "longer" else reply
        with (
            patch.object(compress_mod, "_call_compress_model", AsyncMock(return_value=answer)),
            patch.object(compress_mod, "save_compression"),
            patch.object(compress_mod, "DELAY_BETWEEN_BATCHES", 0),
        ):
            await compress_mod._precompress_params("b", [_tool("list", "", schema)])
        assert _cache[key] == long_desc.removeprefix("Optional. ").strip()

    @pytest.mark.asyncio
    async def test_a_run_that_banked_anything_rebuilds_the_lists(self) -> None:
        from trentina.gateway.profile import AuthConfig, Backend, Profile

        profile = Profile(
            name="p",
            auth=AuthConfig(bearer_token_env="T"),
            backends={
                "b": Backend(
                    url="http://x:8000/mcp",
                    preprocess_tool_descriptions={"processors": ["summarize"]},
                )
            },
        )
        rebuilt = MagicMock()
        saved = compress_mod._on_compressed
        compress_mod.set_on_compressed(rebuilt)
        try:
            with (
                patch.object(compress_mod, "_precompress_backend", AsyncMock(return_value=3)),
                patch.object(compress_mod, "DELAY_BETWEEN_BACKENDS", 0),
            ):
                await compress_mod.precompress_all({"p": profile})
                rebuilt.assert_called_once()
                rebuilt.reset_mock()
                with patch.object(compress_mod, "_precompress_backend", AsyncMock(return_value=0)):
                    await compress_mod.precompress_all({"p": profile})
                rebuilt.assert_not_called()
        finally:
            compress_mod.set_on_compressed(saved)


class TestPreprocessToolDescriptions:
    """#176: compression is the summarize pre-processor on its own channel."""

    def test_the_old_key_does_not_load(self) -> None:
        """Removed in 0.40.0; extra="forbid" makes it a load error, not a no-op."""
        from pydantic import ValidationError

        from trentina.gateway.profile import Backend

        with pytest.raises(ValidationError, match="compress_descriptions"):
            Backend(url="http://x:8000/mcp", compress_descriptions=True)

    def test_only_summarize_runs_on_the_description_channel(self) -> None:
        from trentina.gateway.errors import ProfileConfigError
        from trentina.gateway.loader import _check_drivers
        from trentina.gateway.profile import AuthConfig, Backend, Profile

        profile = Profile(
            name="p",
            auth=AuthConfig(bearer_token_env="T"),
            backends={
                "b": Backend(
                    url="http://x:8000/mcp", preprocess_tool_descriptions={"processors": ["petit"]}
                )
            },
        )
        with pytest.raises(ProfileConfigError, match="tool_description"):
            _check_drivers("p", profile)

    @pytest.mark.asyncio
    async def test_summarize_descriptions_parses_well_formed_entries(self) -> None:
        from trentina.transforms.summarize import summarize_descriptions

        reply = ProviderResult(
            text=json.dumps({"compressed": [{"id": "a", "text": "A."}, {"id": "b"}, "junk"]})
        )
        with patch(
            "trentina.transforms.summarize.limited_generate",
            AsyncMock(return_value=reply),
        ) as generate:
            out = await summarize_descriptions(
                MagicMock(), [{"id": "a", "text": "Long A."}], "parameter"
            )
        assert out == [("a", "A.")]
        assert "PARAMETER" in generate.call_args.kwargs["system_prompt"]
