"""The perimeter half of the public transport contract (#535 R2).

``trentina.transports.base`` is what a route plugin imports. These tests hold
the parts of it an author relies on: the declarations are plain frozen values,
a request reaches a route without its body until ``deliver``, a refusal carries
what ``render`` needs, the spine's own refusals are one table, and the module
imports alone, with nothing from the gateway behind it.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from trentina.outcomes import Outcome
from trentina.transports.base import (
    SPINE_REFUSALS,
    Admitted,
    Audit,
    Bearer,
    Body,
    Context,
    Grant,
    Instance,
    Listener,
    OperatorOrigin,
    Origin,
    Refusal,
    RefusedError,
    Route,
    Wire,
)

BASE = Path(__file__).resolve().parent.parent / "src" / "trentina" / "transports" / "base.py"


class TestDeclarations:
    @pytest.mark.parametrize(
        "value",
        [
            Bearer(),
            Refusal(403, Outcome.DENIED_GUARD),
            OperatorOrigin("api"),
            Origin("api.example.com"),
        ],
    )
    def test_declarations_are_frozen_values(self, value: Any) -> None:
        field = dataclasses.fields(value)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(value, field, "changed")

    def test_bearer_reads_authorization_alone_by_default(self) -> None:
        assert Bearer().fallback_headers == ()

    def test_two_audit_policies(self) -> None:
        assert {a.value for a in Audit} == {"always", "on_finding"}

    def test_an_origin_is_https_on_443_unless_named(self) -> None:
        assert Origin("api.example.com").port == 443


class TestTheRequestAsARouteSeesIt:
    def test_a_wire_holds_no_body(self) -> None:
        """The body is ``deliver``'s, after the slot (#535 cto ruling): a route
        cannot make the profile pay for a body before it holds a slot."""
        fields = {f.name for f in dataclasses.fields(Wire)}
        assert fields == {"method", "path", "raw_path", "query", "headers", "peer"}

    def test_the_grant_holds_no_secret(self) -> None:
        fields = {f.name for f in dataclasses.fields(Grant)}
        assert fields == {"origins", "methods", "enforcement", "options", "hosts"}

    def test_an_instance_holds_no_secret(self) -> None:
        fields = {f.name for f in dataclasses.fields(Instance)}
        assert fields == {"name", "type", "origins", "options"}


def _body(chunks: list[bytes], cap: int) -> Body:
    async def stream() -> AsyncIterator[bytes]:
        for chunk in chunks:
            yield chunk

    return Body(stream(), cap)


class TestBody:
    def test_reads_the_whole_body(self) -> None:
        body = _body([b"ab", b"cd"], cap=4)
        assert asyncio.run(body.read()) == b"abcd"

    def test_a_body_past_the_cap_is_refused_too_large(self) -> None:
        body = _body([b"ab", b"cde"], cap=4)
        with pytest.raises(RefusedError) as raised:
            asyncio.run(body.read())
        assert raised.value.reason == "too_large"

    def test_the_body_is_read_once(self) -> None:
        body = _body([b"ab"], cap=4)
        asyncio.run(body.read())
        with pytest.raises(RuntimeError, match="has been read"):
            asyncio.run(body.read())


class TestRefusedError:
    def test_a_bare_reason_defers_to_the_route_table(self) -> None:
        refused = RefusedError("busy")
        assert (refused.reason, refused.status, refused.outcome) == ("busy", None, None)
        assert not refused.executed
        assert refused.detail is None

    def test_the_message_is_the_reason_alone(self) -> None:
        """A refusal's text is a closed reason code, never a caller's value (#262)."""
        assert str(RefusedError("bad_path", detail="/etc/passwd")) == "bad_path"

    def test_the_spine_answers_an_unknown_caller_and_a_full_profile(self) -> None:
        assert SPINE_REFUSALS["unauthorized"].status == 401
        assert SPINE_REFUSALS["busy"].status == 503
        assert SPINE_REFUSALS["unknown_upstream"].outcome is Outcome.DENIED_ALLOWLIST


class TestTheHooksAreRequired:
    """``admit``, ``deliver`` and ``render`` have no defaults: a route missing one
    is not a route (#535: the policy half and the wire shape are the route's)."""

    def test_a_route_without_render_cannot_be_built(self) -> None:
        class Partial(Route[Admitted, Context]):
            async def admit(self, wire: Wire, grant: Grant, instance: Instance) -> Admitted:
                return Admitted(OperatorOrigin("api"))

            async def deliver(self, admitted: Admitted, ctx: Context) -> Any:
                return None

        # Typed as Any: the type checker refuses an abstract instantiation, which
        # is the point; this checks the runtime refuses it too.
        build: Any = Partial
        with pytest.raises(TypeError, match="render"):
            build()

    def test_a_listener_without_relay_cannot_be_built(self) -> None:
        class Partial(Listener):
            def admit(self, head: bytes) -> Admitted:
                return Admitted(OperatorOrigin("api"))

            def respond(self, refused: RefusedError) -> bytes:
                return b""

        build: Any = Partial
        with pytest.raises(TypeError, match="relay"):
            build()


class TestTheContractStandsAlone:
    def test_base_imports_nothing_from_the_gateway(self) -> None:
        """A plugin imports this module; it must not drag the gateway in behind it."""
        tree = ast.parse(BASE.read_text(encoding="utf-8"))
        modules = {
            (node.module or "") if isinstance(node, ast.ImportFrom) else node.names[0].name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        }
        assert not any("gateway" in m or "perimeter" in m for m in modules), modules

    def test_base_imports_in_a_fresh_interpreter(self) -> None:
        done = subprocess.run(
            [sys.executable, "-I", "-c", "import trentina.transports.base"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 0, done.stderr
