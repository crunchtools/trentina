"""Gateway subpackage — the per-profile MCP proxy.

One endpoint per profile in front of every backend: authentication, tool
allowlists and short names, parameter and response guards, the perimeter
scan of tool descriptions and responses, and the Matrix, LLM and alert
ingresses. See docs/gateway.md, and docs/internal/gateway-design.md for the
original design.
"""

from __future__ import annotations

from ..transports.mcp import route_jsonrpc
from .alert_ingress import register_alert_routes
from .app import gateway_app, register_with_fastmcp
from .auth import verify_bearer
from .backend import BackendCall, call_backend_tool, list_backend_tools
from .circuit import CircuitBreaker, breaker
from .errors import AuthError, GatewayError, ProfileConfigError
from .filter import filter_tools
from .guards import check_request_guards
from .internal import (
    call_internal_tool,
    internal_server_registered,
    list_internal_tools,
    register_internal_server,
)
from .loader import GatewayConfig, load_profiles
from .profile import (
    AlertIngressConfig,
    AuthConfig,
    Backend,
    DefenseConfig,
    ParameterConstraint,
    Profile,
)
from .sessions import Session, SessionRegistry, session_registry

__all__ = [
    "AlertIngressConfig",
    "AuthConfig",
    "AuthError",
    "Backend",
    "BackendCall",
    "CircuitBreaker",
    "DefenseConfig",
    "GatewayConfig",
    "GatewayError",
    "ParameterConstraint",
    "Profile",
    "ProfileConfigError",
    "Session",
    "SessionRegistry",
    "breaker",
    "call_backend_tool",
    "call_internal_tool",
    "check_request_guards",
    "filter_tools",
    "gateway_app",
    "internal_server_registered",
    "list_backend_tools",
    "list_internal_tools",
    "load_profiles",
    "register_alert_routes",
    "register_internal_server",
    "register_with_fastmcp",
    "route_jsonrpc",
    "session_registry",
    "verify_bearer",
]
