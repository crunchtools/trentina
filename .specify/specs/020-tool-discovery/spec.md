# Specification: Tool Discovery

> **Spec ID:** 020-tool-discovery
> **Status:** Implemented (1.15.0)
> **Version:** 0.1.0
> **Author:** crunchtools
> **Date:** 2026-10-17
> **Ticket:** #473 (from #60)

## Overview

A client without native tool search sends every listed schema on every
turn. Kagetora (Hermes) carried 361 tools at about 160K tokens a call, 95%
of it schemas, while Josui on Claude Code sat at 35–60K from the same
gateway because Claude Code defers MCP tools.

**Done is:** an operator turns on `tool_discovery` for a profile and its
client sees a handful of tools plus a way to find or load the rest, with
every call still audited and policed as the real tool.

## Decision

Product (Scott, 2026-10-17): provider-neutral, at the MCP layer, opt-in per
profile; the real tool name stays in the audit row and in guarded-execution
context; publish selection accuracy. Injecting Anthropic's `defer_loading`
in the LLM proxy was rejected as provider-specific.

CTO (2026-10-17): no embedding model in v1 (it would need a model in the
image, an export stage and a gate; the benchmark decides whether it is
earned). The backend-prefix rename was replaced by `describe_backend`,
which front-loads the category without renaming, so allowlists and hooks
are untouched.

## User Stories

1. As an operator of a client without tool search, I set `mode: search` and
   its requests carry a few schemas instead of hundreds, and it still finds
   and calls any tool its allowlist permits.
2. As an operator, I read the audit and see the real backend and tool for
   every call made through `call_tool`, and guarded execution judges the
   real tool.
3. As an operator of Claude Code, I name categories and turn on
   `describe_backend`, and its own search finds tools by what they belong to.

## Requirements

- `off` (default) changes nothing a client sees, except where the operator
  sets `categories` or `describe_backend`.
- `call_tool` meets every rule a direct call meets and writes exactly one
  audit row, under the real tool; it cannot call a discovery tool.
- `find_tools` reads only the served aggregate; a denied tool is never found.
- `dynamic` notifies only the session that loaded, with the spec's
  `notifications/tools/list_changed`, and refuses a stateless client.
- Everything the gateway adds (discovery tools, instructions line,
  description prefix) is the gateway's or the operator's text.
- Selection accuracy is published and held as a floor by a test.
