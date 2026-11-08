# Telemetry Export

*Part of Trentina's **Determinism** promise; see [Why Trentina](../README.md#why-trentina).*

The [audit log](audit-log.md) is the record of every call, and it lives in a SQLite file on the gateway host. Telemetry export sends the safe metadata of the same calls to the monitoring you already run: any OpenTelemetry collector as traces, or stderr as one JSON line per call. One agent run becomes one trace, with its tool calls, model calls and egress requests side by side.

## What Leaves the Gateway

Each call is one `CallRecord`, built from its `gateway_calls` row after the row is committed. It carries only fields the gateway itself sets:

| Field | Span attribute | Example |
|-------|----------------|---------|
| `profile`, `backend` | `trentina.profile`, `trentina.backend` | `kagetora`, `github` |
| `tool` | `gen_ai.tool.name` | `create_issue`, `chat/completions` |
| `outcome`, `success` | `trentina.outcome`, `trentina.success` | `blocked_defense`, `false` |
| `duration_ms` | `trentina.duration_ms`, and the span's start and end | `234` |
| `bytes_arrived`, `bytes_delivered` | `trentina.bytes_arrived`, `trentina.bytes_delivered` | `18234`, `912` |
| `destination_kind` | `trentina.destination_kind` | `fetch`, `model`, `tunnel` |
| `session` | `trentina.mcp_session` | fingerprint of the MCP session |
| `call_ref`, `detections_digest` | `trentina.call_ref`, `trentina.detections_digest` | join keys back to the audit DB |
| `layer`, `risk`, `l3_verdict` | `trentina.layer`, `trentina.risk`, `trentina.l3_verdict` | `L2`, `high`, `flagged`: from the call's detections, closed sets only |
| `agent_session` | `session.id` | fingerprint of the agent's `x-session-id` |
| `trace_id`, `span_id`, `parent_span_id` | the span's own ids | |

Never exported: the call's destination, its arguments, error text, and any content. Those are caller-chosen strings, and the rule for logs applies here too (#262): no string a caller chose leaves the gateway in telemetry. The span name is `<backend> <tool>`. Its status is OK for outcome `ok` and ERROR otherwise.

## Traces

An agent that sends a W3C `traceparent` header on its MCP requests and model calls gets every one of them recorded in its trace, each as a child of the span it named. Trentina keeps the header only if it is exactly version `00` with non-zero lowercase hex ids, and otherwise starts a fresh trace for the request. An `x-session-id` header (256 characters at most) is kept as a fingerprint and exported as `session.id`.

On an OpenRouter chat completion the gateway sets OpenRouter's `session_id` to that fingerprint, or to the trace id when the agent sent only a `traceparent`. OpenRouter's own traces (Broadcast) then group with the gateway's. The agent cannot set `session_id` itself; the [LLM proxy](llm-proxying.md) refuses it.

## OTLP Export

```bash
TRENTINA_OTLP_ENDPOINT=http://otlp:4318
TRENTINA_OTLP_HEADERS=Authorization=Basic%20dHJlbnRpbmE6c2VjcmV0
```

Spans are sent as OTLP/HTTP with JSON encoding to `<endpoint>/v1/traces`: any OpenTelemetry Collector, Grafana Alloy, Datadog Agent, or a Telegraf `http_listener_v2`. The exporter is stdlib-only and goes through no proxy.

- **It never slows a call.** A call only enqueues its record. A full queue (10,000 records) drops the record and counts it.
- **It batches.** A background thread sends up to 512 spans at a time, or whatever arrived in the last 5 seconds.
- **It never retries.** Each batch gets one attempt with a 5-second timeout. A batch the collector refused or never answered is counted as failed and dropped. A dead collector costs records, not latency.
- **Its counts are on `/health`.** `telemetry: {sent, dropped, failed}` appears there whenever the exporter is on.

`TRENTINA_OTLP_HEADERS` takes the `OTEL_EXPORTER_OTLP_HEADERS` form: comma-separated `key=value` pairs, with values percent-decoded. Every value is held by the log guard, so no log line carries it.

## JSON Lines

`TRENTINA_LOG_FORMAT=json` writes the same record, one compact JSON object per call, to stderr. From there a structured-log collector picks it up through journald, with no OTLP needed. It uses the same non-blocking queue.

## See Also

- [Audit Log](audit-log.md): the full record, caller-chosen fields included
- [Configuration](configuration.md): every environment variable
- [LLM Key Proxying](llm-proxying.md): the model calls traced here
