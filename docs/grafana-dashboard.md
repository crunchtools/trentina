# Grafana Dashboard

*Part of Trentina's **Determinism** promise; see [Why Trentina](../README.md#why-trentina).*

Trentina can send every call it handles to your monitoring as an OpenTelemetry trace ([Telemetry Export](telemetry.md)). This page sets up a ready-made Grafana dashboard on top of that, and explains how to read it. Everything it needs is in [`contrib/grafana/`](../contrib/grafana/):

- `trentina-dashboard.json`: the dashboard, 11 panels, each with a tooltip (the ⓘ next to its title).
- `telegraf-receiver.conf`: a Telegraf config that receives Trentina's spans and writes them to InfluxDB 2.x.

## Setup

The pipe is Trentina → Telegraf (receiver) → InfluxDB → Grafana. If you already run InfluxDB and Grafana, it is three steps.

**1. Run the receiver.** Run Telegraf with `telegraf-receiver.conf` and these environment variables:

| Variable | Value |
|----------|-------|
| `INFLUX_URL`, `INFLUX_ORG`, `INFLUX_BUCKET` | your InfluxDB and the bucket to write to |
| `INFLUX_TOKEN` | a **write-only** token for that bucket |
| `OTLP_USERNAME`, `OTLP_PASSWORD` | the basic-auth pair Trentina will send |

It listens on port 4318. Run it on its own, not inside a Telegraf that collects host metrics: it answers requests, so give it nothing but the write token. Telegraf's built-in OpenTelemetry input speaks gRPC only, which is why this one uses an HTTP listener instead.

**2. Point Trentina at it.** In Trentina's environment:

```bash
TRENTINA_OTLP_ENDPOINT=http://telegraf-receiver:4318
TRENTINA_OTLP_HEADERS=Authorization=Basic%20<base64 of user:password>
TRENTINA_OTLP_INSECURE=true   # only if plain http stays on a private network
```

After a restart, `/health` shows `telemetry: {sent, dropped, failed}`. `sent` climbing means spans are arriving.

**3. Import the dashboard.** In Grafana, go to Dashboards → New → Import and upload `trentina-dashboard.json`. Two drop-downs at the top pick your InfluxDB data source (Flux query language) and the bucket. They default to the first InfluxDB data source and `telegraf`. To provision the dashboard from a file instead, drop the JSON in your dashboards directory as is.

**Another backend?** Trentina's spans are standard OTLP (OpenTelemetry Protocol), so any collector works: an OpenTelemetry Collector, Grafana Tempo, Datadog. Only this dashboard is InfluxDB-specific. To build your own, chart the span attributes listed in [Telemetry Export](telemetry.md#what-leaves-the-gateway), chiefly `trentina.outcome`, `trentina.profile`, `trentina.layer` and the span duration.

## Reading the Dashboard

Every number covers the time range picked at the top right. The data starts when the export was turned on; older calls are only in the [audit log](audit-log.md).

### The four totals

| Panel | What it counts | What to watch for |
|-------|----------------|-------------------|
| **Gateway calls** | Every call Trentina handled: MCP tool calls, model calls through the [LLM proxy](llm-proxying.md), fetches, egress tunnels. | A sudden jump is an agent looping. Compare with *Calls by profile*. |
| **Refused or failed** | Calls whose outcome was not `ok`. | This is not a failure count: blocks, denials and decoys are policy working. Amber whenever it is above zero. |
| **Flagged by the defense** | Calls where a defense layer raised a detection, blocked or not. | In flag [mode](profiles.md) a flagged call is still delivered with a warning, so this is usually larger than `blocked_defense`. |
| **p95 duration** | 95% of calls finished faster than this, end to end. | Climbing over days usually means one slow backend; see *Duration by kind*. |

### Calls by outcome

One line per [outcome](audit-log.md). Each call has exactly one.

| Outcome | Meaning | Normal? |
|---------|---------|---------|
| `ok` | The backend answered normally. | The bulk of traffic. |
| `tool_error` | The backend answered but reported an error (a bad argument, a missing record). | Yes, in small numbers. It is the agent's or backend's problem, not Trentina's. |
| `blocked_defense` | L1, L2 or L3 refused the content. | Yes. This is the defense working. |
| `denied_allowlist` | The tool is not allowed for this profile. | A few is an agent probing. Many is a misconfigured profile. |
| `denied_guard` | A rule you wrote rejected the request before it went out: an argument guard, a mode policy, an egress refusal. | Yes. |
| `denied_response_guard` | A rule you wrote withheld the backend's answer. | Yes. |
| `denied_gatekeeper`, `denied_response_gatekeeper` | The [semantic guard](semantic-request-guards.md) judged the call or its answer against your written policy and refused it. | Yes. |
| `decoy_tripped` | An agent called a decoy tool or used a planted credential. | **Look at these.** It is an alarm about the agent, not about the call. |
| `backend_error` | The upstream failed: network, timeout, auth, a provider's spend cap. | Bursts mean a backend outage. |
| `needs_auth` | The backend needs a human to sign in first. | Until someone signs in. |
| `cancelled` | The call was abandoned before it finished (client hang-up or shutdown). | Around restarts. |
| `gateway_error` | A bug in Trentina. | **Never.** The only outcome that should page anyone. |

### Calls by profile

Calls per interval for each agent seat ([profile](profiles.md)). Each agent should have a steady shape of its own; a seat that suddenly multiplies its rate is the first thing to check in a runaway agent.

### Detections by layer

Detections credited to each [defense layer](defense-pipeline.md):

- **L1**: pattern rules (hidden text, encodings, known injection shapes).
- **L2**: a small classifier model running inside Trentina.
- **L3**: an LLM judge, asked only when needed.

A burst of L2 with no matching L3 usually means L2 false positives, not an attack.

### Top flagged tools

Which backend and tool drew the most detections, and from which layer. If the same read-only tool keeps getting flagged by L2 alone, the flags are probably false positives. If L3 flags a tool that writes, look up the call in the audit log: every span carries `trentina.call_ref`, the same value as the audit row and its detections.

### Duration p50 / p95 by kind

Median and 95th-percentile duration, split by what the call reached: `tool` (an MCP backend), `fetch`, `model`, `tunnel` and so on. If p95 climbs while p50 holds, a few slow calls are dragging; if both climb, a whole backend is slow.

### Egress tunnels by profile

Direct network connections each agent opened through Trentina's [client egress](client-egress.md). Spikes are an agent going around its tools.

### Model calls refused or failed

Calls through the LLM proxy that did not come back `ok`, by outcome. A provider outage or spend cap shows as `backend_error`; a request Trentina would not forward (a provider-side tool, an unlisted model) as `denied_guard`.

## See Also

- [Telemetry Export](telemetry.md): what each span carries and how export behaves
- [Audit Log](audit-log.md): the full record behind every number here
