# agent-egress-bench kit (#507)

Everything the third-party [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench)
needs to drive Trentina, as config. No Trentina code is written for the bench:
the gateway under test is the shipped image with `profiles.yaml` below.

| File | What it is |
|---|---|
| `profiles.yaml.in` | The gateway: a `forward` instance for the fetch adapter, the bench's MCP fixture as a backend, one `bench` profile. `@MODE@` and `@FIXTURE_URL@` are filled in at run time. |
| `start-gateway.sh` | Writes `profiles.yaml` and starts the gateway. The runner calls it as the MCP plugin's `start_command`; the fetch run calls it directly. |
| `shim.conf` | nginx in front of `/proxy/forward/bench/`: the fetch adapter sends no credential, so the shim adds the bench profile's bearer. The route's own auth is unchanged. |
| `mcp-plugin.json` | The runner's `mcp-gateway` plugin: endpoint, bearer and Trentina's deny marker. |
| `tool-profile.json` | The runner's tool profile. Claims are labels; they select nothing. |

`.github/workflows/benchmark-decoys.yml` (`job: agent-egress-bench`) runs both
adapters in `flag` and in `block` and uploads each summary JSON. The bench's
http_proxy (TLS-intercepting CONNECT) and websocket rows are not served: known
gap 26, reported as measured.

## What the MCP gateway adapter can and cannot measure here

The bench's MCP fixture offers a case's tools only to a `tools/list` carrying
that case's `_meta.aeb_request_identity` (and session). The adapter assumes a
pass-through gateway. Trentina is not one: it aggregates every backend's tools,
caches and pins each list, and never forwards a client's `_meta` upstream —
which is the rug-pull defense. So the fixture's per-case tools never reach the
served list, and the adapter reports `delivery_unavailable` ("Unknown tool")
rather than a verdict. Those rows are published as measured, not as blocks or
misses; changing the gateway's caching to suit the harness is not on the table.
The scored run is the fetch adapter through `forward`.
