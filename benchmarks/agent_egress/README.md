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
