# Tool Discovery

A client that sends every listed tool's schema with every request pays for
all of them on every turn. Measured on Kagetora (Hermes, #473): 361 tools,
about 160K tokens a call, about 95% of it schemas. Claude Code defers MCP
tools and searches them itself, so the same gateway costs it far less. A
client with no search of its own needs the gateway to list less.

`tool_discovery` is a profile setting, off by default. It works at the MCP
layer, for any client and any model: nothing in it is specific to a
provider.

```yaml
profiles:
  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    backends:
      monitor: {url: "http://monitor:8000/mcp"}
      systemd: {url: "http://systemd:8000/mcp"}
      podman: {url: "http://podman:8000/mcp"}
      mail-work: {url: "http://mail-work:8000/mcp", name_tag: work}
      mail-home: {url: "http://mail-home:8000/mcp", name_tag: home}
    tool_discovery:
      mode: search               # off (default) | search | dynamic
      core: [unit_status, fetch] # served names (globs) always listed
      top_k: 8                   # find_tools results, at most 25
      categories:                # optional; default one per backend
        infra: [monitor, systemd, podman]
        mail: [mail-work, mail-home]
      describe_backend: false    # '<category>: ' leads each description
```

## Modes

**`off`** lists every tool, as before. `categories` and `describe_backend`
still apply; they help a client that searches by itself (below).

**`search`** lists the core tools plus two of the gateway's:

- `find_tools(query, category?, limit?)` returns the best matches with their
  input schemas, ready to call.
- `call_tool(name, arguments)` calls one. It re-enters the router with the
  real served name, so the call meets every rule a direct call meets:
  allowlist, modes, argument normalization, parameter guards, guarded
  execution, response guards, the perimeter, paging. The audit row is the
  real backend and tool, and it is the only row; guarded execution judges
  the real tool. `call_tool` cannot call a discovery tool.

**`dynamic`** lists the core tools plus `load_tools(category | query)`.
Loading adds a category's tools, or a query's best matches, to the
session's list and pushes `notifications/tools/list_changed` to that
session, so the client lists them under their real names and hooks keyed
on those names keep working. It needs an MCP session (`Mcp-Session-Id`); a
stateless client is refused and should be given `search`. What a session
loaded is dropped when the session ends. Whether a client acts on
`list_changed` is the client's: test it before choosing this mode.

`read_part` is always listed when the profile has it: a profile handed
part 1 of a response must be able to ask for part 2.

A tool left off the list is not forbidden. The allowlist is the policy, and
a direct call to a served name routes as it always did.

## Which mode

| Client | Mode |
|--------|------|
| Claude Code, or any client with its own tool search | `off`. Its permissions and hooks key on `mcp__<server>__<tool>`; `call_tool` would hide the real name from both |
| Hermes with `tools.tool_search` on | `off`: Hermes defers MCP tools itself |
| A client without tool search, with sessions and `list_changed` | `dynamic` |
| Anything else without tool search | `search` |

## What is judged

`find_tools` searches the profile's served aggregate: tools the allowlist
kept, whose descriptions the perimeter judged and compression and schema
compaction shaped. It returns that text and nothing else, so it delivers
nothing tools/list would not have. A denied tool is never found. The
discovery tools' own words, and the category line in the session
instructions, are the gateway's and the operator's (backend and category
names from the profile), never a backend's. `PERIMETER_VERSION` does not
move.

Category names, and backend names where no category groups them, reach the
agent: in the instructions, the `category` enums and `describe_backend`'s
prefix. Under `short_names` an agent did not otherwise see backend names.
Name categories for what an agent should know. A honeypot profile refuses
`tool_discovery` at load: it holds only what the loader names, and a
category could say which backends are decoys.

## Helping a client that searches by itself

Claude Code sees tool names and server instructions until it searches. Two
settings help it without renaming anything, so `tools_allow` and hooks are
untouched:

- `categories` (or any mode but `off`) adds one line to the session
  instructions: `Tool categories: mail (mail-work, mail-home); infra (...)`.
- `describe_backend` begins each served description with `<category>: `,
  so a search over descriptions finds `read` under `web` and `get_page`
  under `wiki`.

Prefixing tool names with their backend was considered and rejected: it
renames every tool, which breaks allowlists and hooks.

## Search and its accuracy

`gateway/tool_search.py`, deterministic and local, no model:

- BM25F over the served name and the category and backend (weight 2 each)
  and the description (weight 1). Query words are stemmed and widened by a
  short table of synonyms agents use for the same action.
- Character trigrams of the query against name and category fill what BM25
  leaves empty: a typo, a fragment of a name. Fused by reciprocal rank they
  pushed right answers down at every weight tried, so they only fill.

`benchmarks/tool_search.py` runs `corpora/tool_search.py`: 149 tools in 20
backends and 7 categories, the shape of an operations-and-office profile,
and 81 queries worded by intent. 32 are held out from tuning.

| Queries | recall@1 | recall@3 | recall@8 | MRR |
|---------|----------|----------|----------|-----|
| All (81) | 0.778 | 0.926 | 1.000 | 0.850 |
| Held out (32) | 0.688 | 0.844 | 1.000 | 0.788 |

`find_tools` returns 8 by default, so recall@8 is what an agent meets: the
right tool was among the results for every query. The held-out set was
looked at once, while fixing the stemmer; read its figures as an upper
bound. `tests/test_tool_search.py` holds the floor.

No embedding model ships in v1. One would need a model in the image, an
export stage and a gate of its own; this benchmark decides whether it has
earned that.

```bash
uv run python benchmarks/tool_search.py --misses
```

## Related

- [Per-Agent Profiles](profiles.md)
- [MCP Gateway](gateway.md#tool-names)
- [Guarded Execution](guarded-execution.md)
