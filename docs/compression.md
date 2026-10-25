# Tool Description Compression

*Part of Trentina's **Token savings** promise; see [Why Trentina](../README.md#why-trentina).*

Trentina compresses MCP tool descriptions as they pass through the gateway, reducing context token usage by 70-77% without affecting tool usability. Compressed descriptions are cached in SQLite so the LLM is only called once per unique description — after the first run, it's a local lookup.

## Why This Matters

MCP servers ship verbose tool descriptions. A typical Google Workspace backend has 130 tools, each with multi-paragraph descriptions, inline examples, and detailed parameter documentation. Across 20+ backends, this can consume 15-25K tokens of context on tool definitions alone — before the agent does any actual work.

In the Crunchtools deployment, 154 tool descriptions went from 62K to 17K characters.

Agents don't need verbose descriptions to use tools correctly. Tool names, parameter names, and type schemas carry enough signal for capable models. The prose is redundant.

## How It Works

### Compression Pipeline

Compression is the `summarize` transform on the tool-description channel
(#176): the same act as summarizing a tool response, on a different ingress.

1. **Lazy trigger**: on the first `tools/list`, Trentina walks the backends
   whose `preprocess_tool_descriptions` names `summarize`, in the background.
2. **Cache check**: each tool description is hashed (SHA-256); a hit is a dict
   lookup, no model call.
3. **Batch compression**: misses go to the operator's model (the service
   identity, [Operator](operator.md)), five tool descriptions or twenty
   parameter descriptions per call, with a schema-constrained response.
4. **Cache storage**: results shorter than the original are stored in SQLite,
   keyed by hash, so the same text from any backend or profile is one entry.
5. **Passthrough on failure**: a model that is unavailable leaves the original
   description in place.
6. **Background swap**: nothing compressed is served until the aggregate is
   rebuilt. When a run banks anything, every profile's list is rebuilt in the
   background, the new text is judged there as model output, and the new list
   replaces the cached one when it is done. Clients keep the list they have in
   the meantime, and a restart's first `tools/list` still matches the verdict
   cache.

### Parameter descriptions (0.38.0)

Until 0.38.0 only the tool `description` was compressed, and the prompt told
the model to leave parameters to the schema. On a 376-tool profile that left ~95 KB of a
400 KB tool list untouched. Each parameter description is now:

1. **Trimmed** of what its own schema already says: a leading `Optional.` or
   trailing `(optional)` on a parameter that is not required, and a trailing
   `Defaults to X.` when X is the schema's `default`. Deterministic, no model.
2. **Compressed** by the model when the trimmed text is still 80 characters
   or longer, with the tool and parameter name as context. The prompt keeps
   meaning, units, formats, allowed values and constraints.

The cache key includes the schema default the trim compared against, so the
same words over two different defaults are two entries.

### Configuration

```yaml
backends:
  gws-personal:
    url: "http://gws-personal:8000/mcp"
    preprocess_tool_descriptions:
      processors: [summarize]   # compress tool and parameter descriptions
  slack:
    url: "http://mcp-slack:8000/mcp"
    # nothing set: descriptions are served as the backend wrote them
```

`compress_descriptions: true`, the pre-0.38.0 spelling, was removed in
0.40.0 and is now a load error. Only `summarize` is valid on this channel.

## Real-World Results

From the CrunchTools deployment (154 tools across 21 backends):

| Metric | Value |
|--------|-------|
| Tools compressed | 154 |
| Original characters | 62,014 |
| Compressed characters | 17,228 |
| **Savings** | **72%** |
| Estimated tokens saved | ~11,196 |

### Per-Backend Savings

Some backends benefit more than others — servers with verbose, example-heavy descriptions see the largest reductions:

| Backend | Reduction |
|---------|-----------|
| Memory | 91% |
| Jira | 87% |
| Google Workspace | ~75% |
| CrunchTools servers | ~60% |

### Total Context Cost

With both tool filtering and compression applied, the entire 154-tool surface fits in approximately 4,300 tokens — roughly the size of a short blog post. Without compression, the same tools would consume ~15,500 tokens.

## What Gets Compressed

- **Tool descriptions** — the `description` field in the tool definition
- **Parameter descriptions** — the `description` fields inside
  `inputSchema.properties` and `$defs` (0.38.0)

## What Stays Unchanged

- **Tool names** — always preserved exactly
- **Parameter names** — always preserved exactly
- **Parameter types** — `string`, `integer`, `boolean`, etc.
- **Required fields** — the `required` array
- **JSON schema structure** — `oneOf`, `anyOf`, `enum`, etc.

The structural schema is what agents actually need to construct valid tool calls. The prose descriptions are supplementary context that compression can safely reduce.

## Monitoring

The `quarantine_stats` tool includes compression metrics:

```json
{
  "compression": {
    "tools_compressed": 154,
    "original_chars": 62014,
    "compressed_chars": 17228,
    "savings_percent": 72,
    "estimated_tokens_saved": 11196
  }
}
```

## Schema compaction

Descriptions are prose; inputSchemas are mostly pydantic boilerplate, and they
are compacted deterministically with no model and no cache
(`gateway/schema_compact.py`). Three rules:

- `anyOf: [X, {type: null}]` with `default: null` on an optional property becomes X.
- `default: null` on any other optional property is dropped.
- `$schema` is dropped.

Compaction only **tightens**: every argument set valid under the served schema
is valid under the backend's. The agent loses the explicit `null`, and omitting
the property is still valid. `additionalProperties: false` is kept, because
dropping it would loosen the schema and invite arguments the backend refuses.

It runs after the perimeter scan. Because it only deletes, every string the
agent reads was already judged, so the verdict cache is untouched and enabling
it re-judges nothing. It is on by default; `compact_schemas: false` on a
backend turns it off.

Measured on the lotor tool cache (800 tools, 26 backends): 519k → 461k schema
characters, 11%, about 15k tokens.

Since 0.38.0 the same step drops three fields no agent reads: `outputSchema`
(34 KB on a 376-tool profile), and the top-level `title` and `annotations.title`, which
repeat the name. Results are still validated against the backend's own
outputSchema, which the backend session holds.

## Related

- [Tool Filtering](tool-filtering.md) — the first layer of context reduction (removing tools entirely)
- [MCP Gateway](gateway.md) — where compression sits in the gateway pipeline
- [Per-Agent Profiles](profiles.md) — enabling compression per-backend
