# Security Design Document

This document describes the security architecture of trentina, the MCP gateway. Deployment containment is in [docs/deployment-hardening.md](docs/deployment-hardening.md).

## 1. Threat Model

### 1.1 Assets to Protect

| Asset | Sensitivity | Impact if Compromised |
|-------|-------------|----------------------|
| Consuming agent's tool-calling capabilities | Critical | Attacker uses agent to send emails, modify files, call APIs |
| API credentials (LLM providers, OAuth, connected systems) | Critical | Data theft, unauthorized access |
| Data in connected systems | High | Exfiltration, modification, deletion |
| SQLite blocklist database | Low | Detection history exposed |

### 1.2 Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Malicious website operator | Plants injection in page content | Tool hijacking, data exfiltration |
| Compromised legitimate site | XSS injects prompt injection | Lateral movement via trusted domain |
| Malicious project contributor | Injection in README, comments, CI | Privilege escalation via code review |
| SEO poisoning | Injection in search results | Agent manipulation |

### 1.3 Attack Vectors

| Vector | Description | Mitigation |
|--------|-------------|------------|
| **Hidden HTML injection** | display:none, off-screen, same-color text | The `html` pre-processor converts markup to Markdown, which cannot express hidden text; L1 counts what it finds |
| **Invisible unicode** | Zero-width chars, bidi overrides | L1 counts them in attack context and strips them from L2's copy |
| **Encoded payloads** | Base64/hex instruction injection | L1 detects; L2 and L3 judge |
| **Exfiltration URLs** | Markdown images with data in query params | L1 detects; the egress guard refuses non-global addresses |
| **LLM delimiter spoofing** | Fake im_start, INST, Human: | L1 detects known delimiters |
| **Instruction override** | "Ignore previous instructions" and kin | L2 (local classifier) |
| **Semantic injection** | Instructions disguised as text, social engineering | L3 quarantined LLM, best effort |
| **LLM laundering** | P-LLM rephrases quarantined content | Not defended (requires CaMeL $VAR tokens) |

## 2. Security Architecture

### 2.1 Defense in Depth Layers

Every untrusted payload, at every ingress (web, tool responses, tool
descriptions, Matrix, LLM completions, alerts), runs all three layers. None
can be switched off; an absent layer is a gap that `block` and `redact` refuse
on. Details and measured catch rates: [docs/defense-pipeline.md](docs/defense-pipeline.md).

```
+---------------------------------------------------------+
| Layer 1: Deterministic checks (l1/)                      |
| - Hidden-content, invisible Unicode, encoded payload,    |
|   exfiltration URL and delimiter counts                  |
| - Exact directive patterns, plus evasion undoing         |
| - Normalizes a COPY for L2; never modifies delivery      |
+---------------------------------------------------------+
| Layer 2: local ONNX classifier; the model is a setting   |
| - Reads the original and, when L1 changed it, the copy   |
+---------------------------------------------------------+
| Layer 3: Quarantined LLM, briefed with L1 and L2         |
| - NO tools, NO SDK, NO memory                            |
| - Answers held to a response schema; off-schema is a gap |
| - Finding types are a closed enum: no L3 prose reaches   |
|   an agent                                               |
+---------------------------------------------------------+
| Cumulative memory: SQLite blocklist                      |
| - Written by deterministic code only                     |
| - A refused source stays refused for its TTL             |
+---------------------------------------------------------+
| Trust allowlist: operator configuration                  |
| - Not agent-controlled                                   |
| - Turns a `block` refusal into `redact`; all three       |
|   layers still run                                       |
+---------------------------------------------------------+
```

Around the layers: the egress guard (`egress.py`) pins every gateway-side
fetch to a resolved, global address; file reads are confined
(`tools/confine.py`); parameter and response guards hold tool calls to
operator policy; `posture.py` checks the container's own containment.

### 2.2 L3 Architectural Quarantine

The quarantined LLM's security comes from architectural constraints, not prompt engineering:

1. **No tools**: no provider's request body may carry a tool, function, plugin, provider-run search or MCP key. Every driver refuses one at runtime before sending (`providers/base.py` `enforce_no_tools`, #318).
2. **No SDK**: raw httpx REST calls, so no SDK can configure a tool by accident.
3. **No memory**: each request is stateless.
4. **No write access**: its answer is parsed and schema-checked by deterministic code (`quarantine/schema.py`). It cannot write to the blocklist or any other state, and none of its text is delivered to an agent.

### 2.3 Input Validation

All inputs are validated through Pydantic models:

- **URLs**: Must be valid HTTP/HTTPS
- **File paths**: No path traversal (..), text files only, size limited
- **Prompts**: String inputs (no injection risk to server itself)
- **Extra fields**: Rejected (Pydantic extra="forbid")

## 3. Supply Chain Security

### 3.1 Container Security

Built on **[Hummingbird Python](https://quay.io/repository/hummingbird/python)** for minimal CVE exposure.

### 3.2 Dependency Minimization

No LLM provider SDKs. Direct REST calls via httpx eliminate their dependency trees.

## 4. Security Checklist

Before each release:

- [ ] All inputs validated through Pydantic models
- [ ] L3 request body verified: no tools, no functionDeclarations
- [ ] No shell execution
- [ ] No eval/exec
- [ ] Error messages scrub API keys (SecretStr)
- [ ] Dependencies scanned for CVEs
- [ ] Container rebuilt with latest Hummingbird base
- [ ] Gourmand passes (defensive_error_silencing check)
- [ ] Live L3 on OpenRouter and the boundary-review eval pass on `main`, run by hand ([docs/by-hand.md](docs/by-hand.md#before-each-release)): CI holds no provider key, so nothing else runs them

## 5. Reporting Security Issues

Report a vulnerability privately through [GitHub's private vulnerability reporting](https://github.com/crunchtools/trentina/security/advisories/new). Do NOT open a public issue for one.

### Scope

In scope: the gateway's own code under `src/trentina/`, the published images `quay.io/crunchtools/trentina` and `quay.io/crunchtools/trentina-l2-model`, the Cockpit plugin, and this repository's GitHub Actions workflows. That includes a planted instruction that gets past all three layers, and any attack on the gateway itself: [`.oss-scanner/threat_model.md`](.oss-scanner/threat_model.md) lists where untrusted input enters and the invariants that must hold.

Out of scope: anything the threat model lists as not defended ([`.oss-scanner/threat_model.md`](.oss-scanner/threat_model.md#out-of-scope)) or as a known gap ([docs/defense-pipeline.md](docs/defense-pipeline.md#known-gaps)), unless you show it is worse than documented; a model jailbroken directly by its own user; and a deployment that drops the containment in [docs/deployment-hardening.md](docs/deployment-hardening.md).

### What to expect

- Acknowledgement within 5 business days.
- An assessment (accepted, needs more information, or declined, with the reason) within 10 business days.
- A fix target of 30 days for critical and high severity, 90 days otherwise. The fix ships as a signed image release; the advisory is published with it and credits you unless you ask otherwise.

### If you get no reply

If the advisory has had no response after 5 business days, open a public issue titled "Security contact requested" with no details of the vulnerability, and mention @fatherlinux. We will reply on the private advisory.
