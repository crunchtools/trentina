# Three-Layer Defense Pipeline

*Part of Trentina's **Security** promise; see [Why Trentina](../README.md#why-trentina).*

Trentina runs untrusted content through three independent detection layers before it reaches your agent. Each layer catches attack categories the others miss. No single layer — structural, classifier, or LLM — covers everything.

## Two roles: guards decide, pre-processors transform

Everything Trentina wires into a request path is one of exactly two things. If you are adding a driver and it seems to be neither, it is one of them and you have not decided which yet.

**Guards make the final call on admission to the trust perimeter.** Nothing else does. There are three kinds and they are named here so that "what decides?" is answerable from the docs rather than from `git log`:

| guard | what it judges | where |
|---|---|---|
| **Parameter guards** | the *arguments* of a `tools/call`, after the tool-name allowlist and before the backend is contacted | `gateway/guards.py`, [parameter-guards.md](parameter-guards.md) |
| **Response guards** | the backend's *result*, after the call returns and before anything is transformed, scanned or relayed | `gateway/guards.py`, [response-guards.md](response-guards.md) |
| **The scanner** | content, through L1 → L2 → L3 below | `defense.py` — and `defend()` is the only entry point, enforced by `tests/test_defense_contract.py` |

A guard also decides **what it reads**. On a payload too large or too opaque to scan whole, a pre-processor selects which strings reach L1/L2/L3 and accounts for every byte it declined — coverage, a skip histogram by reason, and `low_scan_coverage` below the floor. The guard still makes the call; it is simply told what it is looking at.

**Pre-processors are everything before that.** They run outside the perimeter, their output is exactly as untrusted as their input, and everything they emit crosses the guards on the way in. They may decode, decrypt, reduce, summarize, normalize, split and reshape — the contract is transformation generally, not reduction (`preprocess/base.py`, and [token-routing.md](token-routing.md) for how they are configured).

### Where the line falls

One rule separates the roles:

> **A pre-processor never bypasses `defend()`.** Everything it emits is scanned. Whether the *delivered* bytes are its output or the untouched original is the **call site's** decision, not the driver's.

`gateway/transform.py` delivers what the chain returned. `gateway/matrix_proxy.py` forwards the upstream ciphertext, because the agent must decrypt for itself. Where the two differ, the call site accounts for the gap.

**Scanning something different from what you deliver is not an anomaly — it is how L1 works.** L1 normalizes a copy for L2 to read and delivers the original untouched, because a Nagios alert or a CVE ticket discusses attacks in the words attacks use.

An earlier revision of this page ruled the opposite: that a pre-processor may never open a gap between what is scanned and what is delivered, and used that to make scan-view extraction a separate kind of driver. The rule does not survive contact with L1, and the split it justified is gone. It is recorded here because the reasoning was plausible and someone will reconstruct it.

Failure modes point in whichever direction hides nothing. A text pre-processor that fails delivers and scans **its own input** — the original, or the floor's output when a required processor ran first; one that selects what to read fails to reading **everything**. Same rule, different thing owned. The exception is a processor the call depends on: a profile's `required` floor, and anything an internal tool was asked to run, fail **closed** — the call is refused rather than handed something other than what was asked for.

Output is minified by default and the agent asks for exact text per call with `trentina_preprocess: false`, above the profile's floor ([Profiles](profiles.md#minifying-and-exact-text)). The choice changes what is delivered, and so what is judged, never whether it is judged. When conversion deleted markup that hid text from a human reader, L1 counts the hiding on the original and L3 is told, on proxied responses as on the internal tools (#229).

## What crosses the pipeline

Everything entering through the gateway is judged at its ingress — the firewall model: filter where content enters, once.

- **MCP tool responses** from every remote backend: text blocks, resource text, and every string leaf of `structuredContent`, judged as one document (recorded as `source_type=tool_response`). Image blocks, and resource blobs an agent could open (an image, a PDF, an archive), cannot be read by any layer yet: they are the `binary_unread` gap, which block and redact refuse and flag delivers with the warning (#367). A blob that is a key or random bytes is counted and read by its type.
- **Tool definitions** on every `tools/list`: name, title, description, `inputSchema`, annotations — the MCP tool-poisoning channel (`tool_description`). Runs on post-compression text; a description the compressor rewrote is model output and gets unconditional L3.
- **Matrix**: `/sync` and room `/messages` responses, buffered and judged whole (`matrix_sync`). E2EE rooms are ciphertext on the wire; with `preprocess.decrypt` configured the proxy terminates Megolm to build the L2 input and forwards the original ciphertext untouched, so the homeserver never sees plaintext and the agent still decrypts for itself. Decryption is read-only, additive and ephemeral — recovered plaintext exists only in the L2 input. Without it, encrypted rooms are outside what the gateway can read, and the coverage gap is counted and reported rather than assumed.
- **LLM completions** through the proxy, judged post-stream (`llm_completion`).
- **Alert webhooks** (`alert`), and the standalone web tools (`safe_*`, `quarantine_*`).

**The mode is per call, the policy per profile.** `defense.modes` lists what the agent may choose through `trentina_mode`, which the gateway inserts into every tool; `defense.enforcement` is the default an omitted mode resolves to — `flag` (content delivered intact with a `_trentina_warning`) or `block` (flagged responses refused). See [Profiles](profiles.md#content-modes). `TRENTINA_ENFORCEMENT_OVERRIDE=flag` is the kill switch, and beats the call's own choice.

`redact` cannot be the enforcement mode, because `enforcement` is the default an omitted `trentina_mode` resolves to, and a call that omits the mode carries no extraction prompt. It is available per call through `defense.modes` since 0.32.0: the call supplies the question, `trentina_mode: {"redact": "<question>"}` since 0.39.0 (a separate `trentina_prompt` before), which is what a proxied response lacked. `extract`, its pre-0.25.0 spelling, loads as `block`.

The PUSH paths set it themselves, because no agent is waiting to be asked: `alert_ingress.enforcement` defaults to `flag`, so a Nagios page forwards with the caution attached. The Matrix path has no mode for flagged content on purpose — refusing a streamed `/sync` response breaks the client's sync loop rather than dropping a message — so a flagged response forwards annotated. An *unjudged* one is different (0.43.0, #227): over the admission cap, past the scan deadline, or missing a required layer. Under `matrix_ingress.unjudged: withhold`, the default, one rule strips its language: anywhere in the response, a string survives only as a single token (at most 255 characters, no whitespace) outside the prose fields (`body`, `topic`, `displayname`, `status_msg`, ...), and a dict key only as a single token; a list element that is a bare alphabetic word is withheld as well, since a sentence can be split one word per element (Matrix's own lists of IDs, aliases and servers all carry a sigil or dot). IDs, sync tokens, types, memberships and timestamps pass, so the client's room model holds and `next_batch` is honoured; no sentence does, whether in content, `unsigned`, relations or an extension. A room event is rebuilt as a `[trentina] withheld` notice keeping its relation, rebuilt from an allowlist (`gateway/matrix_relation.py`, #296): `rel_type` from `m.thread`, `m.reference` and `m.replace`, `event_id`, `m.in_reply_to.event_id` and a boolean `is_falling_back`, each ID event-ID shaped. A reaction's relation and its free-text `key` are not kept. E2EE to-device events (keys, ciphertext) are walked the same way with one allowance: a token may be as long as ciphertext is. Any whitespace text in them is withheld too. `_trentina_warning.withheld_events` counts the events. A response that is not a JSON object, cannot be parsed, or is over the proxy's 32 MB buffer is refused with 502 instead, which stalls that client's sync rather than leak it, under `annotate` as well (#296): none of those can carry a warning or have a reserved key stripped. `annotate` otherwise restores the pre-0.43.0 forwarding, with `scan_failed` in the warning when the judge raised.

Which responses are judged (#296): every 200, deny by default. `/members`, `/state`, profiles and the room directory return names and topics any user chose, and were forwarded unread while the proxy judged seven listed paths. The exempt set (`matrix_proxy._ACKS`, matched on the whole path and the method) is the acknowledgement of a write, the auth flows, one-time and backup keys, plus every DELETE and OPTIONS. A media download forwards unjudged only as `image/*`, `audio/*`, `video/*` or `application/octet-stream`: no layer reads pixels, and an E2EE attachment is ciphertext. Any other non-JSON body is judged as text; flagged or unjudged, it carries `X-Trentina-Warning: <risk level>`, and unjudged under `withhold` it is refused. Under `withhold` the proxy judges with `stop_on_partial`, so an over-cap response costs a token count rather than a full L2 scan.

**The perimeter never edits what it judged.** L1 detects; it does not censor. What the agent receives is byte-identical to what entered the perimeter, or (under `block`) nothing plus the warning. The one rewrite is Matrix's, and it applies only to what was NOT judged: an unjudged response keeps the tokens its client needs and loses its language, because refusing a `/sync` would break the client's loop. Transformation belongs to the pre-processors, which run OUTSIDE the perimeter, BEFORE it, and whose output is what enters it and what is delivered. What the layers read is built from that output by the unpack stage (see the [Layer contract](#layer-contract)), and never replaces it: since 0.38.0 they minify by default (HTML to Markdown, JSON compacted, repeats collapsed to a count), and the response says what ran. That is a token saving, not a security edit, and the agent declines it with `trentina_preprocess: false`, subject to any processor the profile `required`.

## Why This Matters

Prompt injection is the critical vulnerability in agentic AI systems. An attacker plants instructions in content your agent reads — a web page, a Jira ticket, a Slack message, an email body — and the agent follows them because it can't distinguish data from instructions. The [Clinejection attack](https://grith.ai/blog/clinejection-when-your-ai-tool-installs-another) compromised ~4,000 developer machines through a prompt injection in a GitHub issue title.

The defense-in-depth approach means an attack has to evade three fundamentally different detection methods to succeed.

## Layer contract

Four rules shape every layer, and any change to a layer is held to them. `tests/test_layer_contract.py` enforces the first two.

1. **Nothing is delivered that the layers did not read, in its original or decoded form, or, for binary, by its identified type. Each layer reads it exactly once.** Pre-processing is two stages, always in this order (#365). Stage 1, the pre-processors, shrinks what will be delivered. Stage 2, the unpack stage (`unpack/scan.py`), builds what the layers read from that delivery: strict base64 and hex that decode to text are decoded in place, archives, office files and PDFs are opened and read inside (#368, #369), images are read by OCR (#370), and other binary is labelled by its signature, `(image/png, 1.1 KB, not read)`. The delivery itself is never changed. L1 and L2 run in parallel on the unpacked text, and L3 reads it after both. Redact's checks on turn 2's output follow the same rule: L1 and L2 read the delivered strings once, unpacked, as the one document turn 3 then reads (#379). Binary an agent could open and no layer can read yet (an image, a PDF, an archive this stage does not open) is the `binary_unread` gap: block and redact refuse it, and offer `flag`.
2. **Layers share findings, never inputs.** L1's counts by type and L2's label and score reach L3's briefing as structure: fixed names and numbers, never payload text. No layer reads text that another layer produced.
3. **A layer's weakness is fixed inside that layer or at model selection.** The fix is a better model, a new L1 stage, or a gate at model selection. Two gates hold L2, from opposite sides: the obfuscation gate rejects a model a trick can blind (`benchmarks/l2_obfuscation.py`, #362), and the benign gate rejects one that refuses what the gateway delivers (`benchmarks/l2_benign.py`, #411). The image build runs both at one threshold, and the gateway checks their records at startup. The pipeline never gets an extra pass, a second input, or a reshaped copy to compensate.
4. **Read time is linear in payload size, one pass per layer.** The admission cap (`CLASSIFIER_MAX_TOKENS`) is sized on that: 32K tokens is about 23 s of L2 on production CPU, well inside the 60 s MCP client timeout.

Redact's extraction turn reads the same unpacked text (`DefenseVerdict.read`), so it extracts from what was judged. Until 0.57.1 it read a copy L1 had normalized, which made L1 a cleansing layer for that one consumer (#360).

Only canonical base64 is decoded, meaning text whose re-encoding reproduces it exactly. A lenient decoder can read a non-canonical blob differently from the agent's own tools, so such blobs are read as they arrived. Decoded text carries no marker: any bracketed note in front of it made L2 flag 4 to 8 of the 14 benign corpus texts, against 1 without one ([benchmark](benchmark.md#unpack-stage-367)). L3's briefing names what was decoded and labelled instead. Archives, office files, PDFs and images are extracted in later phases (#368 to #370).

### Retired designs

- **The double L2 read (0.31.0 to 0.55.0, #359).** Whenever L1 stripped anything, L2 also read L1's normalized copy, and the stronger score won. It compensated for Prompt Guard 2, whose tokenizer a zero-width split or a fullwidth letter blinds. Measured against Horizon, the shipped L2, over 44 attacks under 7 obfuscations, it changed 1 of 308 outcomes, and on base64 it was worse than the raw bytes (36 against 44 of 44). It cost a sequential second pass that any attacker could trigger with one zero-width character, which doubled the worst-case latency. It was removed. A model with the weakness it covered now fails the obfuscation gate instead: Prompt Guard 2 fails five of the six transforms.

## The Three Layers

### Layer 1 — Deterministic Detection

L1 counts, and never modifies what the agent receives:

- **What the agent receives** (`content`) — the caller's text, untouched. A CVE ticket, a Nagios alert, or a security mail *discusses* attacks in the words attacks use; amputating those lines destroyed exactly the content an ops agent exists to read, and destroyed the evidence before the smarter layers could judge it.
- **Counts, by type** (`PipelineStats`) — hidden markup, unicode manipulation, encoded payloads, exfiltration URLs and links, LLM delimiters, directive patterns like "ignore previous instructions", forged gateway verdicts and tool calls, lines addressed to an AI reader, and, for a directory, Python files that shadow the standard library. They feed the risk score and the warning, and L3's briefing names each non-zero one (`PipelineStats.findings`, from the fixed `FINDING_NAMES` table).

To match through obfuscation, some stages work on a private normalized copy: zero-width characters removed, encoded blobs replaced, fake `<|im_start|>`/`<|eot_id|>`/`[INST]` delimiters dropped, exfiltration image URLs defanged. The copy never leaves L1 (#360). L1 hands on counts and nothing else.

The stages added for #363 (0.58.0) count forms that are findings in themselves, whatever the words say:

| Counter | Counts | Raises L1's risk |
|---|---|---|
| `forgery_gateway_verdicts` | a `_trentina_*` key written as a key, or a claim that Trentina cleared what follows (`l1/forgery.py`) | yes |
| `forgery_tool_calls` | tool-call markup, or a call object interrupting prose | yes |
| `addressed_ai_addressed_lines` | a line that turns to the AI reading it (`l1/addressed.py`); writing about agents does not count | yes |
| `unicode_soft_hyphen_words` | a word with soft hyphens between two or more letters | yes |
| `unicode_fullwidth_runs` | two or more consecutive words in fullwidth Latin letters | yes |
| `unicode_mixed_script_words` | a Latin word carrying Cyrillic or Greek lookalike letters | yes |
| `encoded_escaped_payloads` | a line whose percent, backslash or character-reference escapes decode to an instruction word | yes |
| `directives_ciphered_detected` | a line that matches a directive once read in ROT13 or backwards | yes |
| `exfiltration_exfiltration_links` | a link whose query is built to be filled in: a carrier parameter name, or a placeholder for the value | yes |
| `exfiltration_mismatched_links` | a link showing one site's URL and going to another | no: mail trackers do it on every message |

None of them fires on the corpus's 44 attacks, 14 benign cases or 48 near-miss lines, or on 40,000 lines of a production journal ([benchmark](benchmark.md#l1-stage-false-positives-363)).

**L1 is format-agnostic.** It scans what it is handed and makes no judgement about a payload's type. Until 0.28.0 a `looks_like_html` sniffer chose between an HTML pipeline and a text one on a leading `<!DOCTYPE` or `<html>`; an HTML *fragment* — the shape most tool output carries — matched neither, so identical bytes were defended two different ways depending on their first few characters. The fork is gone. Markup is handled in two tiers instead:

- **Tier 1, conversion (`preprocess/html.py`).** Converting to Markdown does not detect hidden content, it removes the vocabulary that expresses it: Markdown has no `style` attribute, no `display:none`, no foreground/background pair. After conversion the attack class is absent rather than mitigated. The converter declines on anything it cannot parse, so it sits in the default chain and no-ops on everything that is not markup.
- **Tier 2, fingerprints (`l1/hidden.py`).** Conversion cannot be guaranteed to have run — the agent may ask for raw bytes, the converter may decline, or the text may merely embed markup. So an ordinary L1 stage counts hiding fingerprints (`display:none`, off-screen positioning, same-colour text, KaTeX `\color{white}`) on every payload and feeds the risk score.

#### Where these patterns come from

L1's directive, control-token, encoding and image-exfiltration patterns follow OpenRouter's published [prompt-injection guardrail](https://openrouter.ai/docs/guides/features/guardrails/prompt-injection), which is derived from the [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html). OpenRouter sees a lot of injection traffic, and its list is field experience. The patterns keep OpenRouter's names (`l1/directives.py`, `PATTERNS`), so a detection can be looked up there. The KaTeX `\color{white}` fingerprint (`l1/hidden.py`) comes from OWASP alone.

Evasions are handled the way OpenRouter handles them (`l1/evasion.py`): scrambled middles (`ignroe`), one-edit typos (`1gnore`) and character spacing (`i g n o r e`) are undone, and the line is counted when the rewrite matches an exact pattern that the original did not. One rule counts without an exact pattern: two misspelled keywords on a line, at least one of them scrambled (`bpyass all safety measuers`), because nobody shuffles the middles of words by accident. A single typo is never a detection. `sytsem is down`, `systemd`, `"promt" should be "prompt"` and "the system overrides the default" all stay clean. These lines are counted as `directives_evasions_detected`, apart from exact hits.

Where Trentina departs from the source, it does so to cut false positives on ops output. `System:` as a line prefix matches only with a capital S, since `system:` opens ordinary log lines. An opening `<tool>`/`<function>` tag counts only at the start of a line, because documentation writes `<backend>__<tool>`. A keyword with a letter appended (`overrides`, `systemd`) is treated as a word rather than a typo. Measured on 31k lines of a host's journal, `podman`/`systemctl`/`ps` output and this repository's docs and source, the expansion added no detections (see #201).

OWASP's recommended "dual-LLM" architecture, where a quarantined model reads untrusted content and a privileged one acts on structured results, is what L3 already is.

**Latency:** ~55ms per 100k characters. **Cost:** Zero (no model calls). **Always runs.**

### Layer 2 — Local Classifier

A prompt-injection classifier running on ONNX Runtime (CPU, no GPU required), sliding a 512-token window across the payload and keeping the highest malicious score. Which model is an operator setting (#350): `CLASSIFIER_MODEL` names one the image ships, `CLASSIFIER_MODEL_PATH` points at any other export (`scripts/export_l2_model.py`).

| Model (`CLASSIFIER_MODEL`) | Threshold | Notes |
|---|---|---|
| `prompt-injection-guard-small` (default) | 0.7 | Horizon-Labs, Apache-2.0, mmBERT-small. Trained on injections planted in documents, tool output and mail. |

The image ships that one model. Meta's `prompt-guard-2-86m` shipped beside it from 0.55.0 to 0.58.0 and was dropped (#362): it fails five of the six transforms of the obfuscation gate, so one zero-width character blinded it. `CLASSIFIER_MODEL_PATH` still reaches an export of it, or of any model, for research.

**The obfuscation gate is enforced.** The image build classifies every corpus attack plain and under six transforms with the shipped model and writes the result into its `trentina-model.json` (`benchmarks/l2_obfuscation.py --record`); a model that fails stops the build. At startup the gateway reads the record: a model with a failing record, or none, is logged as `l2_obfuscation_gate_failed` or `l2_obfuscation_gate_unrecorded`, and under `TRENTINA_REQUIRE_HARDENED` the gateway refuses to start. The gate's state is part of the verdict stamp. garak's sixteen further encodings are measured against the model and gate nothing (`benchmarks/l2_encodings.py`, #423): the model reads quoted-printable and MIME, which barely change the text, and none of the others; base16 and hex are decoded before it is asked, and the rest are known gaps 21 to 23. To run your own model, export it and record the gate against it before you point `CLASSIFIER_MODEL_PATH` at it.

**So is the benign gate (#411).** The same build then runs the model, at the threshold it ships with, over 207 invented benign cases of the shapes production refused (unit properties, journals, disk-usage and container listings, metrics rows, replies that carry an identifier, agent-forum replies), each read as the gateway reads a tool response: through the default pre-processors, the text block and then every string of the structured content, unpacked. A model that flags more than 2% of the held-out cases stops the build (`benchmarks/l2_benign.py --record`). The record carries the threshold it was taken at, so a gateway started with another `CLASSIFIER_THRESHOLD` reports `l2_benign_gate_unrecorded` until the gate is run at that one. Numbers, and the two shapes the shipped model still flags, are in [benchmark.md](benchmark.md#l2-benign-gate-411-404).

Measured on our corpora (`docs/benchmark.md`, #350), the default catches 36 of 39 internal attacks to Prompt Guard 2's 8, and 21 of 39 when they are planted inside long benign documents to Prompt Guard 2's 4, flagging 3 of 150 benign documents to Prompt Guard 2's 0, at 2.4x the throughput on CPU. Two English-only DeBERTa models, ProtectAI's v2 and PIGuard, were measured and rejected (#353): they flag 29 and 67 of the 150. Prompt Guard 2 is the better detector of DAN-style direct jailbreaks (624 vs 520 of 666 on the jackhhao set, 1 and 3 false positives of 640).

Each model directory carries a `trentina-model.json`: its id, pinned revision, threshold, and which outputs are malicious. A model whose polarity cannot be read from it or its labels does not load, and L2's absence is then a gap like any other (`TRENTINA_REQUIRE_L2`). The model, revision and threshold are part of the perimeter verdict stamp, so switching models sweeps cached verdicts.

**What it misses:** whatever needs reasoning rather than pattern: social engineering and quiet exfiltration requests most of all. A low L2 score is never evidence of safety, and L3 is told so on every call.

**Latency:** per 512-token window, Prompt Guard 2 86M takes ~550ms in production and the default about 40% of that (2.4x, rotated runs on one CPU). **Cost:** Zero (runs locally). **Threshold per model, stricter per profile.**

### Layer 3 — Quarantined LLM (Q-Agent)

A quarantined LLM — `gemini-2.5-flash-lite` by default, any configured provider otherwise — that receives the **original, unmodified content** and judges it while ignoring injected instructions. It waits for L1 and L2 and is briefed with both: L1's counts by type, L2's label and score, and — unconditionally — the caveat that L2 misses attacks that need reasoning, such as social engineering and exfiltration intent, so a low score is never evidence of safety. The Q-Agent is deliberately constrained:

- **No tools** — can't execute actions even if manipulated
- **No memory** — can't be poisoned across sessions
- **No SDK** — raw httpx calls to the provider's REST API, no dependency surface
- **Small model** — less capable models are harder to socially engineer
- **Per-request canary** — every call to the model (detect, extract, verify, the summarize worker, search's L0) gets a fresh `CANARY-<32 hex>` appended to its system prompt with the instruction never to output it (`quarantine/agent.py`, `_generate_canary`). It is random per call because the source is public: a fixed string could be avoided by name. If it appears anywhere in the answer, the content talked the model into repeating its prompt, and the answer is discarded before the schema check. What that becomes depends on the caller: a judge turn is `l3_unavailable`, never clean; search's L0 is a refusal audited `blocked_defense` (`L0 canary leaked`); the summarize worker declines and the original payload goes on to the perimeter. The canary is never stored, logged or returned. It catches one kind of takeover, a leaked prompt; a payload that only asks for `clean` does not trip it. Decoy tools inside the judge, a tripwire for actions the judge itself attempts, were measured and not built (`docs/benchmark.md`, #357). Decoys offered to the agent are a different thing and do ship: [Decoy Tools and Honeytokens](profiles.md#decoy-tools-and-honeytokens).
- **Schema-checked answers** — the judge reads the content it judges, so its answer is checked against the schema it was asked for (`quarantine/schema.py`, #294) whatever the provider promises: only Gemini and OpenAI enforce one, Anthropic gets it as a hint and Ollama only `format: json`. A missing or non-boolean `injection_detected`, an off-set `risk_level`, a non-string extraction field, or a body that is not a JSON object is `MalformedResponseError`: asked once more, then `l3_unavailable` (redact: `t2_unavailable`/`t3_unavailable`), never clean. Undeclared keys are dropped and strings cut to their `maxLength`. A finding's `type` off the enum becomes `other` rather than refusing — it carries no verdict, and judges drift there.

**What it catches:** Social engineering, data exfiltration intent, authority-based attacks, subtle semantic manipulation — everything that requires understanding *meaning*, not just *pattern*.

**What it misses:** with the default `QUARANTINE_MODEL` (`gemini-2.5-flash-lite`), the Q-Agent's aggregate catch rate on attacks written to evade both L1 and L2 is 86% (see `benchmarks/results/`), not near-100% — and it drops to 33% on the `detector_meta` category (attacks targeting the detector itself). A stronger `QUARANTINE_MODEL` closes most of that gap; see `docs/benchmark.md` for per-model numbers before treating L3 as a reliable backstop.

**Latency:** 1-2s per turn (Gemini round-trip). **Cost:** Gemini API tokens — one call per payload, three in redact mode. **Always runs;** its absence is a gap, never a skip.

## Coverage

What is defended and what is not, by kind of content, as of 0.62.0. A row
changes only together with the code and the gap tests in
`tests/test_coverage_gaps.py`. #365 is the plan that closes most of the
gaps below.

| Content | The agent receives | The layers read | Block mode |
|---|---|---|---|
| Prose and plain text | the text; reply chains collapsed and repeats grouped by default | the same | judged |
| HTML | Markdown; hidden elements, scripts and comments dropped, and the hiding counted for L1 (#229) | that Markdown | judged |
| HTML with `trentina_preprocess: false` | raw HTML | raw HTML, with L1 counting hiding fingerprints | judged |
| JSON and `structuredContent` | compacted JSON; in a text block, repeated array elements collapsed to a count and a log held in a string reduced to petit's samples and summary (#419); `structuredContent` as it arrived | a text block as delivered; every string of `structuredContent`, keys included | judged |
| Base64 or hex that decodes to text (canonical only; base16 is hex in upper case) | as it arrived | the decoded text, in place, to two levels | judged; hex and base16 attacks are flagged as often as plain ones (41 of 44) and no benign text is ([benchmark](benchmark.md#garaks-encodings-423)) |
| URL-safe, unpadded or otherwise non-canonical base64 | as it arrived | the raw blob | judged, but L2 may react to the blob |
| Text in base32, Ascii85, base85, uuencoding, Braille or Morse | as it arrived | the encoding as it arrived; nothing decodes it | judged, but L2 flags nearly all of it whatever it says (gap 21) |
| Text in ROT13, Atbash or leetspeak | as it arrived | as it arrived; L1 matches its directive patterns through ROT13 | judged, with L2 detections lost and benign text flagged (gap 22) |
| Text spelled in the NATO alphabet, or written in invisible binary ("sneaky bits") | as it arrived | as it arrived | judged, and passed by L1 and L2 (gap 23) |
| Text in quoted-printable or MIME encoding | as it arrived | as it arrived, soft line breaks included | judged; L2 reads through it (42 of 44 attacks against 41 plain, 6 of 86 benign texts flagged) |
| Text hidden in Unicode variant selectors | as it arrived | as it arrived; L1 counts the run | judged; L1's count alone refuses it, whatever it says |
| Binary that is a key, an executable or random bytes, 64 characters or more, whose characters read as noise | as it arrived | a label naming its type and size | judged |
| A token that decodes to binary but whose characters read as language | as it arrived | the token as it arrived | judged |
| A zip, tar, gzip, bzip2 or xz archive inside text or JSON, a data URI or an MCP blob | as it arrived | every file in it: text unpacked like any other, an archive inside opened to two levels, other binary labelled | judged; refused (`binary_unread`) if a file in it is an image or PDF, is encrypted, or the archive breaks a limit |
| A Word, Excel or PowerPoint file (docx, xlsx, pptx) in a JSON string | its visible text as Markdown, `{"format": "docx", "as_markdown": ...}`; text the file marks hidden dropped and counted for L1 (#368) | that Markdown | judged |
| The same with `trentina_preprocess: false`, or outside JSON | as it arrived | the text of every XML part, hidden text included and counted; embedded media labelled | judged; refused (`binary_unread`) if it embeds an image or a macro |
| A PDF that `fetch` retrieved, or a base64 PDF in a JSON string | the text its pages show, as Markdown, with its links; invisible text dropped and counted for L1 (#369); a line for pages that are images and for embedded files left out | that Markdown | judged |
| The same with `trentina_preprocess: false`, or a base64 PDF in other text (up to 140,000 characters) | as it arrived | each page's text, invisible text under its own heading and counted; notes, form values, links, JavaScript, document information and metadata from every object in the file; embedded files read like files in an archive | judged; a page that is a picture, scanned or under an OCR text layer, is read from its image by OCR (#370), and refused (`binary_unread`) when OCR could not read it or it is past the sixth such page; refused too for an embedded file that cannot be read, a password, a file the reader could not finish in 20 CPU-seconds, or more than 500 pages or a million characters |
| An image (PNG, JPEG, GIF, WebP, BMP, TIFF, ICO) inside text or JSON, a data URI, an MCP image block or blob, or a page of a PDF that is a picture | as it arrived | the text OCR reads in it, and under its own heading the text too faint for a person to see, counted as hidden (#370) | judged; refused (`binary_unread`) for an image OCR could not read, one past 6 MB, the seventh and later images of one payload, or an animation of more than four frames |
| Audio, video, HEIC; a 7z, rar or zstd archive; a legacy `.doc`, `.xls` or `.ppt` | as it arrived | a label; nothing reads inside it | refused (`binary_unread`), with `flag` offered; flag delivers it with the warning |
| An MCP resource blob an agent could open and the rows above do not read | as it arrived | nothing | refused (`binary_unread`), with `flag` offered |
| An MCP resource blob that is a key or random bytes | as it arrived | nothing; counted by type | judged on the rest of the response |
| A fetched URL that is not text or a PDF (image, archive, binary) | a refusal | nothing | refused |
| A Matrix image download, under `unjudged: withhold` (the default) | the image, with the risk level in a header if flagged | the text OCR reads in it | judged; refused if OCR could not read it (#371) |
| Other Matrix media (`audio/*`, `video/*`, `application/octet-stream`, which is what an E2EE attachment is) under withhold | a refusal | nothing | refused: nothing reads it |
| A Matrix room event the gateway could not decrypt, under withhold | the withheld notice in its place; the rest of the response as judged | nothing | withheld, and counted in the warning |
| Any of those three under `unjudged: annotate` | as it arrived, media with the warning header | nothing | forwarded unjudged, by the operator's choice |
| Over the admission cap (`CLASSIFIER_MAX_TOKENS`, 32,768 L2 tokens) | block and redact: a refusal; flag: as it arrived | flag: the head only | refused |

### Known gaps

Each gap has an issue and a measurement. Where a test can hold it open,
one does; the rest name the benchmark that measured them.

1. **An image is read at the level OCR reads** (#370), and no further.
   Since 0.62.0 the unpack stage reads the text in an image with the
   PP-OCR models, twice: as it arrived, and with its contrast stretched to
   find text too faint to see. Measured: print from 8 pixels tall, at any
   rotation tried (15, 45, 90, 180 degrees), black on white or white on
   clear, through JPEG. Outside it: handwriting and stylised lettering,
   mirrored text (read as noise), type under about 8 pixels (6 pixels came
   back garbled), scripts the bundled models do not read, text in a QR code
   or steganography, and an image built to fool a model. An image is
   `binary_unread` when OCR did not run on it: over 6 MB, the seventh and
   later images of a payload, more than four animation frames, or a format
   Pillow does not open (HEIC). A PDF page that is a picture, with or
   without an OCR text layer, has its image read. A figure on a PDF page
   that also has visible text does NOT: that page is read by its text, and
   what the figure shows goes unread and uncounted.
   Audio and video have no reader. Archives and office files
   are read since 0.60.0 (#368), with these limits, each of which leaves the
   archive `binary_unread`: 7z, rar, zstd and legacy office files are not
   opened; an encrypted entry, and a zip entry compressed with LZMA, is not
   read; an archive past 1 MiB uncompressed, 256 files, a 200 to 1 ratio or
   two levels of nesting is refused whole; so is a zip with bytes its
   directory does not account for (a self-extracting stub, a file only a
   stream reader would find) and a tar or compressed stream with data after
   its end. Tested.
2. **Only canonical base64 is decoded** (#367). URL-safe and unpadded
   base64, and base64 wrapped at a width that is not a multiple of four, are
   read as they arrived, and an instruction hidden that way reaches L2 and
   L3 as a blob. MIME's 76-character wrapping decodes line by line. Strictness is
   deliberate: a lenient decoder could read a blob differently from the
   agent's own tools. Tested.
3. **Decoding stops at two levels and 140,000 characters.** Base64 of base64
   is read; a third level is read as it arrived. A longer token is
   identified from its first 4,096 characters: an openable format is
   `binary_unread`, anything else is read as it arrived.
4. **Binary with no known signature counts as read.** The table in
   `unpack/signatures.py` covers images, PDFs, archives (also behind a
   stub), office files, audio, video, SQLite and WebAssembly. Bytes matching
   none of them are labelled when the token is 64 characters or more and
   its characters read as noise, and read as they arrived otherwise. Either
   way they are not the `binary_unread` gap. A format an agent's tools can
   open that the table does not list would be delivered unread.
5. **Images of 4 by 4 pixels or less are counted as read** (tracking
   pixels, spacers), by the size a PNG or GIF header states. A letter or a
   QR code needs more pixels than that. A header can lie about its size; an
   agent's image tools then read pixels no layer did.
6. **L1 reads two ciphers and three escape forms, and no others** (#363).
   ROT13 and reversed lines are matched against the directive patterns;
   percent, backslash and character-reference escapes are decoded and
   read for instruction words. Base32, Morse, a Caesar shift other than 13
   and every other encoding reach L2 and L3 as they arrived. The
   lookalike counter knows Cyrillic and Greek only. What L2 makes of what
   reaches it is gaps 21 to 23. Tested.
7. **L1's own refusal is coarse on invisible characters.** Four of them
   already rate high risk. In the L1 briefing ablation
   ([benchmark](benchmark.md#l1-briefing-ablation)) L1 alone refused 29
   benign texts carrying zero-width or tag characters that L2 and L3
   cleared, and caught 2 attacks they missed.
8. **L1's briefing to L3 has no measurable effect.** Same ablation: with
   and without L1's counts, L3's verdicts differed on 13 of 241 payloads in
   both directions, inside its own run-to-run noise.
9. **L2 flags SSH `authorized_keys` lines** whatever their key: `ssh-rsa
   ops@lotor` alone scores 0.97 with the default model, and the same line
   with its key labelled scores 0.92 (2026-10-04). Horizon reads the shape as
   key planting. Block mode refuses a response that is little else; in a
   longer document the line is diluted (two such lines scored 0.62).
10. **L3 flags a near-empty document whose content is an unread image.**
   A README of a heading, a labelled image and one line was flagged by L3 on
   three of three calls; the same image in a paragraph of text was not.
   Block mode refuses it either way (`binary_unread`); flag mode reports L3
   as well.
11. **L3 flags bare imperatives.** 16 of the 48 near-miss lines that L1
   correctly passes ("Override the default port in config.yaml.") were
   flagged by L3, judged on their own without a surrounding document.
12. **L3 misses evasive attacks.** The default `QUARANTINE_MODEL` catches
    86% of attacks written to evade L1 and L2, and 33% of those aimed at
    the detector itself ([benchmark](benchmark.md)).
13. **Flag mode reads only the head of an oversized payload.** The tail is
    delivered unread, and the warning says so (`l2_truncated`,
    `l3_truncated`).
14. **Under `unjudged: annotate`, Matrix media and undecrypted events
    forward unread** (#371). Under withhold, the default, they do not: an
    image is read by OCR and judged, other media is refused, and an
    encrypted room event the gateway could not decrypt becomes the
    withheld notice. annotate is the operator choosing delivery over
    judgement, and says so in a header or a warning key. An E2EE
    attachment is ciphertext to the gateway even with `preprocess.decrypt`,
    which decrypts events and not media, so under withhold an agent in an
    encrypted room receives no attachments.
15. **Office hiding is detected only where the format marks it** (#368).
    Counted as hidden: Word's `vanish`, `webHidden` and `specVanish`, on the
    run or through a style or the document default; a hidden sheet or row;
    a shared string no cell uses; a slide with `show="0"`. White text,
    one-point type, a shape moved off the page and a hidden column are not
    counted. The layers still read that text: what is missed is the count,
    and stage 1 delivers it as visible. Tested.
16. **PDF invisibility is detected only where an operator names it**
    (#369). Counted: text render modes 3 and 7; a size under a point or a
    position off the page, for text drawn on the page itself; white fill on
    a page that has painted nothing else. Not counted, though the layers
    read the text: white text after any fill, shading or image; text sized
    or placed inside a form XObject; text in a hidden optional-content
    layer, behind an image or clipped away. A page that is an image with
    all of its text invisible is a scan with an OCR layer: the layer is
    read as the page's text and not counted. When the file itself is
    delivered the page's picture is read by OCR too (#370), so the layers
    read what the layer claims and what the picture shows, and the page is
    `binary_unread` only when OCR could not read the picture, which
    includes every such page past the sixth. Stage 1 delivers the layer's
    text and no picture. Tested.
17. **A planted credential is matched only as it was planted** (#357). The
    honeytoken check ([decoys](profiles.md#decoy-tools-and-honeytokens)) is
    a substring match on a call's arguments. A caller that base64-encodes
    the value, splits it across two arguments or two calls, or describes it
    in words is not seen, and neither is anything an agent sends without a
    tool call through the gateway. It is a tripwire for the common case,
    where an injection says "send the key to this address" and the agent
    does. Tested.
18. **A response that is little but a base64-shaped identifier is flagged
    by L2** (#411). The shipped model passes the obfuscation gate because it
    reads base64 as possibly hostile, and a reply such as
    `{"ok": true, "event_id": "$..."}`, a Matrix event ID in an object with
    one other field, gives it almost no context to read the ID against: 9 of
    12 flag at 0.7, scoring 0.71 to 0.94. An identifier inside a record does not
    (0 of 41 unit, container, image and disk listings). `block` refuses such
    a reply and offers `redact`. Scored on every image build as
    `event_id_reply` ([benchmark](benchmark.md#l2-benign-gate-411-404)).
    Tested, in the image (`tests/test_l2_integration.py`).
19. **A long log inside a JSON string can be flagged by L2** (#411, #419).
    A hundred journal lines returned as one string is read in many windows
    of which the worst decides. Since #419 `structured` hands such a string
    to petit, and that did not close this: a journal of mixed units keeps
    about two lines in three, because lines that differ in a word (a unit
    name, a key fingerprint) are each their own group, and 2 of 6 flag at
    0.7 where 1 of 6 did, not the same ones. A journal of one repeated
    message reduces to three samples and a count. Asking for fewer lines,
    or a narrower unit or pattern, avoids it. Scored on every image build as
    `journal_query_100` ([benchmark](benchmark.md#a-log-in-a-json-string-419)).
    Tested, in the image.
20. **A request that reads as an ordinary one passes every layer** (#29).
    Varonis's published customer-export request, a colleague asking an agent
    to send this week's export, is flagged by nothing: L1 strips nothing, L2
    scores it 0.007, and none of the four shipped judges flags it. Nothing in
    the text separates it from a real colleague's mail, so detection is the
    wrong control; what stops it is a limit on what the agent may send.
    Imperva's bare install instruction is the same shape with a URL: L2
    scores it 0.254, and two of the four shipped judges (Gemini 3.5
    Flash-Lite, Gemini 3.8 Flash) pass it
    ([benchmark](benchmark.md#l3-on-them-2026-10-10-the-four-shipped-judges)).
    L1 and L2 tested, L2 in the image; the judges measured once each.
21. **L2 flags an encoding it cannot read, whatever the text says** (#423).
    base32, Ascii85, base85, UU, Braille and Morse reach L2 as they
    arrived (gap 6). The shipped model flags 37 to 44 of 44 attacks written
    in them and 79 to 86 of 86 benign texts
    ([benchmark](benchmark.md#garaks-encodings-423)). So `block` refuses
    harmless encoded text, and a flag on such a blob says it is a blob. The
    same holds for base64 the unpack stage does not decode (gap 2): raw
    base64 is flagged 130 times in 130. L3 reads the same blob; what it
    makes of one is not measured. Tested, L2 in the image.
22. **A letter cipher costs L2 detections and adds false positives**
    (#423). Under ROT13, Atbash and leetspeak the shipped model flags 24,
    21 and 35 of 44 attacks against 41 plain, and 25, 18 and 21 of 86
    benign texts against none. L1 matches its directive patterns through
    ROT13 only, and those attacks carry none: it counted 1 of 44. Tested,
    L2 in the image.
23. **An attack spelled in the NATO alphabet, or written in sneaky bits,
    passes L1 and L2** (#423). `India Golf November Oscar Romeo Echo` is
    six ordinary words: no attack of 44 scored above 0.11. Sneaky bits
    writes a text in binary with two invisible characters (U+2062 and
    U+2064) and a zero-width space for each space. L2's tokenizer drops
    all three, so every such text scores 0.004, and L1 counts a zero-width
    character only inside a Latin word and the two operators nowhere.
    Neither is flagged once in 44. An agent has to decode either on
    purpose; L3 is not measured on them. Tested, L2 in the image.
24. **L2 flags about one post in eight on an agent-written forum feed**
    (#404). On 1,427 posts and comments from one feed the shipped model
    flagged 183 at 0.7; a third of those score 0.98 or more, so no
    threshold separates them. Of the 11 attacks a reader found among the
    first 905 it flagged 2. L2's flag refuses on its own, so `block`
    refuses each of those posts, and it keeps doing so: on every judge
    measured, L2 flags between three in ten and five in six of the attacks
    the judge clears
    ([benchmark](benchmark.md#what-l2s-lone-flag-is-worth-404)). The fix is
    a model that passes a benign gate built from this shape; the gate's
    invented forum replies do not reproduce it (none is flagged). Measured
    by `crunchtools/data-collector`, whose documents are not fixtures, so
    no test holds it.
25. **L3 flags a benign document that carries an instruction for its human
    reader** (#397). A README, runbook or support thread with "run `make
    test` before you push" spliced into it is flagged by the default judge
    with its pack 45 times in 288 under the briefing production sends, and
    118 times with no briefing; the same instructions judged bare are
    flagged about 2% of the time, which is what the packs were tuned and
    gated on. Unbriefed, Haiku 4.5 flags 84 of the 288, Gemini 3.8 Flash 31
    and Gemini 3.5 Flash-Lite 7. `block` refuses such a document and offers
    `redact`. The pack gate holds embedded documents since 1.3.0, and both
    packs measured on it since fail it by one to three cases
    ([benchmark](benchmark.md#briefing-arms-and-embedded-documents-397)).
    A judge on the generic prompts, which is any judge not reached through
    OpenRouter, flags more: 127 and 27 of 228 for the two Gemini Flash-Lite
    models. Measured by `benchmarks/detonation.py --mode judge --briefing`
    and `benchmarks/prompt_pack.py`.

### Attack coverage by layer (Prompt Guard 2, 2026-06)

Benchmarked against 105 test cases across 10 attack categories when Prompt
Guard 2 was L2. The default model since 0.55.0 also catches most of the
social-engineering and exfiltration rows (`docs/benchmark.md`, #350). L1
has only counted since 0.29.0; it never strips.

| Attack Type | L1 (Structural) | L2 (Classifier) | L3 (Q-Agent) |
|-------------|-----------------|-----------------|--------------|
| Hidden div injection | **counts** (conversion removes it) | n/a | n/a |
| Zero-width obfuscation | **counts** | reads through it with the default model | catches |
| Base64 encoded payloads | reads it decoded, so its patterns apply (since 0.57.0) | reads it decoded | reads it decoded |
| Markdown image exfiltration | **catches** | misses | n/a |
| Direct instruction override | partial | **catches** (100%) | catches |
| System prompt manipulation | partial | **catches** (90%) | catches |
| LLM delimiter injection | **catches** | catches (90%) | catches |
| Role/persona hijacking | misses | partial (80%) | **catches** |
| Social engineering | misses | misses (40%) | **catches** |
| Data exfiltration (action) | partial | misses (20%) | **catches** |

The key insight: classifiers are excellent at what they were trained for (instruction overrides) and categorically blind to what they weren't (social engineering, exfiltration). The Q-Agent covers the gap. No single model — classifier or LLM — handles everything.

### Pacing L3: the adaptive limiter

L3 is the only layer paced by someone else. Every provider call
(`quarantine/limiter.py`) waits in a FIFO queue in front of the
(provider, model) it goes to, shared by user-facing scans, the perimeter,
compression and the boot warm-up. User-facing calls are granted a slot before
warm-up work, so hundreds of tool descriptions judged at boot never make a
`tools/call` wait behind them.

The limit is found, not configured, by AIMD, the rule TCP uses:

- slow start doubles it per window until the provider first throttles;
- after that it grows by one per window of successes;
- a 429 halves it, once per congestion epoch, so a burst of 429s from requests
  that were in flight together counts once, and pauses new requests for the
  provider's `Retry-After`, or, when the provider sends none, for the
  limiter's own backoff (1s doubling to 30s, with jitter).

A throttled call is retried on the same provider after the pause, within
`TRENTINA_L3_THROTTLE_BUDGET`, and only then falls back. A 503 or a timeout is
an outage, not a capacity signal: it moves down the fallback chain at once and
leaves the limit alone.

### Boot warm-up

On a cold perimeter store, the first `tools/list` has to judge every tool
description. `gateway/warmup.py` starts that work from the FastMCP lifespan as
soon as the event loop serves, through the same single-flight build a client's
`tools/list` uses (`router.ensure_profile_build`). A client that connects
mid-warm-up joins it instead of starting its own. The warm-up logs one summary
line: its duration, profiles, tools, descriptions judged vs. cached, and each
judge's final limit and throttle count.

## Configuration

Defense settings are configured per profile:

```yaml
profiles:
  myagent:
    auth:
      bearer_token_env: TRENTINA_PROFILE_MYAGENT_TOKEN
    defense:
      enforcement: flag        # what a flag COSTS — flag | block
      # l2_threshold: 0.6      # optional: flag below the model's own threshold
```

**There are no per-layer on/off switches, and that is deliberate.** An earlier schema had
`sanitize` / `classify` / `quarantine` booleans; production ran `quarantine: false` for months
without the owner knowing, partly because none of it was wired and partly because three
unrelated words hid what they controlled. A profile behind Trentina gets all three layers, full
stop. `DefenseConfig` is `extra="forbid"`, so a config still carrying those keys does not warn —
it refuses to start.

What a profile controls is a threshold and a consequence:

- **`l2_threshold`** — how suspicious L2 must be before it FLAGS. A flag is a consequence, not
  an execution: L2 runs either way. Unset (the default), the model's own threshold decides,
  0.7 for the default model and 0.5 for Prompt Guard 2. A value below it also flags content
  the classifier labels BENIGN, so set it knowingly and measure first (#86); a value above it
  changes nothing.
- **`enforcement`** — what a flag costs. `flag` delivers the content with a
  `_trentina_warning` (the calibration mode) and `block` refuses it outright.
  `TRENTINA_ENFORCEMENT_OVERRIDE=flag` is the kill switch.

A layer that is unavailable at runtime (no ONNX model, provider down) is a degraded state that
`/health` reports and `block` refuses on. `TRENTINA_REQUIRE_L2=false` / `TRENTINA_REQUIRE_L3=false`
turn that layer's absence into a warning instead of a refusal; no setting excuses a partial read.

## Pipeline Flow

```
Stage 0  pre-processors (outside the perimeter; subtract, never absolve)
Stage 1  L1  ∥  L2          both read the payload as it arrived, once
Stage 2  L3 detect          waits for both; briefed with both
Stage 3  the mode decides delivery
```

The mode decides what is delivered, never which layers run (`modes.py`). The names are OpenRouter's guardrail actions, but `redact` rewrites through L3 rather than substituting spans — see [Content Tools](quarantine-tools.md#the-names-are-openrouters).

| mode | L1 | L2 | L3 detect | L3 extract | L3 verify | delivers |
|------|----|----|-----------|------------|-----------|----------|
| block | ✓ | ✓ | ✓ | — | — | nothing if any layer flagged; else the original |
| flag | ✓ | ✓ | ✓ | — | — | the original, plus the verdict |
| redact | ✓ | ✓ | ✓ | from the unpacked text the layers read | L1 ∥ L2 on the extraction, then L3 | a verified extraction; nothing if verify objects |

Ten rules hold on every path (#187):

1. All three layers fire. No mode, config or source property reduces the count.
2. L1 and L2 run in parallel on the arrived bytes, each reading them once, so their signals stay independent ([Layer contract](#layer-contract)).
3. L3 waits for both and sees both findings.
4. The mode decides delivery, never detection.
5. Every finding reaches the agent as structure — booleans, scores, closed-enum finding types — never as text L3 wrote. A page can steer the judge into quoting it.
6. `flag` is a security-researcher grant, almost never right for an assistant, coding agent or swarm.
7. `redact` runs L3 three times: detect, extract, verify. Verify objecting refuses; there is no fourth turn.
8. Search is not special: L0's answer, titles and URLs are one document through the same path.
9. `block` and `redact` require a verdict from every layer; `flag` delivers regardless, loudly. An absent layer can be excused per layer; a partial read cannot.
10. The allowlist never skips a layer or hides a flag. It turns a block into a redact — and a redact that fails still refuses.

The gateway applies the same rule to proxied responses and tool descriptions under `defense.enforcement` (`flag` or `block`).

## Related

- [Blocklist](blocklist.md) — cumulative detection memory across sessions
- [Quarantine Tools](quarantine-tools.md) — how the defense pipeline is exposed as MCP tools
- [Per-Agent Profiles](profiles.md) — per-profile defense configuration
