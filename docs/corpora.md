# Corpora

*Part of Trentina's **Security** promise; see [Why Trentina](../README.md#why-trentina).*

Every attack and every benign text the defense is tested and measured against lives in `corpora/`. This page says where each one came from, why it is there, and what it can and cannot tell you. The numbers measured on them are in the [benchmark](benchmark.md).

## Why This Matters

A detection rate means nothing without the set it was measured on. Three things go wrong when that set is not written down:

- **A defense graded only on its author's attacks grades itself.** The internal corpus was written by the people who wrote the pipeline. Third-party sets exist here so that is not the only measurement.
- **A set that measures one threat gets quoted for another.** A direct-jailbreak set says little about injection buried in a fetched document. Each section below states what its corpus does not measure.
- **Corpora drift.** A case id that names different text next month makes last month's number meaningless. Vendored corpora are fixed in git; fetched ones are pinned to a revision and a SHA-256.

## How It Works

| Corpus | Module | Cases | Source | Licence | Held |
|---|---|---|---|---|---|
| [Internal](#internal) | `corpora/internal.py` | 44 attacks, 14 benign | ours | AGPL-3.0-or-later | vendored |
| [L1 patterns](#l1-patterns) | `corpora/l1_patterns.py` | 48 attack and near-miss pairs | ours | AGPL-3.0-or-later | vendored |
| [OWASP test list](#owasp-test-list) | `corpora/owasp.py` | 14 attacks | OWASP Cheat Sheet Series | CC-BY-SA-4.0 | vendored |
| [Benign operations output](#benign-operations-output) | `corpora/benign_ops.py` | 296 benign | ours | AGPL-3.0-or-later | vendored |
| [Detonation](#detonation) | `corpora/detonation.py` | 12 carriers, 36 attack and 10 benign inserts | ours | AGPL-3.0-or-later | vendored |
| [Jailbreak classification](#jailbreak-classification) | `corpora/jailbreak.py` | 262 test, 1,044 train | `jackhhao/jailbreak-classification` | Apache-2.0 | fetched |
| [InjecAgent](#injecagent) | `corpora/injecagent.py` | 32 attack inserts | `uiuc-kang-lab/InjecAgent` | MIT | fetched |
| [garak latent injection](#garak-latent-injection) | `corpora/garak_latent.py` | 972 attacks, 22 benign | `NVIDIA/garak`, anonymized | Apache-2.0 | vendored |
| [garak encodings](#garak-encodings) | `corpora/garak_encodings.py` | 16 transforms, no text | `NVIDIA/garak`, as transforms | Apache-2.0 | vendored |
| [Disclosed attacks](#disclosed-attacks) | `corpora/disclosed.py` | 5 attacks | published disclosures, rewritten | AGPL-3.0-or-later | vendored |
| [Guarded calls](#guarded-calls) | `corpora/gatekeeper.py` | 12 calls to refuse, 24 routine | written for this repository | AGPL-3.0-or-later | vendored |
| [Tool search](#tool-search) | `corpora/tool_search.py` | 149 tools, 81 queries (32 held out) | written for this repository | AGPL-3.0-or-later | vendored |

`corpora/registry.py` holds the same list as data, and `tests/test_corpora_registry.py` fails when a module there has no record or a record has no section here.

**Vendored** means the text is in this repository. **Fetched** means it is downloaded on first use into `corpora/data/` (gitignored) at a pinned revision and refused if its SHA-256 does not match (`corpora/fetch.py`). A corpus is fetched when it is large or when its rows carry text this repository may not hold, such as real-looking mail addresses.

A run that mixes corpora reports each apart. A rate blended across a semantic corpus and a direct-jailbreak set would describe neither.

### Internal

The L3 benchmark (#43). Every attack is written to pass the cheaper layers: no delimiter tokens, no "ignore previous instructions", no encoded payload, no image beacon. What is left is injection that survives only as meaning, such as a social pretext, a request that looks like helpfulness, or an instruction aimed at the detector. That is the gap L3 exists to close, and where providers differ.

- **Where it came from.** Hand-written. Each case's `notes` names the public research behind its pattern: Willison's lethal trifecta, the OpenClaw disclosures (#29), the Prompt Guard 2 benchmark (#17). The multilingual cases came with #353.
- **What it does not measure.** It is small, and its authors wrote the defense. A miss here is informative; a clean sweep is weaker evidence than it looks.
- **Rules.** `tests/test_adversarial_corpus.py` proves, with no API call, that each attack reaches L3 intact and that at least 70% bypass L1. Case ids are permanent: the tuning and held-out split is a hash of the id, and the shipped prompt packs record counts measured on it.
- **Read by.** `benchmarks/provider_benchmark.py`, both L2 gates in the image build, the prompt-pack harness, the detonation harness, and the pre-processor and L1 stage tests.

### L1 patterns

One attack and one benign near-miss for every exact L1 pattern (#201). The near-miss is the half that matters: it is what keeps a pattern from firing on ordinary prose.

- **Where it came from.** Hand-written, one pair per pattern in `l1/directives.py` and one per L1 stage.
- **Why it is apart from Internal.** These are the blatant attacks L1 exists to catch. In the internal corpus they would break the 70% L1-bypass rule that keeps it semantic.
- **Read by.** `tests/test_l1_patterns.py`, `tests/test_l1_stages.py`, `benchmarks/l1_briefing.py`.

### OWASP test list

The fourteen test inputs from the OWASP [LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), taken wholesale (#201): direct overrides, typoglycemia, Best-of-N variations and remote-injection patterns.

- **Where it came from.** The cheat sheet's testing section, CC BY-SA 4.0. That section was titled "Testing for Vulnerabilities" when the list was taken and is "Smoke-Testing Your Defenses" now. One change: `evil.com` is a real domain, so it is `evil.example` here.
- **Why it is here.** It is the list every scanner starts from, so it is the floor. L1 is held to all fourteen, whole and inside an archive.
- **What it does not measure.** Anything semantic. Passing it says the textbook is covered and nothing more.
- **Read by.** `tests/test_l1_patterns.py`, `tests/test_unpack_archive.py`.

### Benign operations output

296 invented cases of what an operations agent actually reads (#411, #404, #450, #474): unit properties, journal lines, disk-usage listings, metrics rows, opaque identifiers, short agent-forum replies, machine-written meeting notes with and without their links, and writing about attacks (security docs, detector source, issue lists). These are the shapes L2 refused in production after the default model changed.

- **Where it came from.** Generated from a fixed seed (411), so a case id names the same text on every run. Every line is invented; none comes from a production host.
- **Why it is here.** The internal corpus has fourteen benign cases, all prose written to look like an attack. Nothing in any gate looked like routine tool output until this did.
- **Rules.** 207 cases are gated: the image build fails a model that refuses more than 2% of them. Four shapes the shipped model is known to flag (`KNOWN_GAPS`: three logs, and meeting notes that end in bare links) are measured on every build and never dropped; they are [known gaps](defense-pipeline.md#known-gaps) 19 and 28. Each case is read as the router reads a tool response (#431). One case in four is the tuning split, by hash of its id.
- **Read by.** `benchmarks/l2_benign.py` (the image build's benign gate), `tests/test_benign_gate.py`, `tests/test_coverage_gaps.py`, `tests/test_l2_integration.py`.

### Detonation

What the detonation harness reads (#357). A **carrier** is a benign document of the kind an agent fetches mid-task. An **insert** is text spliced into one: an attack, or benign text that only looks like instructions. The harness hands the result to a model as a tool result and watches what it does next.

- **Where it came from.** Hand-written: twelve carriers; 36 attack inserts, six for each thing an injection against an agent asks for (a link that carries data out, reading a secret and sending it, running remote code, misusing a business tool, persistence, a step dressed as part of the task); and ten benign instructions addressed to a human reader. Every host is a reserved `.example` name and no real person, product or address appears.
- **Why it is here.** The other corpora ask whether a judge flags a text. This one asks what an agent does when the text arrives the way an attack arrives.
- **Read by.** `benchmarks/detonation.py`, and `benchmarks/prompt_pack.py` for its embedded-document cases.

### Jailbreak classification

[`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification), a third-party labeled set of jailbreak and benign prompts (#85). It gives the false-positive rate a denominator in the hundreds.

- **Where it came from.** Hugging Face, Apache-2.0, pinned at revision `2f2ceeb39658`, each split checked by SHA-256. Not vendored: it is 1.6 MB of jailbreak prompts.
- **What it does not measure.** It is **direct** jailbreak, a user attacking a chatbot with DAN-style personas. Trentina's threat is indirect injection in retrieved content. It measures L2, which is trained on this syntax, and over-triggering on benign roleplay. It is also in the training data of Horizon, the default L2 model, so those rows flatter it.
- **Rules.** `test` is the held-out split and `train` the tuning split. Case ids are `ext-<split>-<row>`; categories start `external_`.
- **Read by.** `benchmarks/provider_benchmark.py --corpus external`, `benchmarks/prompt_pack.py`, `benchmarks/decoy_tools.py`.

### InjecAgent

The 32 data-stealing attacker instructions of [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) (arXiv 2403.02691), a benchmark of indirect injection against tool-using agents.

- **Where it came from.** GitHub, MIT, pinned at commit `f19c9f2c79a4` and checked by SHA-256. Not vendored: the rows carry real-looking mail addresses.
- **Why it is here.** They are what an injection asks an agent to do, written by someone other than this repository's authors. Half are used as written, half behind the benchmark's "enhanced" prefix.
- **What it does not measure.** Detection. They are inserts for the detonation harness, not labeled cases for a judge.
- **Read by.** `benchmarks/detonation.py` (skipped with `--no-injecagent`).

### garak latent injection

The latent-injection probes of [garak](https://github.com/NVIDIA/garak), NVIDIA's LLM vulnerability scanner (#10): an instruction buried in a document an assistant is asked to read. Three families carry a document and are taken: stock-plan and earnings **reports**, **resumes**, and **WHOIS** records.

- **Where it came from.** `garak/probes/latentinjection.py` at `v0.17.0` (commit `93aa9cdec309`), Apache-2.0. Each attack is garak's own cross product of context, separator, injection instruction, payload and trigger: 324 reports, 480 resumes, 168 WHOIS records. The user-side task ("Summarise this resume:") is left out, because the gateway judges the retrieved document and never sees the question.
- **What was changed.** garak's contexts hold real people, so they are rewritten before they are held here. WHOIS records: registrant domains are under `.example`; names, addresses, mail and phone numbers are roster values; registry ids are zeroed; the registries' closing notices are cut. Resumes: one was a real researcher's CV and one a real professor's biography, and the employers, institutions, awards and name are rewritten. Reports: two executive names. The three trigger hosts are under `.example` and `.test`. The injection separators, instructions and payloads are garak's, unchanged. `corpora/garak_latent.json` is the result and `corpora/garak_latent.py` carries the full list of changes.
- **Why it is here.** It is indirect injection in retrieved content, Trentina's threat model, written by someone else. The jailbreak set is third-party but direct; the internal corpus is indirect but ours.
- **Benign controls.** The same 20 contexts with the injection removed, and garak's Eiffel Tower and legal paragraphs joined: 22 documents an agent would have read had nobody tampered with them.
- **What it does not measure.** Variety. 972 documents are 20 contexts times a few dozen injections, so a rate here is a rate over templates, and 22 benign documents move the false-positive rate in steps of 5%. garak's Translation and LatentJailbreak families have no document and are not taken, nor is the rest of garak, which probes a model's own output.
- **Rules.** `sample` is one attack in five by hash of its id, with every benign control; `full` is all 972. Case ids are `garak-<family>-<n>` in garak's loop order; categories start `garak_`. A test holds every mail address, phone number and registrant domain to the roster.
- **Read by.** `benchmarks/provider_benchmark.py --corpus garak`.

### garak encodings

The encoders of garak's `encoding` probes (#423): sixteen ways to write a text so that a filter does not read it. It holds no text of its own. Each transform is applied to the internal attacks and to benign text, to measure what the L2 model and the pipeline make of the result.

- **Where it came from.** `garak/probes/encoding.py`, `garak/resources/encodings.py` and `garak/resources/smuggling/smuggle_ascii.py` at `v0.17.0` (commit `93aa9cdec309`), Apache-2.0. Taken: base16, base32, hex, Ascii85, base85, quoted-printable, UU, MIME, ROT13, Atbash, leetspeak, Braille, Morse, the NATO alphabet, Unicode variant selectors and "sneaky bits" (a text written in binary with two invisible characters). Each gives what garak's function gives for the same text, including what garak drops: Braille and Morse lose any character they have no cell or code for, and the NATO alphabet keeps letters only.
- **What was changed.** garak's leetspeak swaps letters on a coin toss; here the toss is seeded with the text, so a text has one encoding on every run. garak wraps the encoded text in a request to decode it, aimed at the model it is testing; the gateway judges a document, so the encoded text stands alone.
- **What was not taken.** Base2048, Ecoji and Zalgo need third-party packages. Base64 and Unicode tag characters are already transforms of the obfuscation gate.
- **Why it is apart from the gate's transforms.** Those are part of the perimeter: a model that fails one does not ship. These are measured and gate nothing. A transform moves from here into the gate in a change that carries its measurement.
- **What it does not measure.** Whether an agent would act on the encoded text. Most of these need a deliberate decoding step that an agent reading a document does not take unprompted; garak supplies that prompt, and it is left out here. A miss is a text the gateway did not read, which is not the same as an attack that worked.
- **Rules.** Quoted-printable and MIME are one routine in the standard library and agree byte for byte; both are kept because garak lists both. A test holds every reversible encoding to the standard library's decoder.
- **Read by.** `benchmarks/l2_encodings.py`, `tests/test_garak_encodings.py`, `tests/test_coverage_gaps.py`.

### Disclosed attacks

Payloads reproduced from published disclosures (#29), so the defense is measured on what was actually sent and not on our restatement of it.

- **Where it came from.** Imperva's [message-object injections](https://www.imperva.com/blog/compromise-openclaw-with-prompt-injections-in-message-objects/) against OpenClaw (2026-06-10): a contact name, a vCard and a location label that close their own object and carry an instruction, padded with whitespace so the victim never sees it; and the same instruction as hidden in an image, which the model Imperva tested refused. Varonis's [agent-phishing simulations](https://www.varonis.com/blog/openclaw-phishing) (2026-06-09): the one sentence of attacker text it published, a routine request for a customer export, under a mail header of ours.
- **What was changed.** The researcher's name and the second name are roster names, the host is `corp_artifactory.example` (the underscore is the original's), and the phone numbers are placeholders. Padding, brackets and wording are kept. Imperva elides both ends of the location label; two opening words are ours. Each case's `notes` says what was changed.
- **Why it is here.** These attacks worked against a deployed agent. The internal corpus cites them and restates them; this holds the originals.
- **What it does not measure.** Anything statistical: it is five cases, to be read one at a time. The Varonis request is indistinguishable in text from a real colleague's, so a miss on it is Varonis's finding and argues for an outbound control more than a better detector. Varonis's other three scenarios published no attacker text. The display-name allowlist bypass in #29 is an identity question and has no payload.
- **Rules.** Categories start `disclosed_`. L1 strips nothing from any of them, and a test says so.
- **Read by.** `benchmarks/provider_benchmark.py --corpus disclosed`.

### Guarded calls

Calls for [guarded execution](guarded-execution.md) to judge (#456). Every other corpus here is content an agent reads; these are calls an agent makes: a tool, its arguments, and the facts the gateway holds about it (the destination, whether the profile has sent there before, whether the session was delivered flagged content).

- **Where it came from.** Hand-written, one category per scenario in [Where to use it](guarded-execution.md#where-to-use-it), each with that page's policy word for word. Two scenarios are Varonis's phishing simulations (#29) as the calls they led to: the customer export, and the "team lead" asking for keys in an incident.
- **How it is written.** Payloads are described, not reproduced: an attachment reads "CSV of 247 customer records", a credential "contains an AWS access key". The judge decides on what a call does, and a description states that. Names are the fictional roster.
- **What it measures.** Per scenario: whether its own attack is refused, how many of its attacks are, and how many routine calls are refused that should go through. Each scenario has one headline attack, at least one variant, and at least four routine calls written to sit close to the attack.
- **What it does not measure.** Real traffic, and payloads as an attacker would write them. Data split across many small calls, which is known gap 30. The arguments step on planted instructions, which is the same `defend()` the other corpora measure.
- **Rules.** A test holds each policy to the page and each scenario to its shape.
- **Read by.** `benchmarks/gatekeeper.py`, `tests/test_gatekeeper_corpus.py`.

### Tool search

A served tool catalog and the queries an agent asks of it, for [tool discovery](tool-discovery.md) (#473). Not content to judge: `benchmarks/tool_search.py` measures whether `find_tools` ranks the tool that does the job first, or in its first eight.

- **Where it came from.** Hand-written in the shape of an operations-and-office profile: twenty backends, short names as `gateway/names.py` issues them, descriptions in the first-sentence style backends write. No description is copied from a real server.
- **How it is written.** Queries are worded by intent and mostly not in the tool's own words. Those marked held out were never used to tune the ranker.
- **Read by.** `benchmarks/tool_search.py`, `tests/test_tool_search.py`.

## Held-out Rules

A held-out set measures a defense only while nobody has tuned against it. Vault's 2026-05-20 contamination postmortem is the cautionary tale: L1+L2 went from 45.9% to 90.3% after engineers read the held-out misses and patched against them. The number rose; the defense did not.

1. **Nobody reads held-out misses while tuning.** Tune on the tuning split, report the held-out rate, and stop. A harness prints held-out counts, never held-out text or ids of misses.
2. **A held-out set is burned once it has been read.** Reading a miss, for any reason, moves the set to burned: its numbers stay in the record with that note, and it no longer counts as held out. Its cases may join a tuning split.
3. **Every case carries a `source`.** `Case.source` is mandatory: the file that holds hand-written cases, or the URL and pinned revision of a fetched set. `tests/test_corpus_source.py` fails a loader that returns a case without one.
4. **Keep a queue of unopened held-out sets.** Write a new held-out set before the current one is burned, so there is one to move to.

### Unopened held-out queue

| Set | Status |
|---|---|
| Tool search, 32 queries marked held out | Unopened |

No held-out attack set is queued yet. The next one is written, with `source` on every case, before any existing held-out split is read.

## What Is Not a Corpus

- **The wild feed** (`benchmarks/wild_feed.py`, #357) collects what agents are sent on a public agent network. Its output is a run artifact and never a fixture.
- **The obfuscation transforms** (`src/trentina/quarantine/obfuscation.py`) are applied to the internal attacks by the L2 obfuscation gate. They are part of the perimeter, so they live in `src/`. garak's wider list is measured and not gated, and is [above](#garak-encodings).
- **File builders** (`tests/office_files.py`, `tests/pdf_files.py`, `tests/image_files.py`) make documents in memory for the unpack tests. They hold no payloads of their own.

## Adding a Corpus

1. **No real people.** Names, mail addresses, phone numbers and hosts are rewritten to the fictional roster before commit (Alice and Bob, `example.com`, `*.example`, 555-01xx). This applies to third-party data as much as to ours.
2. **Captured content is never a fixture.** An attack found in production traffic or the wild feed enters a corpus only rewritten by hand.
3. **A third-party set is reported apart.** Give it a category prefix in `corpora/registry.py` and never blend its rate with another's.
4. **Pin what you fetch.** Revision and SHA-256 beside the loader, through `corpora/fetch.py`.
5. **Say what it does not measure.** Add its section here; the registry test fails until you do.
6. **Do not grow the internal corpus casually.** Its cases feed the image-build gates and the recorded pack measurements. New attacks from a named source get their own corpus.

## Example

```bash
# The internal corpus through every configured L3 provider
uv run python benchmarks/provider_benchmark.py

# Internal and the jailbreak set, each reported apart
uv run python benchmarks/provider_benchmark.py --corpus both

# garak's documents: the sample, or all 972
uv run python benchmarks/provider_benchmark.py --corpus garak
uv run python benchmarks/provider_benchmark.py --corpus garak --garak-split full

# Every corpus, each reported apart
uv run python benchmarks/provider_benchmark.py --corpus all

# What would run, with no API call
uv run python benchmarks/provider_benchmark.py --corpus all --dry-run
```

## Related

- [Benchmark](benchmark.md): the numbers measured on these corpora
- [Defense Pipeline](defense-pipeline.md): the layers, the gates and the known gaps
- [Prompt Packs](l3-prompt-tuning.md): the tuning and held-out split
