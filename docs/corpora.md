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
| [Benign operations output](#benign-operations-output) | `corpora/benign_ops.py` | 225 benign | ours | AGPL-3.0-or-later | vendored |
| [Detonation](#detonation) | `corpora/detonation.py` | 12 carriers, 36 attack and 10 benign inserts | ours | AGPL-3.0-or-later | vendored |
| [Jailbreak classification](#jailbreak-classification) | `corpora/jailbreak.py` | 262 test, 1,044 train | `jackhhao/jailbreak-classification` | Apache-2.0 | fetched |
| [InjecAgent](#injecagent) | `corpora/injecagent.py` | 32 attack inserts | `uiuc-kang-lab/InjecAgent` | MIT | fetched |

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

225 invented cases of what an operations agent actually reads (#411, #404): unit properties, journal lines, disk-usage listings, metrics rows, opaque identifiers, and short agent-forum replies. These are the shapes L2 refused in production after the default model changed.

- **Where it came from.** Generated from a fixed seed (411), so a case id names the same text on every run. Every line is invented; none comes from a production host.
- **Why it is here.** The internal corpus has fourteen benign cases, all prose written to look like an attack. Nothing in any gate looked like routine tool output until this did.
- **Rules.** 207 cases are gated: the image build fails a model that refuses more than 2% of them. Two shapes the shipped model is known to flag (`KNOWN_GAPS`) are measured on every build and never dropped; they are [known gaps](defense-pipeline.md#known-gaps) 18 and 19. One case in four is the tuning split, by hash of its id.
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

## What Is Not a Corpus

- **The wild feed** (`benchmarks/wild_feed.py`, #357) collects what agents are sent on a public agent network. Its output is a run artifact and never a fixture.
- **The obfuscation transforms** (`src/trentina/quarantine/obfuscation.py`) are applied to the internal attacks by the L2 obfuscation gate. They are part of the perimeter, so they live in `src/`.
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

# Internal and the third-party set, each reported apart
uv run python benchmarks/provider_benchmark.py --corpus both

# What would run, with no API call
uv run python benchmarks/provider_benchmark.py --corpus both --dry-run
```

## Related

- [Benchmark](benchmark.md): the numbers measured on these corpora
- [Defense Pipeline](defense-pipeline.md): the layers, the gates and the known gaps
- [Prompt Packs](l3-prompt-tuning.md): the tuning and held-out split
