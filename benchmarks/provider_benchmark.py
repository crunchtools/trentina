#!/usr/bin/env python3
"""Cross-provider injection-detection benchmark (issue #43).

Runs the Layer 3 adversarial corpus (``corpora/internal.py``) through
``quarantine_detect()`` once per configured LLM provider and produces a
comparative report: detection rate by attack category, false-positive rate on
benign content, risk-level calibration, latency, and estimated token cost.

The thesis this measures: does it matter which LLM you put behind the Q-Agent?
The corpus is deliberately semantic — every attack already bypasses Layer 1 and
Layer 2 — so what remains is purely the model's reasoning about intent.

Usage (see docs/benchmark.md for the full option list)

    uv run python benchmarks/provider_benchmark.py
        Benchmark every provider that has credentials configured.

    uv run python benchmarks/provider_benchmark.py --providers gemini,anthropic
        Benchmark a specific subset.

    uv run python benchmarks/provider_benchmark.py --dry-run
        List what would run without spending any tokens.

    uv run python benchmarks/provider_benchmark.py --l2-only
        Score the corpus through L1 and L2 only and sweep ``l2_threshold``
        (issue #86). No provider, no tokens; needs the Prompt Guard 2 model.

    uv run python benchmarks/provider_benchmark.py --corpus external
        The third-party jailbreak set (issue #85, ``jailbreak.py``);
        ``both`` runs the two, reported separately and never blended.

Every run also scores each case through L2 once (the score does not depend
on the provider) and appends the threshold sweep to the report.

Credentials are read from the same environment variables the server uses:
GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY. Ollama is auto-detected by
probing OLLAMA_BASE_URL (default http://localhost:11434).

Cost figures use the editable PRICING table below and are estimates only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks import l2_sweep
from corpora import disclosed, garak_latent, jailbreak
from corpora.internal import CORPUS, RISK_ORDER, Case
from trentina.config import DEFAULT_CLASSIFIER_THRESHOLD, get_config
from trentina.defense import _stage_one
from trentina.quarantine.agent import quarantine_detect
from trentina.quarantine.classifier import is_classifier_available, model_info
from trentina.quarantine.prompts import DETECTION_SYSTEM_PROMPT
from trentina.unpack.scan import unpack

TOKENS_PER_MILLION = 1_000_000
HTTP_OK = 200

PRICING: dict[str, tuple[float, float]] = {
    "gemini": (0.10, 0.40),
    "openai": (0.15, 0.60),
    "anthropic": (1.00, 5.00),
    "ollama": (0.0, 0.0),
    # OpenRouter's price is the model's. This is gemini-2.5-flash-lite, the
    # default judge there; edit it when QUARANTINE_MODEL names another.
    "openrouter": (0.10, 0.40),
}

PROVIDER_ENV_KEY: dict[str, str | None] = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "ollama": None,
    "openrouter": "OPENROUTER_API_KEY",
}

_DETECTION_FAILED_PREFIX = "Q-Agent detection failed"


def resolved_model(provider: str) -> str:
    """The model name each provider driver actually uses, for reporting.

    Mirrors the resolution logic in ``quarantine/providers/__init__.py`` so the
    report names the real model, not the placeholder default.
    """
    config = get_config()
    default_gemini = "gemini-2.5-flash-lite"
    if provider == "gemini":
        return config.model
    if provider == "openai":
        return config.model if config.model != default_gemini else "gpt-4o-mini"
    if provider == "anthropic":
        return config.model if config.model != default_gemini else "claude-haiku-4-5-20251001"
    if provider == "ollama":
        return config.ollama_model
    if provider == "openrouter":
        return config.model if config.model != default_gemini else f"google/{default_gemini}"
    return "unknown"


@dataclass
class CaseResult:
    """Outcome of running one corpus case against one provider."""

    id: str
    category: str
    expect_injection: bool
    min_risk: str
    detected: bool
    risk_level: str
    latency_ms: float
    input_tokens: int
    output_tokens: int
    cost_usd: float
    error: bool
    summary: str = ""
    l2_malicious_score: float | None = None

    @property
    def correct(self) -> bool:
        """Did the detector reach the right injection/benign verdict?"""
        return self.detected == self.expect_injection

    @property
    def risk_ok(self) -> bool:
        """For a correctly-detected attack, did it meet the minimum severity?

        False when the case carries no ``min_risk`` (the external corpus has
        no severity label); ``risk_calibration`` leaves those out entirely.
        """
        if not self.expect_injection or not self.detected or not self.min_risk:
            return False
        return RISK_ORDER.get(self.risk_level, 0) >= RISK_ORDER[self.min_risk]


@dataclass
class ProviderReport:
    """Aggregated metrics for one provider across the whole corpus."""

    provider: str
    model: str
    results: list[CaseResult] = field(default_factory=list)

    def _scored_attacks(self) -> list[CaseResult]:
        """Attack cases that produced a verdict (provider errors excluded)."""
        return [r for r in self.results if r.expect_injection and not r.error]

    def _scored_benign(self) -> list[CaseResult]:
        return [r for r in self.results if not r.expect_injection and not r.error]

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.error)

    @property
    def detection_rate(self) -> float:
        attacks = self._scored_attacks()
        if not attacks:
            return 0.0
        return sum(1 for r in attacks if r.detected) / len(attacks)

    @property
    def fp_rate(self) -> float:
        benign = self._scored_benign()
        if not benign:
            return 0.0
        return sum(1 for r in benign if r.detected) / len(benign)

    @property
    def risk_calibration(self) -> float | None:
        """Share of caught attacks at or above their ``min_risk``.

        None when no caught attack carries one: n/a, not a made-up 0%.
        """
        detected = [r for r in self._scored_attacks() if r.detected and r.min_risk]
        if not detected:
            return None
        return sum(1 for r in detected if r.risk_ok) / len(detected)

    def subset(self, corpus: str) -> ProviderReport:
        """The same provider's results on one corpus only."""
        return ProviderReport(
            self.provider, self.model, [r for r in self.results if corpus_of(r) == corpus]
        )

    def aggregates(self) -> dict[str, Any]:
        """Every metric above, keyed by name, for the JSON report."""
        return {
            "detection_rate": self.detection_rate,
            "fp_rate": self.fp_rate,
            "risk_calibration": self.risk_calibration,
            "median_latency_ms": self.median_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "cost_per_1k_calls_usd": self.cost_per_1k_calls_usd,
            "total_cost_usd": self.total_cost_usd,
            "errors": self.errors,
            "detection_by_category": self.detection_by_category(),
            "fp_by_category": self.fp_by_category(),
        }

    def detection_by_category(self) -> dict[str, tuple[int, int]]:
        """category -> (detected, total_scored) over attack cases."""
        out: dict[str, list[int]] = {}
        for r in self._scored_attacks():
            slot = out.setdefault(r.category, [0, 0])
            slot[1] += 1
            if r.detected:
                slot[0] += 1
        return {k: (v[0], v[1]) for k, v in out.items()}

    def fp_by_category(self) -> dict[str, tuple[int, int]]:
        """category -> (false_positives, total_scored) over benign cases."""
        out: dict[str, list[int]] = {}
        for r in self._scored_benign():
            slot = out.setdefault(r.category, [0, 0])
            slot[1] += 1
            if r.detected:
                slot[0] += 1
        return {k: (v[0], v[1]) for k, v in out.items()}

    def _latencies(self) -> list[float]:
        return [r.latency_ms for r in self.results if not r.error]

    @property
    def median_latency_ms(self) -> float:
        lat = self._latencies()
        return statistics.median(lat) if lat else 0.0

    @property
    def p95_latency_ms(self) -> float:
        lat = sorted(self._latencies())
        if not lat:
            return 0.0
        idx = min(len(lat) - 1, round(0.95 * (len(lat) - 1)))
        return lat[idx]

    @property
    def total_cost_usd(self) -> float:
        return sum(r.cost_usd for r in self.results)

    @property
    def cost_per_1k_calls_usd(self) -> float:
        scored = [r for r in self.results if not r.error]
        if not scored:
            return 0.0
        return (sum(r.cost_usd for r in scored) / len(scored)) * 1000


def l2_threshold_in_force() -> float:
    """The cut the loaded L2 model flags at (#350), the sweep's bold row.

    A profile's ``l2_threshold`` is unset by default, so the model's own
    threshold, from its manifest or ``CLASSIFIER_THRESHOLD``, is what decides.
    """
    model = model_info()
    return model.threshold if model is not None else DEFAULT_CLASSIFIER_THRESHOLD


async def score_l2(cases: list[Case]) -> dict[str, float | None]:
    """Each case's L2 malicious score, exactly as ``defend()`` computes it.

    ``unpack`` then ``_stage_one`` is the production recipe: L1 and L2 in
    parallel, L2 reading the unpacked delivery once (#359, #367). Going through it rather than the
    classifier keeps the sweep on the number the gateway thresholds. None
    for every case when the model is not loaded, and for a case whose scan
    raised, as ``_run_case`` records a failed call rather than aborting the
    run.
    """
    if not await asyncio.to_thread(is_classifier_available):
        print("warning: no L2 model loaded; L2 scores omitted", file=sys.stderr)
        return {c.id: None for c in cases}

    async def _one(case: Case) -> tuple[str, float | None]:
        try:
            read = unpack(case.payload).text
            _, result, _ = await _stage_one(
                read,
                "benchmark",
                None,
                unpacked=read is not case.payload,
                scan=True,
                stop_on_partial=False,
            )
        except Exception as exc:
            print(f"warning: L2 failed on {case.id}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return case.id, None
        return case.id, None if result is None else result.score

    return dict(await asyncio.gather(*(_one(c) for c in cases)))


def _scored_pairs(
    cases: list[Case], scores: dict[str, float | None]
) -> tuple[list[tuple[float, bool]], int]:
    """``(score, is_attack)`` pairs for the sweep, and how many had no score."""
    pairs = [(s, c.expect_injection) for c in cases if (s := scores.get(c.id)) is not None]
    return pairs, len(cases) - len(pairs)


def l2_payload(cases: list[Case], scores: dict[str, float | None]) -> dict[str, Any]:
    """The JSON block for ``cases``: their raw scores plus the sweep, so a
    later cut needs no rerun."""
    pairs, _ = _scored_pairs(cases, scores)
    top = l2_sweep.best(pairs)
    return {
        "current_threshold": l2_threshold_in_force(),
        "model": None if (m := model_info()) is None else f"{m.id}@{m.revision}",
        "scores": {c.id: scores.get(c.id) for c in cases},
        "best_threshold": None if top is None else top.threshold,
        "sweep": [asdict(p) for p in l2_sweep.sweep(pairs)],
    }


def render_l2_markdown(
    cases: list[Case], scores: dict[str, float | None], corpus: str = "internal"
) -> str:
    """The sweep section for one corpus, named in its heading.

    Unscored cases are counted, not swept.
    """
    pairs, unscored = _scored_pairs(cases, scores)
    return l2_sweep.render_markdown(pairs, l2_threshold_in_force(), unscored, corpus=corpus)


CORPORA = ("internal", "external", "garak", "disclosed")

_PREFIXES = {
    jailbreak.CATEGORY_PREFIX: "external",
    garak_latent.CATEGORY_PREFIX: "garak",
    disclosed.CATEGORY_PREFIX: "disclosed",
}


def corpus_of(case: Case | CaseResult) -> str:
    """The corpus a category's prefix marks; ``internal`` for one with none."""
    for prefix, name in _PREFIXES.items():
        if case.category.startswith(prefix):
            return name
    return "internal"


CHARS_PER_TOKEN = 4
OUTPUT_TOKENS_ESTIMATE = 150
"""A detection verdict is a short JSON object; this rounds it up."""


def projected_cost(provider: str, cases: list[Case]) -> float:
    """Rough USD for one pass: prompt plus payload at 4 chars/token, in and out.

    For ``--dry-run`` before a spend, not a bill. The real figure comes back
    as ``total_cost_usd``, from the provider's own token counts.
    """
    in_tok = sum(len(DETECTION_SYSTEM_PROMPT) + len(c.payload) for c in cases) // CHARS_PER_TOKEN
    return _cost(provider, in_tok, OUTPUT_TOKENS_ESTIMATE * len(cases))


def _cost(provider: str, input_tokens: int, output_tokens: int) -> float:
    in_price, out_price = PRICING.get(provider, (0.0, 0.0))
    return (input_tokens / TOKENS_PER_MILLION) * in_price + (
        output_tokens / TOKENS_PER_MILLION
    ) * out_price


RETRY_BASE_DELAY = 1.0
RETRY_MAX_DELAY = 15.0
RETRYABLE_MARKERS = (
    "503",
    "429",
    "500",
    "502",
    "504",
    "overload",
    "timed out",
    "timeout",
    "unavailable",
    "connect",
    # A provider that ends a completion with an error mid-answer (seen from
    # OpenRouter as finish_reason "error") leaves JSON that does not parse.
    # It is the same transient failure as a 503, one layer up.
    "malformedresponseerror",
)


async def _run_case(provider: str, case: Case, delay: float, retries: int) -> CaseResult:
    """Run a single case through one provider, timing and pricing the call.

    Transient failures (503/429/timeouts/connection errors) are retried up to
    ``retries`` times with exponential backoff — the same retryable/terminal
    split issue #42 defines for provider fallback. Terminal failures (bad
    schema, auth) are not retried. Any failure is captured as an errored
    ``CaseResult`` rather than raised, so one bad call never aborts the run.
    """
    loop = asyncio.get_event_loop()
    result: dict[str, Any] | None = None
    summary = ""
    latency_ms = 0.0
    for attempt in range(retries + 1):
        start = loop.time()
        try:
            result = await quarantine_detect(
                case.payload, provider_name=provider, include_usage=True
            )
            summary = str(result.get("summary", ""))
        except Exception as exc:
            result = None
            summary = f"{type(exc).__name__}: {exc}"
        latency_ms = (loop.time() - start) * 1000
        errored = result is None or summary.startswith(_DETECTION_FAILED_PREFIX)
        retryable = any(m in summary.lower() for m in RETRYABLE_MARKERS)
        if not errored or attempt >= retries or not retryable:
            break
        await asyncio.sleep(min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * 2**attempt))

    if delay:
        await asyncio.sleep(delay)

    error = result is None or summary.startswith(_DETECTION_FAILED_PREFIX)
    payload = result or {}
    usage = payload.get("usage", {}) or {}
    in_tok = int(usage.get("input_tokens", 0))
    out_tok = int(usage.get("output_tokens", 0))
    return CaseResult(
        id=case.id,
        category=case.category,
        expect_injection=case.expect_injection,
        min_risk=case.min_risk,
        detected=bool(payload.get("injection_detected", False)),
        risk_level=str(payload.get("risk_level", "low")),
        latency_ms=round(latency_ms, 1),
        input_tokens=in_tok,
        output_tokens=out_tok,
        cost_usd=_cost(provider, in_tok, out_tok),
        error=error,
        summary=summary[:300],
    )


async def run_provider(
    provider: str, cases: list[Case], concurrency: int, delay: float, retries: int
) -> ProviderReport:
    """Run the full corpus against one provider with bounded concurrency.

    Results are sorted back into corpus order before returning so the JSON and
    markdown output is stable and diffable across runs.
    """
    report = ProviderReport(provider=provider, model=resolved_model(provider))
    sem = asyncio.Semaphore(concurrency)

    async def _guarded(case: Case) -> CaseResult:
        async with sem:
            return await _run_case(provider, case, delay, retries)

    tasks = [asyncio.create_task(_guarded(c)) for c in cases]
    for done, coro in enumerate(asyncio.as_completed(tasks), 1):
        res = await coro
        mark = "ERR" if res.error else ("HIT" if res.detected else "   ")
        print(
            f"  [{provider}] {done}/{len(cases)} {mark} {res.id} ({res.latency_ms:.0f}ms)",
            file=sys.stderr,
        )
        report.results.append(res)

    order = {c.id: i for i, c in enumerate(cases)}
    report.results.sort(key=lambda r: order[r.id])
    return report


def available_providers(requested: list[str] | None) -> list[str]:
    """Providers with usable credentials, intersected with any --providers list.

    Ollama is probed over HTTP; hosted providers are gated on their API-key
    environment variable. Warnings are emitted only when the caller explicitly
    asked for a provider that turns out to be unavailable.
    """
    candidates = requested or list(PROVIDER_ENV_KEY)
    usable: list[str] = []
    for name in candidates:
        if name not in PROVIDER_ENV_KEY:
            print(f"warning: unknown provider {name!r}, skipping", file=sys.stderr)
            continue
        if name == "ollama":
            base = get_config().ollama_base_url.rstrip("/")
            try:
                reachable = httpx.get(f"{base}/api/tags", timeout=1.5).status_code == HTTP_OK
            except httpx.HTTPError:
                reachable = False
            if reachable:
                usable.append(name)
                continue
            if requested and "ollama" in requested:
                print(f"warning: ollama not reachable at {base}", file=sys.stderr)
            continue
        env = PROVIDER_ENV_KEY[name]
        if env and os.environ.get(env):
            usable.append(name)
            continue
        if requested:
            print(f"warning: {name} requested but {env} not set", file=sys.stderr)
    return usable


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "—"


def _category_table(
    title: str,
    reports: list[ProviderReport],
    categories: list[str],
    counts: dict[str, dict[str, tuple[int, int]]],
) -> str:
    """Render a category-by-provider table (used for both detection and FP)."""
    header = "| Category | " + " | ".join(r.provider for r in reports) + " |"
    sep = "|----------|" + "|".join(["------"] * len(reports)) + "|"
    lines = [f"## {title}", "", header, sep]
    for cat in categories:
        cells = [
            f"{_pct(*counts[r.provider].get(cat, (0, 0)))} "
            f"({counts[r.provider].get(cat, (0, 0))[0]}/"
            f"{counts[r.provider].get(cat, (0, 0))[1]})"
            for r in reports
        ]
        lines.append(f"| {cat} | " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


CORPUS_NOTES = {
    "internal": ("Hand-authored semantic attacks built to slip past L1 and L2: this measures L3."),
    "external": (
        f"`{jailbreak.DATASET}` ({jailbreak.LICENSE}), pinned at "
        f"`{jailbreak.REVISION[:12]}`. Direct jailbreak, NOT indirect "
        "injection in retrieved content: it measures L2 and over-triggering on "
        "benign roleplay, not L3's semantic gap. High detection here is a "
        "sanity floor. No severity labels, so Risk-cal is n/a."
    ),
    "garak": (
        f"`{garak_latent.REPOSITORY}` latent-injection probes ({garak_latent.LICENSE}), "
        f"derived from `{garak_latent.TAG}`: an instruction buried in a report, a "
        "resume or a WHOIS record, and the same documents untouched as benign "
        "controls. Indirect injection by a third party, with every real person "
        "rewritten. No severity labels, so Risk-cal is n/a."
    ),
    "disclosed": (
        "Payloads reproduced from published disclosures (#29), rewritten to "
        "fictional names. Five cases: read each one, not the rate."
    ),
}

NOTABLE_LIST_CAP = 25


def _ids(ids: list[str]) -> str:
    """Sorted, backticked, cut at ``NOTABLE_LIST_CAP`` with a count of the rest."""
    shown = ", ".join(f"`{i}`" for i in sorted(ids)[:NOTABLE_LIST_CAP])
    more = len(ids) - NOTABLE_LIST_CAP
    return f"{shown}, and {more} more" if more > 0 else shown


def _notable(reports: list[ProviderReport]) -> list[str]:
    """Cases every provider got wrong, the same way."""
    by_id: dict[str, list[CaseResult]] = {}
    for r in reports:
        for res in r.results:
            by_id.setdefault(res.id, []).append(res)
    universal_miss: list[str] = []
    universal_fp: list[str] = []
    for cid, results in by_id.items():
        scored = [x for x in results if not x.error]
        if not scored or any(x.correct for x in scored):
            continue
        (universal_miss if scored[0].expect_injection else universal_fp).append(cid)
    return [
        "## Notable results",
        "",
        f"- Attacks missed by **every** provider ({len(universal_miss)}): "
        + (_ids(universal_miss) if universal_miss else "none"),
        f"- Benign content flagged by **every** provider ({len(universal_fp)}): "
        + (_ids(universal_fp) if universal_fp else "none"),
        "",
    ]


def _summary(reports: list[ProviderReport]) -> list[str]:
    """The summary table: one row of headline metrics per provider."""
    out = [
        "## Summary",
        "",
        (
            "| Provider | Model | Detection | FP rate | Risk-cal | "
            "Median latency | $/1k calls | Errors |"
        ),
        (
            "|----------|-------|-----------|---------|----------|"
            "----------------|------------|--------|"
        ),
    ]
    for r in reports:
        cal = "n/a" if r.risk_calibration is None else f"{r.risk_calibration:.0%}"
        out.append(
            f"| {r.provider} | `{r.model}` | {r.detection_rate:.0%} | "
            f"{r.fp_rate:.0%} | {cal} | {r.median_latency_ms:.0f}ms | "
            f"${r.cost_per_1k_calls_usd:.2f} | {r.errors} |"
        )
    out.append("")
    return out


def render_markdown(
    reports: list[ProviderReport], meta: dict[str, Any], cases: list[Case], corpus: str
) -> str:
    """One corpus's provider report, as Markdown.

    ``reports`` and ``cases`` must already be that corpus's subset
    (``ProviderReport.subset``, ``by_corpus``): aggregates never mix
    corpora. ``cases`` supplies the category rows; ``meta`` is
    ``build_meta``'s, read for the timestamp and ``corpora[corpus]`` counts.
    ``corpus`` is ``internal`` or ``external`` and picks the heading and the
    note on what that corpus measures.
    """
    attack_cats = sorted({c.category for c in cases if c.expect_injection})
    benign_cats = sorted({c.category for c in cases if not c.expect_injection})
    counts = meta["corpora"][corpus]
    out = [
        f"# Q-Agent provider benchmark: {corpus} corpus",
        "",
        CORPUS_NOTES[corpus],
        "",
        (
            "Detection = share of attacks flagged. FP = share of benign content "
            "wrongly flagged. Risk-cal = share of caught attacks that met the "
            "expected minimum severity. Cost is an estimate from the harness "
            "PRICING table."
        ),
        "",
        f"- Generated: {meta['timestamp']}",
        (
            f"- Corpus: {counts['n_attacks']} attacks + {counts['n_benign']} benign "
            f"= {counts['n_total']} cases across {counts['n_categories']} categories"
        ),
        f"- Providers: {', '.join(r.provider for r in reports)}",
        "",
        *_summary(reports),
        _category_table(
            "Detection by attack category",
            reports,
            attack_cats,
            {r.provider: r.detection_by_category() for r in reports},
        ),
        _category_table(
            "False positives by benign category",
            reports,
            benign_cats,
            {r.provider: r.fp_by_category() for r in reports},
        ),
        *_notable(reports),
    ]
    return "\n".join(out)


def _corpus_counts(cases: list[Case]) -> dict[str, int]:
    """Total, attack, benign and category counts of ``cases``."""
    attacks = sum(1 for c in cases if c.expect_injection)
    return {
        "n_total": len(cases),
        "n_attacks": attacks,
        "n_benign": len(cases) - attacks,
        "n_categories": len({c.category for c in cases}),
    }


def by_corpus(cases: list[Case]) -> dict[str, list[Case]]:
    """The selected cases split by corpus, in CORPORA order, empty ones left out."""
    split = {name: [c for c in cases if corpus_of(c) == name] for name in CORPORA}
    return {name: sub for name, sub in split.items() if sub}


def build_meta(
    providers: list[str],
    cases: list[Case],
    external_split: str | None = None,
    garak_split: str | None = None,
) -> dict[str, Any]:
    """Run metadata, counted from the cases that actually ran.

    Returns ``timestamp``, ``providers``, ``pricing``, and ``corpora``: per
    corpus present in ``cases``, ``n_total``/``n_attacks``/``n_benign``/
    ``n_categories``, and for ``external`` and ``garak`` also the dataset,
    revision, license, and ``split`` (the matching ``*_split`` argument).
    """
    corpora: dict[str, dict[str, Any]] = {
        name: _corpus_counts(sub) for name, sub in by_corpus(cases).items()
    }
    if "external" in corpora:
        corpora["external"].update(
            dataset=jailbreak.DATASET,
            revision=jailbreak.REVISION,
            license=jailbreak.LICENSE,
            split=external_split,
        )
    if "garak" in corpora:
        corpora["garak"].update(
            dataset=garak_latent.REPOSITORY,
            revision=garak_latent.COMMIT,
            license=garak_latent.LICENSE,
            split=garak_split,
        )
    return {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "corpora": corpora,
        "providers": providers,
        "pricing": PRICING,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--providers",
        help="Comma-separated subset (gemini,openai,anthropic,ollama). "
        "Default: all with credentials.",
    )
    p.add_argument(
        "--corpus",
        choices=("internal", "external", "garak", "disclosed", "both", "all"),
        default="internal",
        help="internal: the hand-authored L3 corpus. external: the third-party "
        "jailbreak set (downloaded on first use). garak: garak's latent-injection "
        "documents. disclosed: payloads from published disclosures. both: internal "
        "and external. all: every one. Each corpus is reported separately.",
    )
    p.add_argument(
        "--garak-split",
        choices=garak_latent.SPLITS,
        default="sample",
        help="Split of the garak set: sample (one attack in five) or full (972).",
    )
    p.add_argument(
        "--external-split",
        choices=jailbreak.SPLITS,
        default="test",
        help="Split of the external set: test (262), train (1,044) or all (1,306).",
    )
    p.add_argument(
        "--categories",
        help="Comma-separated category filter (e.g. detector_meta,exfil_action).",
    )
    p.add_argument(
        "--limit", type=int, help="Run only the first N cases of each corpus (smoke test)."
    )
    p.add_argument("--concurrency", type=int, default=4, help="Max concurrent calls per provider.")
    p.add_argument("--delay", type=float, default=0.0, help="Seconds to sleep after each call.")
    p.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Retry transient failures (503/429/timeout) up to N times with "
        "exponential backoff. Terminal errors (auth/schema) are not retried.",
    )
    p.add_argument(
        "--out",
        default=str(_REPO_ROOT / "benchmarks" / "results"),
        help="Output directory for JSON + markdown.",
    )
    p.add_argument(
        "--l2-only",
        action="store_true",
        help="Score the corpus through L1+L2 and sweep l2_threshold. No provider calls.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="List providers, cases and projected cost, without calling any API.",
    )
    return p.parse_args(argv)


def select_cases(args: argparse.Namespace) -> list[Case]:
    """Each chosen corpus, category-filtered, cut to ``--limit`` on its own.

    In ``CORPORA`` order.
    """
    corpora: list[list[Case]] = []
    if args.corpus in ("internal", "both", "all"):
        corpora.append(list(CORPUS))
    if args.corpus in ("external", "both", "all"):
        corpora.append(jailbreak.load(args.external_split))
    if args.corpus in ("garak", "all"):
        corpora.append(garak_latent.load(args.garak_split))
    if args.corpus in ("disclosed", "all"):
        corpora.append(list(disclosed.CORPUS))
    wanted = {c.strip() for c in args.categories.split(",")} if args.categories else None
    selected: list[Case] = []
    for corpus in corpora:
        kept = [c for c in corpus if wanted is None or c.category in wanted]
        selected += kept[: args.limit] if args.limit else kept
    return selected


def _dry_run(cases: list[Case], providers: list[str], l2_only: bool) -> None:
    """Print the target, per-corpus counts, projected cost unless ``l2_only``, and each case."""
    target = "L2 only" if l2_only else (providers or "(none available)")
    print(f"Would run {len(cases)} cases against: {target}")
    for name, sub in by_corpus(cases).items():
        counts = _corpus_counts(sub)
        print(f"  {name}: {counts['n_attacks']} attacks + {counts['n_benign']} benign")
    for provider in [] if l2_only else providers:
        print(f"  projected {provider}: ~${projected_cost(provider, cases):.2f} (estimate)")
    for c in cases:
        kind = "ATTACK" if c.expect_injection else "benign"
        print(f"  {kind:6} {c.category:26} {c.id}")


async def main_async(args: argparse.Namespace) -> int:
    requested = [p.strip() for p in args.providers.split(",")] if args.providers else None
    providers = [] if args.l2_only else available_providers(requested)
    # The external corpus may download on first use; keep that off the loop.
    cases = await asyncio.to_thread(select_cases, args)

    if not cases:
        print("No cases selected.", file=sys.stderr)
        return 2

    if args.dry_run:
        _dry_run(cases, providers, args.l2_only)
        return 0

    if not providers and not args.l2_only:
        print(
            "No providers available. Set GEMINI_API_KEY / OPENAI_API_KEY / "
            "ANTHROPIC_API_KEY, or start Ollama. --l2-only needs none.",
            file=sys.stderr,
        )
        return 2

    print(f"Scoring {len(cases)} cases through L2…", file=sys.stderr)
    scores = await score_l2(cases)

    reports: list[ProviderReport] = []
    for provider in providers:
        print(f"Running {len(cases)} cases against {provider}…", file=sys.stderr)
        report = await run_provider(provider, cases, args.concurrency, args.delay, args.retries)
        for res in report.results:
            res.l2_malicious_score = scores.get(res.id)
        reports.append(report)

    meta = build_meta(providers, cases, args.external_split, args.garak_split)
    write_outputs(Path(args.out), meta, reports, cases, scores)
    return 0


def write_outputs(
    out_dir: Path,
    meta: dict[str, Any],
    reports: list[ProviderReport],
    cases: list[Case],
    scores: dict[str, float | None],
) -> None:
    """Write ``benchmark-<ts>.json`` and ``.md`` to ``out_dir`` and echo the report.

    Everything is reported per corpus: a detection rate blended across a
    semantic L3 corpus and a direct-jailbreak set would mean nothing.
    ``reports`` is empty under ``--l2-only``; each corpus's markdown is then
    its sweep alone. ``scores`` maps case id to its L2 score, None where
    unscored.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = meta["timestamp"].replace(":", "").replace("-", "")
    json_path = out_dir / f"benchmark-{stamp}.json"
    md_path = out_dir / f"benchmark-{stamp}.md"
    corpora = by_corpus(cases)

    payload = {
        "meta": meta,
        "l2": {name: l2_payload(sub, scores) for name, sub in corpora.items()},
        "providers": [
            {
                "provider": r.provider,
                "model": r.model,
                "corpora": {name: r.subset(name).aggregates() for name in corpora},
                "cases": [asdict(c) for c in r.results],
            }
            for r in reports
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2))
    sections: list[str] = []
    for name, sub in corpora.items():
        if reports:
            sections.append(render_markdown([r.subset(name) for r in reports], meta, sub, name))
        sections.append(render_l2_markdown(sub, scores, name))
    md = "\n".join(sections)
    md_path.write_text(md)

    print("\n" + md)
    print(f"\nWrote {json_path}", file=sys.stderr)
    print(f"Wrote {md_path}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
