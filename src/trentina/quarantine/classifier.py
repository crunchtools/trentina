"""Layer 2 — a local prompt-injection classifier via ONNX Runtime.

Embedded in-process inference. No sidecar, no HTTP API, no network calls.
Synchronous — ONNX inference is CPU-bound, not I/O-bound.

Which model is pluggable (#350): any sequence-classification ONNX export in a
directory, described by a ``trentina-model.json`` manifest (or, failing one,
by the labels in its ``config.json``). The image ships Horizon-Labs'
prompt-injection-guard-small, the default.

The classifier sees the L2 input (post-Layer 1) on the input path,
and extracted text (post-Layer 3) on the output verification path.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import DEFAULT_CLASSIFIER_THRESHOLD, get_config, int_env
from ..errors import UnscannableContentError
from .benign_gate import benign_state
from .obfuscation import gate_state

logger = logging.getLogger(__name__)

TELEMETRY_ENV = "ORT_DISABLE_TELEMETRY"
"""Turns off onnxruntime's telemetry, set below before onnxruntime loads.

onnxruntime's C++ init reads this, so it has to land before the lazy
``import onnxruntime`` in :func:`is_classifier_available` — hence module
scope. The Containerfile sets it too; this covers running outside the
container.

With telemetry live, importing onnxruntime reads /etc/machine-id, reads
/etc/os-release four times, reads /proc/cpuinfo, writes a debug log to
/tmp/mat-debug-1.log and creates a session file at /tmp/.ses. None of that
belongs in a process whose job is handling untrusted content. Disabling
leaves only the /sys/class/drm and /sys/class/accel probes onnxruntime
genuinely needs to choose an execution provider.

It is also a second line of defence against the import-time segfault the
Containerfile addresses: the machine-id read that trips a shell-less image
sits on this same telemetry path, so either mitigation alone prevents it.
"""

os.environ.setdefault(TELEMETRY_ENV, "1")

_session: Any | None = None
_tokenizer: Any = None
_model: ModelInfo | None = None
_loaded = False
_load_attempted = False

MANIFEST_FILE = "trentina-model.json"
"""Written beside ``model.onnx`` when a model is exported for Trentina."""

BENIGN_LABELS = frozenset({"BENIGN", "SAFE"})
"""Label names that mean clean, read without a manifest."""

MALICIOUS_LABELS = frozenset({"MALICIOUS", "INJECTION", "JAILBREAK"})
"""Label names that mean attack, read without a manifest. A label in neither
set refuses the model: ``POSITIVE``/``NEGATIVE`` say nothing about polarity."""


class ModelManifestError(ValueError):
    """A model directory that does not say which of its outputs is malicious."""


WINDOW_TOKENS = 512
"""The window a model is scanned in when its manifest states none (#438).

The window is the model's, not the gateway's: ``trentina-model.json`` carries
``window_tokens`` and :func:`resolve_model` reads it into
:class:`ModelInfo`. This is the default, and it is never taken past the
model's own ``max_position_embeddings``. Prompt Guard 2 could read no more
than 512. Horizon's prompt-injection-guard-small can read 8192 and is still
scanned at 512: no wider window measured reliably faster, 4096 and 8192 ran
two to five times slower, and 256 flagged benign prose (``docs/benchmark.md``,
"L2 window width")."""

WINDOW_SPECIAL_TOKENS = 2
"""Special tokens the model wraps each window in (CLS ... SEP).

``classify()`` takes the real count from the tokenizer rather than this
constant, so a model that wraps differently stays correct. This is the value
the default window geometry below is stated against, and a test pins the two
together.
"""

WINDOW_CONTENT_TOKENS = WINDOW_TOKENS - WINDOW_SPECIAL_TOKENS
"""Content tokens one default window actually carries.

The window is WINDOW_TOKENS wide, but the special tokens occupy two of those
slots, so only this many tokens of the input fit. The overlap below is the
guard band over CONTENT, which is the thing an injection is made of -- stating
it against WINDOW_TOKENS overstates it by WINDOW_SPECIAL_TOKENS.
"""

GUARD_TOKENS = 64
"""Content tokens two neighbouring windows share, unless the manifest's
``guard_tokens`` says otherwise.

Overlap exists so an injection straddling a window boundary still lands
intact inside at least one window. It only has to exceed the longest
injection we care about catching whole: the canonical forms
("ignore all previous instructions and ...") run 10-30 tokens, so 64 is a
comfortable margin.
"""

WINDOW_STRIDE = WINDOW_CONTENT_TOKENS - GUARD_TOKENS
"""How far the default window advances: 446, leaving the guard band.

This was stride=256 -- a 256-token guard band, which meant a 50% overlap
and ran the model over every token TWICE. On a 32,768-token scan that is
128 passes instead of 74, and at the measured 872 ms per pass on host01 it
cost roughly 47 seconds of pure duplicate work per scan. The Matrix proxy
scans every /sync response, so agent1 paid it on every message and
agent3 could not finish an initial sync inside its 30 s budget at all
(RT #1460).
"""

MIN_WINDOW_TOKENS = 16
"""The narrowest window a manifest may state. Below it a window holds less
than any instruction, and the scan is passes with nothing to read."""


@dataclass(frozen=True)
class ModelInfo:
    """What L2 is running: identity for the verdict stamp, and how to score it."""

    id: str
    revision: str
    threshold: float
    malicious: tuple[int, ...]  # output indices whose probabilities sum to the score
    source: str = ""
    license: str = ""
    gate: str = "unrecorded"  # obfuscation gate: passed, failed or unrecorded (#362)
    benign_gate: str = "unrecorded"  # benign gate, the same three states (#411)
    window: int = WINDOW_TOKENS  # tokens one pass reads, special tokens included (#438)
    guard: int = GUARD_TOKENS  # content tokens neighbouring windows share


def resolve_model(model_path: str, threshold_override: float | None = None) -> ModelInfo:
    """Read a model directory's manifest and labels into a :class:`ModelInfo`.

    The manifest names the malicious outputs, by ``malicious_indices`` or by
    ``malicious_labels``, and the threshold. Without one, every ``id2label``
    entry in :data:`MALICIOUS_LABELS` is malicious, provided every label is
    in that set or :data:`BENIGN_LABELS`, and the threshold is
    ``DEFAULT_CLASSIFIER_THRESHOLD``. Any other label (``LABEL_0``, a
    sentiment model's ``POSITIVE``, or none at all, as Prompt Guard 2 ships)
    is refused without a manifest:
    guessing a polarity wrong would report every attack as clean, so L2 is
    absent instead and ``TRENTINA_REQUIRE_L2`` decides. The indices are
    checked against the session's output width when it loads.

    Args:
        model_path: The model directory: ``config.json``, optionally
            ``trentina-model.json``, beside the ``model.onnx`` the caller loads.
        threshold_override: ``CLASSIFIER_THRESHOLD``. When set it replaces the
            manifest's threshold; None keeps the manifest's, or
            ``DEFAULT_CLASSIFIER_THRESHOLD`` with no manifest.

    Returns:
        The model's id (manifest, else the directory name), revision
        (manifest, else an ``unpinned-<size>-<mtime>`` stand-in), threshold
        in force, and the sorted output indices whose probabilities sum to
        the malicious score.

    Raises:
        ModelManifestError: polarity unknown or degenerate, a manifest label
            ``config.json`` lacks, a negative index, or a threshold outside
            (0, 1].
        OSError, ValueError: ``config.json`` or the manifest is missing or
            not JSON.
    """
    root = Path(model_path)
    config = json.loads((root / "config.json").read_text())
    id2label = {int(k): str(v).upper() for k, v in (config.get("id2label") or {}).items()}
    manifest_path = root / MANIFEST_FILE
    manifest: dict[str, Any] = (
        json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    )

    if "malicious_indices" in manifest:
        malicious = tuple(sorted({int(i) for i in manifest["malicious_indices"]}))
        if any(i < 0 for i in malicious):
            raise ModelManifestError("negative output index in the manifest")
    elif "malicious_labels" in manifest:
        wanted = {str(label).upper() for label in manifest["malicious_labels"]}
        malicious = tuple(sorted(i for i, label in id2label.items() if label in wanted))
        if len(malicious) != len(wanted):
            raise ModelManifestError("manifest names a malicious label config.json lacks")
    else:
        known = BENIGN_LABELS | MALICIOUS_LABELS
        if not id2label or any(label not in known for label in id2label.values()):
            raise ModelManifestError("unrecognized labels and no manifest: polarity unknown")
        malicious = tuple(sorted(i for i, label in id2label.items() if label in MALICIOUS_LABELS))
    if not malicious or (id2label and len(malicious) >= len(id2label)):
        raise ModelManifestError("no benign/malicious split in the model's outputs")

    threshold = (
        threshold_override
        if threshold_override is not None
        else float(manifest.get("threshold", DEFAULT_CLASSIFIER_THRESHOLD))
    )
    if not 0.0 < threshold <= 1.0:
        raise ModelManifestError("threshold outside (0, 1]")
    window, guard = _window_geometry(manifest, config)
    return ModelInfo(
        id=str(manifest.get("id") or root.name),
        revision=str(manifest.get("revision") or _unpinned_revision(root)),
        threshold=threshold,
        malicious=malicious,
        source=str(manifest.get("source", "")),
        license=str(manifest.get("license", "")),
        gate=gate_state(manifest),
        benign_gate=benign_state(manifest, threshold),
        window=window,
        guard=guard,
    )


def _window_geometry(manifest: dict[str, Any], config: dict[str, Any]) -> tuple[int, int]:
    """The window and guard band a model is scanned with (#438).

    The manifest's ``window_tokens`` and ``guard_tokens``, else the defaults,
    the window never past the model's own ``max_position_embeddings``. A
    manifest that states a window the model cannot read is refused: every
    pass would be cut short by the model while the scan reported it whole.
    Neighbouring windows must advance, and by at least as far as they
    overlap, or one payload costs passes without bound.

    Raises:
        ModelManifestError: a window or guard band that is not a whole
            number, a window under :data:`MIN_WINDOW_TOKENS` or over the
            model's limit, or a guard band that leaves no stride.
    """
    limit = config.get("max_position_embeddings")
    limit = limit if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0 else None
    stated = manifest.get("window_tokens")
    window = stated if stated is not None else min(WINDOW_TOKENS, limit or WINDOW_TOKENS)
    guard = manifest.get("guard_tokens", GUARD_TOKENS)
    for value in (window, guard):
        if not isinstance(value, int) or isinstance(value, bool):
            raise ModelManifestError("window_tokens and guard_tokens must be whole numbers")
    if window < MIN_WINDOW_TOKENS or (limit is not None and window > limit):
        raise ModelManifestError("window_tokens outside what the model can read")
    if guard < 0 or guard * 2 > window - WINDOW_SPECIAL_TOKENS:
        raise ModelManifestError("guard_tokens leaves the window no stride")
    return window, guard


def _unpinned_revision(root: Path) -> str:
    """A stand-in revision for a model with no pinned one in its manifest.

    The revision is part of the verdict stamp, so two different unpinned
    exports swapped into one path must not share it: verdicts one reached
    would be replayed for the other. The graph's size and mtime differ.
    """
    try:
        stat = (root / "model.onnx").stat()
    except OSError:
        return "unpinned"
    return f"unpinned-{stat.st_size}-{stat.st_mtime_ns}"


def _check_output_width(session: Any, model: ModelInfo) -> None:
    """Refuse a manifest whose malicious outputs the graph does not have.

    A static output width is required: an index past it would raise on the
    first scan, and one that covers every output would flag everything.
    """
    width = session.get_outputs()[0].shape[-1]
    if not isinstance(width, int) or max(model.malicious) >= width or len(model.malicious) >= width:
        raise ModelManifestError("malicious outputs do not fit the model's output width")


def model_info() -> ModelInfo | None:
    """The loaded model, or None before a load or after a failed one."""
    return _model if _loaded else None


@dataclass
class ClassifierResult:
    """Result from the L2 classifier."""

    label: str  # "BENIGN" or "MALICIOUS"
    score: float  # confidence score (0.0-1.0)
    latency_ms: float  # inference time
    truncated: bool = False  # content exceeded the token cap; scan is partial
    tokens: int = 0  # total tokens in the input, including any beyond the cap


def is_classifier_available() -> bool:
    """Check if the ONNX model is loaded and ready. Lazy-loads on first call.

    Thread count is pinned here: left at its default the CPU provider starts
    one intra-op thread per core and spin-waits on them, so a single long
    scan pegs every core and starves the gateway.
    """
    global _session, _tokenizer, _model, _loaded, _load_attempted

    if _loaded:
        return True
    if _load_attempted:
        return False

    _load_attempted = True

    config = get_config()
    model_path = config.classifier_model_path

    try:
        import onnxruntime as ort
        from transformers import AutoTokenizer
    except ImportError:
        logger.warning("onnxruntime or transformers not installed — classifier unavailable")
        return False

    try:
        model_file = f"{model_path}/model.onnx"
        # TRUST: deciding which model outputs mean "malicious"
        #   untrusted: nothing a caller chose; the operator's model directory and env
        #   judged-by: resolve_model (polarity, threshold) and _check_output_width
        #   on-failure: fail-closed: any error leaves _loaded False, L2 is absent, and
        #     TRENTINA_REQUIRE_L2 refuses block/redact rather than guess a polarity
        #   owner: classifier.is_classifier_available
        #   evidence: T4 except below never sets _loaded; T2 json builds plain types only
        _model = resolve_model(model_path, config.classifier_threshold)
        _tokenizer = AutoTokenizer.from_pretrained(model_path)

        sess_options = ort.SessionOptions()
        threads = config.classifier_threads
        if threads > 0:
            sess_options.intra_op_num_threads = threads
            sess_options.inter_op_num_threads = 1

        _session = ort.InferenceSession(
            model_file,
            sess_options=sess_options,
            providers=["CPUExecutionProvider"],
        )
        _check_output_width(_session, _model)
        _loaded = True
        logger.info(
            "Layer 2 classifier loaded from %s: %s@%s, threshold %.2f, "
            "window %d (guard %d), obfuscation gate %s, benign gate %s",
            model_path,
            _model.id,
            _model.revision or "unpinned",
            _model.threshold,
            _model.window,
            _model.guard,
            _model.gate,
            _model.benign_gate,
        )
    except Exception:
        logger.warning(  # logsafe: ours — loading the operator's model
            "Failed to load classifier model from %s", model_path, exc_info=True
        )
        return False

    return True


def _pad_segment(segment_ids: list[int], max_length: int) -> tuple[list[int], list[int]]:
    """Wrap token IDs in special tokens, at their natural length.

    NO PADDING. The exported graph declares both inputs as
    ``['batch_size', 'sequence_length']`` — the sequence axis is dynamic — and
    batch is always 1 here, so there is no second row to line up against.
    Padding to ``max_length`` was making every short input cost a full
    512-token pass: a 15-token chat message measured 791 ms padded and 52 ms
    at its natural length, for a byte-identical score (0.9994 both ways).

    That mattered little when every scan was a full window. It matters a lot
    now: with scan-view extraction the typical payload is far under one
    window, so the common case was paying roughly 15x for zeros.

    ``max_length`` is still honoured as a ceiling — a segment longer than the
    model's context window is truncated, because that is a real constraint
    rather than a formatting choice.

    Builds the model input straight from IDs the tokenizer already produced.
    The previous approach decoded each window back to text and re-tokenized
    it, which cost a second tokenizer pass per segment for a result that is
    identical on any real text — verified against the model's own tokenizer
    on prose, code, HTML, and non-Latin scripts.

    The two differ only on binary decoded as text, where the round trip
    silently dropped tokens (242 of 302 in testing) because U+FFFD runs do
    not survive decode and re-encode. Slicing keeps what the tokenizer
    actually produced, so the scan sees more of the input, not less.
    """
    ids = [_tokenizer.cls_token_id, *segment_ids, _tokenizer.sep_token_id]
    if len(ids) > max_length:
        ids = ids[:max_length]
    return ids, [1] * len(ids)


def _classify_segment(input_ids: list[int], attention_mask: list[int]) -> tuple[str, float]:
    """Classify a single segment. Returns (label, malicious_score)."""
    import numpy as np

    inputs = {
        "input_ids": np.array([input_ids], dtype=np.int64),
        "attention_mask": np.array([attention_mask], dtype=np.int64),
    }

    if _session is None or _model is None:
        # is_classifier_available() guards every caller of this function, so
        # this should be unreachable -- fail loudly rather than silently
        # under python -O if that invariant ever breaks.
        raise RuntimeError("_classify_segment called without a loaded classifier session")
    outputs = _session.run(None, inputs)
    logits = outputs[0][0]

    exp_logits = np.exp(logits - np.max(logits))
    probs = exp_logits / exp_logits.sum()

    malicious_score = float(sum(probs[i] for i in _model.malicious))
    label = "MALICIOUS" if malicious_score >= _model.threshold else "BENIGN"

    return label, malicious_score


def classify(
    text: str, *, fail_on_truncate: bool = False, source: str = "content"
) -> ClassifierResult | None:
    """Run Layer 2 classifier on text.

    Returns ClassifierResult, or None if the model is not available.
    Synchronous — ONNX Runtime inference is CPU-bound, not I/O-bound.
    Prefer :func:`classify_async` from async code so a long scan cannot
    block the event loop.

    For text longer than the model's window (``ModelInfo.window``, 512 unless
    its manifest says otherwise, #438), splits into overlapping segments that
    share the model's guard band (64 tokens by default) and returns the
    highest malicious score.  Scanning stops
    after ``Config.admission_tokens`` tokens and the result is marked
    ``truncated``; callers must treat a truncated scan of an untrusted
    source as unscannable rather than clean.  Without that bound an 855 KB
    PDF decoded as text produced ~462k tokens and ~1,800 inference passes,
    which pegged every core for the better part of an hour.

    ``fail_on_truncate`` raises :class:`UnscannableContentError` as soon as
    the token count is known, before any inference runs.  A caller that
    will reject a truncated scan anyway gains nothing from the ~74 passes
    it would take to produce one, and letting them run hands an attacker a
    cheap way to burn two minutes of CPU per request.
    """
    if not is_classifier_available():
        return None

    start = time.monotonic()

    model = _model
    max_length = model.window if model is not None else WINDOW_TOKENS
    guard = model.guard if model is not None else GUARD_TOKENS

    all_ids = _encode(text)

    total_tokens = len(all_ids)
    max_tokens = get_config().admission_tokens
    truncated = max_tokens > 0 and total_tokens > max_tokens
    if truncated:
        if fail_on_truncate:
            raise UnscannableContentError(source, total_tokens, max_tokens)
        all_ids = all_ids[:max_tokens]

    # One loop for every length. There was a single-window shortcut here that
    # re-tokenized ``text`` with ``truncation=True`` whenever the input was at
    # most one window long, but a window carries two tokens less than that
    # of content: a 511- or 512-token input lost its last one or two tokens
    # and came back with ``truncated`` False (#298). A short input is one
    # pass of this loop at its natural length, which is what the shortcut
    # bought, so nothing was gained by keeping a second path.
    best_label = "BENIGN"
    best_score = 0.0

    # WINDOW_CONTENT_TOKENS states this for the default window; the tokenizer
    # is the source of truth so a model wrapping windows differently stays
    # correct.
    content_length = max_length - _tokenizer.num_special_tokens_to_add()
    # The guard band is content the neighbouring windows share; resolve_model
    # holds it to half a window, and max(..., 1) keeps the loop advancing for
    # a tokenizer that wraps in more special tokens than the default two.
    stride = max(content_length - guard, 1)

    # max(..., 1): empty text still gets its one pass, as it did before.
    for start_idx in range(0, max(len(all_ids), 1), stride):
        segment_ids = all_ids[start_idx : start_idx + content_length]
        input_ids, attention_mask = _pad_segment(segment_ids, max_length)
        seg_label, seg_score = _classify_segment(input_ids, attention_mask)

        if seg_score > best_score:
            best_score = seg_score
            best_label = seg_label

        if start_idx + content_length >= len(all_ids):
            break

    label = best_label
    score = best_score

    elapsed_ms = (time.monotonic() - start) * 1000

    if truncated:
        logger.warning(
            "Layer 2 scan truncated: %d tokens exceeds cap of %d; scanned the first %d only",
            total_tokens,
            max_tokens,
            max_tokens,
        )

    return ClassifierResult(
        label=label,
        score=score,
        latency_ms=round(elapsed_ms, 2),
        truncated=truncated,
        tokens=total_tokens,
    )


def _encode(text: str) -> list[int]:
    """Content token IDs, no special tokens, no truncation."""
    return list(
        _tokenizer(text, truncation=False, add_special_tokens=False, return_attention_mask=False)[
            "input_ids"
        ]
    )


def count_tokens(text: str) -> int | None:
    """``text``'s length in L2's tokens, or None when the model is absent.

    The unit ``Config.admission_tokens`` is stated in. Tokenizing is
    milliseconds where inference is minutes, which is why admission can
    afford to count before anything runs.
    """
    if not is_classifier_available():
        return None
    return len(_encode(text))


def head(text: str, tokens: int) -> str:
    """The longest prefix of ``text`` that is at most ``tokens`` of L2's tokens.

    What flag hands L3 when a payload is over the cap, so L2 and L3 read the
    same prefix. Without the model there is no token boundary to cut at; the
    longest prefix whose ``estimate_tokens`` fits stands in.
    """
    if not is_classifier_available():
        return text.encode("utf-8")[:tokens].decode("utf-8", errors="ignore")
    try:
        offsets = _tokenizer(
            text,
            truncation=False,
            add_special_tokens=False,
            return_attention_mask=False,
            return_offsets_mapping=True,
        )["offset_mapping"]
    except NotImplementedError:
        # A slow (Python) tokenizer has no offsets; decoding the same IDs
        # is the same prefix, give or take whitespace normalization.
        return str(_tokenizer.decode(_encode(text)[:tokens]))
    if len(offsets) <= tokens:
        return text
    return text[: offsets[tokens - 1][1]] if tokens > 0 else ""


def token_offsets(text: str) -> list[tuple[int, int]] | None:
    """Where each of L2's tokens sits in ``text``, as (start, end) characters.

    What paging cuts on (#340): a part is a run of whole tokens, so its size
    is stated in the unit the admission cap is. None when the model is
    absent or its tokenizer reports no offsets; a caller that cannot place a
    token boundary does not cut.
    """
    if not is_classifier_available():
        return None
    try:
        offsets = _tokenizer(
            text,
            truncation=False,
            add_special_tokens=False,
            return_attention_mask=False,
            return_offsets_mapping=True,
        )["offset_mapping"]
    except NotImplementedError:
        return None
    return [(int(start), int(end)) for start, end in offsets]


def estimate_tokens(text: str) -> int:
    """An upper bound on ``text``'s tokens when there is no tokenizer: its UTF-8 bytes.

    A SentencePiece token covers at least one byte of input (byte fallback
    is exactly one), so bytes do not undercount any script. Ruthlessly
    high on ASCII: an estimate may refuse what a count would admit, never
    the reverse.
    """
    return len(text.encode("utf-8"))


async def classify_async(
    text: str, *, fail_on_truncate: bool = False, source: str = "content"
) -> ClassifierResult | None:
    """Run :func:`classify` on a worker thread.

    Inference holds the GIL only inside ONNX Runtime's C++ kernels, so
    offloading keeps the asyncio event loop responsive while a scan runs.
    Every async caller should use this instead of calling classify directly.
    ``fail_on_truncate`` is for callers that refuse a partial scan anyway.
    """
    gate = _l2_gate()
    await gate.acquire(_caller())
    # The permit follows the THREAD, not this coroutine: a cancelled caller
    # leaves the scan running, and releasing on cancel would let the next
    # scan start beside it and break the bound.
    scan = asyncio.ensure_future(
        asyncio.to_thread(classify, text, fail_on_truncate=fail_on_truncate, source=source)
    )
    scan.add_done_callback(lambda _done: gate.release())
    return await asyncio.shield(scan)


class FairGate:
    """A counting gate that hands a freed permit to profiles in turn (#291).

    A plain semaphore is FIFO across every caller, so one profile queueing a
    hundred scans made every other profile wait behind all hundred: a
    gateway-wide stall one agent could cause, and a timing another agent
    could read. Here each caller key has its own FIFO, and a freed permit
    goes to the next key in rotation. Another profile's backlog now delays a
    scan by at most one scan per profile waiting, not by the backlog.
    """

    def __init__(self, permits: int) -> None:
        self._free = permits
        self._queues: collections.OrderedDict[
            str | None, collections.deque[asyncio.Future[None]]
        ] = collections.OrderedDict()

    def locked(self) -> bool:
        """True when a new caller would have to wait."""
        return self._free == 0

    async def acquire(self, key: str | None) -> None:
        """Wait for a permit in ``key``'s turn."""
        if self._free > 0 and not self._queues:
            self._free -= 1
            return
        waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._queues.setdefault(key, collections.deque()).append(waiter)
        try:
            await waiter
        except asyncio.CancelledError:
            # Granted, then cancelled before it could run: pass the permit on.
            if waiter.done() and not waiter.cancelled():
                self.release()
            raise

    def release(self) -> None:
        """Hand the permit to the next key in rotation, or put it back."""
        while self._queues:
            key, queue = next(iter(self._queues.items()))
            waiter = queue.popleft()
            if queue:
                self._queues.move_to_end(key)
            else:
                del self._queues[key]
            if not waiter.done():
                waiter.set_result(None)
                return
        self._free += 1


def _caller() -> str | None:
    """The profile a scan is for, or None standalone: the gate's turn key."""
    # Imported here: the gateway package imports this one on its way in.
    from ..gateway.context import get_current_profile

    profile = get_current_profile()
    return profile.name if profile is not None else None


_gate: tuple[asyncio.AbstractEventLoop, FairGate] | None = None


def _l2_gate() -> FairGate:
    """Bound concurrent scans, so a burst cannot oversubscribe the cores.

    Each scan already runs ``CLASSIFIER_THREADS`` intra-op threads; the boot
    warm-up hands L2 hundreds of descriptions at once (#216), and running
    them all together is slower than running them a few at a time. One gate
    per event loop, because its futures bind to the loop that made them.
    """
    global _gate
    loop = asyncio.get_running_loop()
    if _gate is None or _gate[0] is not loop:
        _gate = (loop, FairGate(int_env("TRENTINA_L2_CONCURRENCY", 2, minimum=1)))
    return _gate[1]


def classifier_status() -> str:
    """Report load state without triggering the lazy load.

    Health probes must stay cheap; calling is_classifier_available() here
    would pull a model off disk on the first request.
    """
    if _loaded:
        return "loaded"
    return "failed" if _load_attempted else "not-loaded"


def reset_classifier() -> None:
    """Reset classifier state. For testing only."""
    global _session, _tokenizer, _model, _loaded, _load_attempted
    _session = None
    _tokenizer = None
    _model = None
    _loaded = False
    _load_attempted = False
