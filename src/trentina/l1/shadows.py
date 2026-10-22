"""Module shadow detection for Python directories.

Detects Python files that shadow standard library modules — a supply chain
attack vector where a local file with the same name as a stdlib module is
loaded instead of the real one.  See wunderwuzzi's Claude Code Opus 5 bypass
(2026-08-26) for a real-world exploit chain using struct.py shadowing.

The scan reads a directory through a descriptor the caller already holds
(#287): ``dir_tool`` lists through the fd confinement checked, and hands the
same entries here, so the listing delivered and the shadows found come from
one read of one directory. Each candidate is opened relative to that fd with
``O_NOFOLLOW`` and must be a regular file. A shadow that is a symlink is
still a shadow, since Python would import through it, but it is reported as
``symlink`` and never read: its target may be anywhere.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass, field
from itertools import islice
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

log = logging.getLogger(__name__)

STDLIB_MODULES: frozenset[str] = sys.stdlib_module_names

_EXEC_RE = re.compile(r"\b(?:exec|eval|compile)\s*\(")
_PROCESS_RE = re.compile(r"\b(?:subprocess|os\.system|os\.popen|os\.exec\w*|Popen)\b")
_DYNAMIC_IMPORT_RE = re.compile(r"\b__import__\s*\(")
_CHR_RE = re.compile(r"chr\s*\(\s*\d+\s*\)")
_INTERNAL_IMPORT_RE = re.compile(r"(?:from\s+_\w+\s+import|import\s+_\w+)")
_NETWORK_RE = re.compile(r"\b(?:socket|urllib|http\.client|requests|httpx)\b")
_OBFUSCATION_RE = re.compile(
    r"(?:"
    r"\\x[0-9a-fA-F]{2}"
    r"|b(?:64|85|16)decode"
    r"|a85decode"
    r"|join\s*\(\s*\[.{0,200}?chr"
    r"|getattr\s*\(.{0,200}?,\s*[\"']__"
    r"|codecs\.decode"
    r"|bytes\.fromhex"
    r")"
)

_SHELL_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "decode_exec",
        "decoded text piped to a shell",
        re.compile(
            r"(?:base64\s+(?:-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d)"
            r"[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
        ),
    ),
    (
        "eval_decode",
        "eval of decoded text",
        re.compile(r"\beval\b[^\n]{0,200}?(?:base64|xxd\s+-r|\brev\b|\\x[0-9a-fA-F]{2})"),
    ),
    ("hex_escapes", "run of hex escapes", re.compile(r"(?:\\x[0-9a-fA-F]{2}){4}")),
    ("reverse_shell", "/dev/tcp or /dev/udp redirection", re.compile(r"/dev/(?:tcp|udp)/")),
)
_NODE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "code_execution",
        "eval/Function constructor",
        re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
    ),
    (
        "obfuscation",
        "base64/char-code decoding",
        re.compile(
            r"\batob\s*\(|Buffer\.from\([^)\n]{0,200}base64|"
            r"(?:fromCharCode[^\n]{0,200}){3}"
        ),
    ),
)
_IP_REGISTRY_RE = re.compile(r"^\s*(?:@[\w.-]+:)?registry\s*=\s*\w+://(?:\d{1,3}\.){3}\d{1,3}\b")
_NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")

AUTOEXEC_FILES: dict[str, str] = {
    "package.json": "node",
    ".npmrc": "npmrc",
    ".bashrc": "shell",
    ".profile": "shell",
    ".bash_profile": "shell",
    ".env": "shell",
}
"""Files a tool loads and runs, or sources, by name alone (#76). The registry
only SELECTS which files get the per-language scan: presence is a count, never
a detection, since a ``package.json`` or ``.env`` is in nearly every repo."""
GIT_HOOKS: frozenset[str] = frozenset(
    {
        "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
        "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout",
        "post-merge", "pre-push", "pre-receive", "update", "post-receive", "post-update",
        "push-to-checkout", "pre-auto-gc", "post-rewrite", "fsmonitor-watchman",
    }
)  # fmt: skip
_NOT_CONTENT = frozenset({"symlink", "linked", "size", "unscanned", "unreadable", "binary"})

MAX_FILE_SIZE = 500_000
MAX_SCAN_BYTES = 4_000_000
"""Bytes read across one directory's shadows. Past it a shadow is still
reported, with an ``unscanned`` indicator, so the scan's cost is bounded
without a shadow going unreported."""
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
_DIR_FLAGS = _OPEN_FLAGS | os.O_DIRECTORY


@dataclass
class ShadowStats:
    """Stdlib-shadowing files in a directory, as L1 counts.

    Unlike every other stage this one reads a DIRECTORY, not text, so the
    ``dir`` producer runs it and merges the counts into the listing's L1 stats.
    Both counts are suspicious, and any shadow at all makes L1's risk
    ``critical``: one ``struct.py`` beside the code an agent is about to run is
    the whole attack, so there is no count below which it is merely medium.
    """

    files: int = 0
    obfuscated: int = 0
    autoexec_files: int = 0
    """Auto-execute files found (#76). Informational: never suspicious by name."""
    autoexec_obfuscated: int = 0
    """Of those, files with obfuscation inside. Suspicious, but not critical alone."""

    @classmethod
    def from_result(cls, result: ShadowScanResult) -> ShadowStats:
        return cls(
            files=len(result.shadows_found),
            obfuscated=sum(1 for f in result.shadows_found if f.is_obfuscated),
            autoexec_files=len(result.autoexec_found),
            autoexec_obfuscated=sum(1 for f in result.autoexec_found if f.is_obfuscated),
        )


@dataclass
class ObfuscationIndicator:
    """A single obfuscation signal found in a file."""

    category: str
    description: str
    line_number: int | None = None


@dataclass
class ShadowFinding:
    """A Python file that shadows a standard library module."""

    filename: str
    shadows_module: str
    path: str
    obfuscation_indicators: list[ObfuscationIndicator] = field(default_factory=list)
    risk_level: str = "high"

    @property
    def is_obfuscated(self) -> bool:
        return len(self.obfuscation_indicators) > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "filename": self.filename,
            "shadows_module": self.shadows_module,
            "path": self.path,
            "risk_level": self.risk_level,
            "is_obfuscated": self.is_obfuscated,
            "obfuscation_indicators": [asdict(i) for i in self.obfuscation_indicators],
        }


@dataclass
class AutoexecFinding:
    """A file a tool runs by name (see ``AUTOEXEC_FILES``), with what was found in it."""

    filename: str
    kind: str
    obfuscation_indicators: list[ObfuscationIndicator] = field(default_factory=list)

    @property
    def is_obfuscated(self) -> bool:
        """True when the file holds at least one obfuscation indicator."""
        return len(self.obfuscation_indicators) > 0


@dataclass
class ShadowScanResult:
    """Result of scanning a directory for module shadows and auto-execute files."""

    directory: str
    shadows_found: list[ShadowFinding] = field(default_factory=list)
    autoexec_found: list[AutoexecFinding] = field(default_factory=list)
    files_scanned: int = 0
    entries_read: int = 0
    """Directory entries looked at, so a caller that bounded the scan can tell
    whether the bound cut it short."""
    bytes_read: int = 0
    """Shadow bytes read so far, against ``MAX_SCAN_BYTES``."""

    @property
    def risk_level(self) -> str:
        has_obfuscated = any(f.is_obfuscated for f in self.shadows_found)
        return "critical" if has_obfuscated else "high" if self.shadows_found else "low"

    @property
    def has_shadows(self) -> bool:
        return len(self.shadows_found) > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "directory": self.directory,
            "files_scanned": self.files_scanned,
            "risk_level": self.risk_level,
            "has_shadows": self.has_shadows,
            "shadows": [s.to_dict() for s in self.shadows_found],
        }


def _scan_for_obfuscation(content: str) -> list[ObfuscationIndicator]:
    """Scan Python source for obfuscation indicators."""
    indicators: list[ObfuscationIndicator] = []

    for i, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if _EXEC_RE.search(stripped):
            indicators.append(ObfuscationIndicator("code_execution", "exec/eval/compile call", i))

        if _PROCESS_RE.search(stripped):
            indicators.append(ObfuscationIndicator("process_spawn", "subprocess/os.system call", i))

        if _DYNAMIC_IMPORT_RE.search(stripped):
            indicators.append(ObfuscationIndicator("dynamic_import", "__import__ call", i))

        chr_matches = _CHR_RE.findall(stripped)
        if len(chr_matches) >= 3:
            indicators.append(
                ObfuscationIndicator(
                    "char_building", f"{len(chr_matches)} chr() calls on one line", i
                )
            )

        if _INTERNAL_IMPORT_RE.search(stripped):
            indicators.append(
                ObfuscationIndicator(
                    "internal_import",
                    "imports from internal (_) module — re-exports real API while adding payload",
                    i,
                )
            )

        if _NETWORK_RE.search(stripped):
            indicators.append(
                ObfuscationIndicator("network_access", "network library reference", i)
            )

        if _OBFUSCATION_RE.search(stripped):
            indicators.append(ObfuscationIndicator("obfuscation", "encoding/decoding pattern", i))

    return indicators


def _scan_patterns(
    text: str, patterns: tuple[tuple[str, str, re.Pattern[str]], ...]
) -> list[ObfuscationIndicator]:
    indicators: list[ObfuscationIndicator] = []
    for i, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indicators.extend(
            ObfuscationIndicator(category, description, i)
            for category, description, pattern in patterns
            if pattern.search(stripped)
        )
    return indicators


def _scan_npmrc(content: str) -> list[ObfuscationIndicator]:
    """Obfuscation in ``.npmrc``, or a registry redirected to a bare IP address."""
    indicators = _scan_patterns(content, _SHELL_PATTERNS)
    for i, line in enumerate(content.split("\n"), 1):
        if _IP_REGISTRY_RE.match(line):
            indicators.append(ObfuscationIndicator("registry_redirect", "registry is an IP", i))
    return indicators


def _scan_package_json(content: str) -> list[ObfuscationIndicator] | None:
    """Obfuscation in install-time scripts, or None when it declares none."""
    try:
        manifest = json.loads(content)
    except (ValueError, RecursionError):
        return None
    scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
    if not isinstance(scripts, dict):
        return None
    hooks = [scripts[k] for k in _NPM_LIFECYCLE if isinstance(scripts.get(k), str)]
    if not hooks:
        return None
    return _scan_patterns("\n".join(hooks), _SHELL_PATTERNS + _NODE_PATTERNS)


_SCANNERS: dict[str, Callable[[str], list[ObfuscationIndicator] | None]] = {
    "shell": lambda content: _scan_patterns(content, _SHELL_PATTERNS),
    "npmrc": _scan_npmrc,
    "node": _scan_package_json,
}


def _not_read(st: os.stat_result, result: ShadowScanResult) -> ObfuscationIndicator | None:
    """Why the shadow ``st`` is reported without being read, or None to read it.

    A file with more than one link is not read, nor its size reported: a hard
    link to Trentina's own state would pass every check on the directory it
    sits in, and either answer would be a bit about that file (#287).
    """
    if not stat.S_ISREG(st.st_mode):
        return ObfuscationIndicator("unreadable", "shadow changed type while being read")
    if st.st_nlink > 1:
        return ObfuscationIndicator("linked", "shadow is hard-linked; not read")
    if st.st_size > MAX_FILE_SIZE:
        return ObfuscationIndicator(
            "size", f"unusually large for a stdlib shadow ({st.st_size} bytes)"
        )
    if st.st_size > MAX_SCAN_BYTES - result.bytes_read:
        return ObfuscationIndicator("unscanned", "directory's shadow read budget spent")
    return None


def _read_shadow(
    fd: int,
    result: ShadowScanResult,
    scan: Callable[[str], list[ObfuscationIndicator] | None] = _scan_for_obfuscation,
) -> list[ObfuscationIndicator] | None:
    """Obfuscation indicators for the open file ``fd``, within the scan's budget.

    None when ``scan`` finds the file is not one it applies to."""
    skipped = _not_read(os.fstat(fd), result)
    if skipped is not None:
        return [skipped]
    with open(fd, "rb", closefd=False) as fh:
        # One byte past the cap, so a file that grew after fstat is caught too.
        raw = fh.read(MAX_FILE_SIZE + 1)
    result.bytes_read += len(raw)
    if len(raw) > MAX_FILE_SIZE:
        return [ObfuscationIndicator("size", "unusually large for a stdlib shadow")]
    if b"\x00" in raw:
        return [ObfuscationIndicator("binary", "shadow is not text")]
    return scan(raw.decode("utf-8", errors="replace"))


def _scan_at(
    dir_fd: int,
    name: str,
    result: ShadowScanResult,
    scan: Callable[[str], list[ObfuscationIndicator] | None] = _scan_for_obfuscation,
) -> list[ObfuscationIndicator] | None:
    """Indicators for ``name`` in ``dir_fd``, or None when it is no importable file.

    Opened relative to the descriptor and never through a symlink. A
    symlink is reported without being read; a FIFO, device or directory is
    not a module Python would import, so it is not a shadow.
    """
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode):
        return [ObfuscationIndicator("symlink", "shadow is a symlink; its target was not read")]
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        # TRUST: opening a caller-placed file inside a confined directory
        #   untrusted: `name`, and the file's bytes, chosen by whoever writes the root
        #   judged-by: confine.open_confined admitted `dir_fd`; O_NOFOLLOW keeps the
        #     open in it, and _read_shadow refuses anything but a regular file
        #   on-failure: fail-closed; an unreadable shadow is still a critical shadow
        #   owner: tools/dir._list_confined, which holds `dir_fd`
        #   evidence: T1 os.open dir_fd and O_NOFOLLOW; T3 #287; T4 S_ISREG above
        fd = os.open(name, _OPEN_FLAGS, dir_fd=dir_fd)
    except OSError:
        return [ObfuscationIndicator("unreadable", "shadow file exists but cannot be read")]
    try:
        return _read_shadow(fd, result, scan)
    except OSError:
        return [ObfuscationIndicator("unreadable", "shadow file exists but cannot be read")]
    finally:
        os.close(fd)


def _record(
    result: ShadowScanResult, filename: str, module: str, indicators: list[ObfuscationIndicator]
) -> None:
    """Count the shadow ``filename`` of stdlib ``module`` into ``result``."""
    result.files_scanned += 1
    result.shadows_found.append(
        ShadowFinding(
            filename=filename,
            shadows_module=module,
            path=filename,
            obfuscation_indicators=indicators,
            risk_level="critical" if indicators else "high",
        )
    )


def scan_shadows(
    dir_fd: int, entries: Iterable[os.DirEntry[str]], directory: str
) -> ShadowScanResult:
    """Shadows among ``entries``, as listed from the open directory ``dir_fd``.

    The caller lists and passes the entries, so what it delivers and what
    is scanned are the same read. ``directory`` is a label only; nothing is
    opened by path. Blocking: run it in the thread that holds ``dir_fd``.
    """
    result = ShadowScanResult(directory=directory)
    for entry in entries:
        result.entries_read += 1
        _scan_entry(dir_fd, entry, result)
    return result


def detect_module_shadows(directory: str, *, max_entries: int | None = None) -> ShadowScanResult:
    """Scan a directory named by path for Python files that shadow stdlib modules.

    NOT confined: for an operator's own path only. A tool handling a
    caller's path opens it through ``tools/confine.py`` and calls
    ``scan_shadows`` on that descriptor (#287).

    ``max_entries`` stops the scan after that many directory entries, lazily.
    """
    try:
        fd = os.open(directory, _DIR_FLAGS)
    except OSError:
        return ShadowScanResult(directory=directory)
    try:
        with os.scandir(fd) as it:
            return scan_shadows(fd, islice(it, max_entries), directory)
    finally:
        os.close(fd)


def _scan_entry(dir_fd: int, entry: os.DirEntry[str], result: ShadowScanResult) -> None:
    """Record ``entry`` in ``result`` if it shadows a stdlib module."""
    name = entry.name
    if name in AUTOEXEC_FILES:
        _scan_autoexec(dir_fd, name, AUTOEXEC_FILES[name], name, result)
        return
    if name == ".git":
        _scan_git_hooks(dir_fd, result)
        return
    if name.endswith(".py"):
        module_name = name[:-3]
        if module_name not in STDLIB_MODULES:
            result.files_scanned += entry.is_file(follow_symlinks=False)
            return
        indicators = _scan_at(dir_fd, name, result)
        if indicators is not None:
            _record(result, name, module_name, indicators)
        return
    if name in STDLIB_MODULES:
        _scan_package(dir_fd, name, result)


def _scan_package(dir_fd: int, name: str, result: ShadowScanResult) -> None:
    """A stdlib-named directory with an ``__init__.py`` is a package shadow."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        # Whether its target holds an __init__.py is a read through the link.
        _record(result, name, name, [ObfuscationIndicator("symlink", "stdlib-named symlink")])
        return
    if not stat.S_ISDIR(st.st_mode):
        return
    try:
        pkg_fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError:
        return
    try:
        indicators = _scan_at(pkg_fd, "__init__.py", result)
    finally:
        os.close(pkg_fd)
    if indicators is not None:
        _record(result, f"{name}/__init__.py", name, indicators)


def _scan_autoexec(dir_fd: int, name: str, kind: str, label: str, result: ShadowScanResult) -> None:
    """Count the auto-execute file ``name``; its indicators are obfuscation inside it.

    A symlink, hard link, size or read-budget indicator says the file was not
    read, which is no obfuscation, so it is dropped: presence alone is a count.
    """
    indicators = _scan_at(dir_fd, name, result, _SCANNERS[kind])
    if indicators is None:
        return
    result.files_scanned += 1
    found = [i for i in indicators if i.category not in _NOT_CONTENT]
    result.autoexec_found.append(AutoexecFinding(label, kind, found))


def _scan_git_hooks(dir_fd: int, result: ShadowScanResult) -> None:
    """The hooks git runs from ``.git/hooks``, opened below ``dir_fd`` without a link."""
    try:
        git_fd = os.open(".git", _DIR_FLAGS, dir_fd=dir_fd)
    except OSError:
        return
    try:
        hooks_fd = os.open("hooks", _DIR_FLAGS, dir_fd=git_fd)
    except OSError:
        return
    finally:
        os.close(git_fd)
    try:
        with os.scandir(hooks_fd) as it:
            names = sorted({e.name for e in it if e.name in GIT_HOOKS})
        for hook in names:
            # Git ignores a hook without an executable bit, so its text is inert.
            if not os.stat(hook, dir_fd=hooks_fd, follow_symlinks=False).st_mode & 0o111:
                continue
            _scan_autoexec(hooks_fd, hook, "shell", f".git/hooks/{hook}", result)
    except OSError:
        return
    finally:
        os.close(hooks_fd)
