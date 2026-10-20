"""Check the process's own containment at startup (#268).

Trentina holds every profile's bearer, every backend's credential and the
OAuth signing key, so a file-write or code-execution primitive inside it is a
compromise of every agent it serves. The container flags that blunt such a
primitive (``--read-only``, ``--security-opt no-new-privileges``,
``--cap-drop=all``, seccomp) are set by whoever runs it, not by the image,
and nothing told an operator when one was missing.

This reads what the kernel says about the running process and names each gap
in one WARNING. ``TRENTINA_REQUIRE_HARDENED=true`` turns any gap into a
startup failure, for a deployment that would rather not run than run open.

Every name logged is a constant from this module or an environment variable
name the operator set; no value is ever read into a message.

Linux only. Without ``/proc`` the one gap reported is ``unverifiable``.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .config import bool_env
from .errors import ConfigError

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

# Secrets with a _FILE form. One that arrived in the environment is readable
# for the life of the process at /proc/self/environ, whatever envscrub pops.
FILE_FORM_SECRETS = (
    "TRENTINA_OAUTH_JWT_SIGNING_KEY",
    "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET",
    "TRENTINA_BACKEND_TOKEN_KEY",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
)

_ST_RDONLY = 1  # os.ST_RDONLY; spelled out because it is absent off Linux


@dataclass
class Posture:
    """What the checks found. ``gaps`` are constant codes, safe to log."""

    gaps: list[str] = field(default_factory=list)
    env_secrets: list[str] = field(default_factory=list)


def _status_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def _writable_import_path() -> bool:
    # sys.path[0] is the working directory under `python -m` unless
    # PYTHONSAFEPATH (or -P) is set. A writable entry anywhere on the path
    # turns a file write into code execution at the next lazy import, and
    # onnxruntime and transformers are imported lazily. A file entry is a zip
    # archive Python imports from. An entry that does not exist yet is judged
    # by its nearest existing ancestor: whoever can write there can create it.
    for entry in sys.path:
        path = Path(entry or os.getcwd()).absolute()
        while not path.exists() and path != path.parent:
            path = path.parent
        if os.access(path, os.W_OK):
            return True
    return False


def _initial_env_names(raw: bytes) -> set[str]:
    return {item.split(b"=", 1)[0].decode("utf-8", "replace") for item in raw.split(b"\0") if item}


def inspect(proc: Path = Path("/proc/self")) -> Posture:
    """Read the running process's containment. Never raises.

    Without ``/proc`` nothing can be verified, and that is itself the gap
    ``unverifiable``: ``TRENTINA_REQUIRE_HARDENED`` must not pass a check
    that never ran.
    """
    posture = Posture()
    try:
        status = _status_fields((proc / "status").read_text())
    except OSError:
        posture.gaps.append("unverifiable")
        return posture
    if status.get("NoNewPrivs") != "1":
        posture.gaps.append("no_new_privs_off")
    try:
        if int(status.get("CapEff", ""), 16) != 0:
            posture.gaps.append("capabilities_held")
    except ValueError:
        posture.gaps.append("capabilities_unknown")
    # 2 is filter mode; 0 is none, 1 strict (which would not run Python).
    if status.get("Seccomp") != "2":
        posture.gaps.append("seccomp_off")
    if not sys.flags.safe_path:
        posture.gaps.append("cwd_on_import_path")
    if _writable_import_path():
        posture.gaps.append("import_path_writable")
    try:
        if not os.statvfs("/").f_flag & _ST_RDONLY:
            posture.gaps.append("rootfs_writable")
    except OSError:
        posture.gaps.append("rootfs_unknown")
    _check_env_secrets(proc, FILE_FORM_SECRETS, posture)
    return posture


def _check_env_secrets(proc: Path, names: Iterable[str], posture: Posture) -> None:
    try:
        initial = _initial_env_names((proc / "environ").read_bytes())
    except OSError:
        posture.gaps.append("unverifiable")
        return
    posture.env_secrets = sorted(name for name in set(names) if name in initial)
    if posture.env_secrets:
        posture.gaps.append("secret_in_environment")


def check_startup_posture(proc: Path = Path("/proc/self")) -> Posture:
    """Log every gap; refuse to start on any when TRENTINA_REQUIRE_HARDENED is set."""
    posture = inspect(proc)
    if posture.gaps:
        _report(posture)
    else:
        logger.info("posture: no_new_privs, no capabilities, seccomp, read-only rootfs")
    return posture


def check_secret_sources(names: Iterable[str], proc: Path = Path("/proc/self")) -> Posture:
    """The same verdict for the secrets configuration named, once it is loaded.

    ``check_startup_posture`` runs before profiles exist, so it knows only the
    fixed names. Call this after everything has read its secrets, with
    ``loader.secret_env_names()``: a profile's ``${VAR}`` or a bridge token
    that arrived in the environment is the same gap.
    """
    posture = Posture()
    _check_env_secrets(proc, names, posture)
    if posture.gaps:
        _report(posture)
    return posture


def check_l2_gate() -> Posture:
    """Name an L2 model that has no passing record for either of its gates.

    The Layer contract makes reading through obfuscation the model's job, so
    a model that one zero-width character blinds is a gap in the perimeter
    the same way a missing seccomp filter is one in the container (#362).
    The benign gate is the other side (#411): a model, or a threshold, never
    measured against the content the gateway delivers refuses routine reads,
    and an agent refused its data works from part of it. Call after the
    classifier has loaded. No model at all is not this gap:
    ``TRENTINA_REQUIRE_L2`` decides that.
    """
    from .quarantine.classifier import model_info

    posture = Posture()
    model = model_info()
    if model is not None and model.gate != "passed":
        posture.gaps.append(f"l2_obfuscation_gate_{model.gate}")
    if model is not None and model.benign_gate != "passed":
        posture.gaps.append(f"l2_benign_gate_{model.benign_gate}")
    if posture.gaps:
        _report(posture)
    return posture


def _report(posture: Posture) -> None:
    logger.warning(
        "posture: running without %s. See docs/deployment-hardening.md.",
        ", ".join(posture.gaps),
    )
    if posture.env_secrets:
        # Names only: these are the operator's variable names, never values.
        logger.warning(
            "posture: %s came from the environment and stay readable at "
            "/proc/self/environ; use the _FILE form",
            ", ".join(posture.env_secrets),
        )
    if bool_env("TRENTINA_REQUIRE_HARDENED", False):
        raise ConfigError(
            "TRENTINA_REQUIRE_HARDENED is set and the process is not contained: "
            + ", ".join(posture.gaps)
        )
