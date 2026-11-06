"""Profile secrets a running gateway can resolve, by env var name (#736).

Every secret a profile names, it names as an environment variable: a git
token, an LLM key, a ``${VAR}`` in a backend header, a bridge token. A
variable is fixed at exec time, and ``envscrub`` pops the ones no profile used
at startup, so a profile that needs a new one could not be validated, let
alone applied, before a restart: ``config_tool`` loads the candidate, the
loader finds the variable empty, and the write is refused. ``token_store``
closed that for the bearer token alone (#635); this closes it for the rest.

The store is the third place a profile secret is looked for, after ``VAR_FILE``
and ``VAR`` (``loader.read_profile_secret``). It is keyed by the SAME name, so
``profiles.yaml`` does not change, and nor do the rules built on that name:
the protected set that keeps a header from naming another profile's
credential, and ``config_guard``'s masking, see one namespace either way.

Read on every load and every reload, which is what makes a value put here
after startup live without one. A value enters out of band, never through a
tool: ``token_store`` can mint because the gateway generates the token, but a
GitHub token or an API key comes from outside, and a tool taking it as an
argument would copy it into the operator's transcript and the audit log::

    podman exec -i trentina python -m trentina.gateway.secret_store put NAME < value

``put`` is write-once, so a value in use is not replaced by accident;
``--replace`` is for rotating an outside credential, which keeps its name.
The store lives beside the others under ``/data``, which ``tools/confine.py``
refuses to every file tool.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from ..config import get_config
from . import secret_file
from .errors import ProfileConfigError

#: An env var name. It becomes a filename, so the shape is what keeps it one:
#: no dot, no slash, no traversal.
SECRET_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}\Z")

_DIR_NAME = "secrets"


def secrets_dir() -> Path:
    """The secret directory, beside the key and token stores."""
    return Path(get_config().db_path).parent / _DIR_NAME


def _path(name: str) -> Path:
    if not SECRET_NAME_RE.fullmatch(name):
        raise ProfileConfigError(f"secret name {name!r} is not an env var name")
    return secrets_dir() / name


def read_secret(name: str) -> str:
    """The stored value for ``name``, or "" when there is none.

    Absent is "", like an unset variable, so "is this required?" stays the
    caller's. A file that exists and cannot be read is a broken store, not an
    absent secret, and raises. ``O_NOFOLLOW`` refuses a symlink planted in the
    directory. Not held here: the loader holds what it resolves, once.
    """
    path = _path(name)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise ProfileConfigError(
            f"secret store: cannot read {name} ({exc.strerror or type(exc).__name__})"
        ) from exc
    with os.fdopen(fd, "rb") as fh:
        return fh.read().decode("utf-8").strip()


def put(name: str, value: str, *, replace: bool = False) -> None:
    """Store ``value`` under ``name``, 0600 in a 0700 directory.

    Refuses an existing name unless ``replace``: see the module docstring.
    """
    path = _path(name)
    value = value.strip()
    if not value:
        raise ProfileConfigError(f"secret store: refusing an empty value for {name}")
    secret_file.private_dir(_DIR_NAME)
    payload = value.encode("utf-8")
    if replace:
        secret_file.replace_atomically(path, payload)
    else:
        secret_file.write_once(path, payload)


def names() -> list[str]:
    """The names stored, never the values."""
    directory = secrets_dir()
    if not directory.is_dir():
        return []
    return sorted(p.name for p in directory.iterdir() if SECRET_NAME_RE.fullmatch(p.name))


def main(argv: list[str] | None = None) -> int:
    """``put NAME [--replace]`` reads the value from stdin; ``list`` prints names."""
    parser = argparse.ArgumentParser(prog="python -m trentina.gateway.secret_store")
    sub = parser.add_subparsers(dest="command", required=True)
    put_cmd = sub.add_parser("put", help="store stdin under NAME")
    put_cmd.add_argument("name")
    put_cmd.add_argument("--replace", action="store_true", help="rotate an existing value")
    sub.add_parser("list", help="print the stored names")
    args = parser.parse_args(argv)

    if args.command == "list":
        for name in names():
            print(name)
        return 0
    try:
        put(args.name, sys.stdin.read(), replace=args.replace)
    except FileExistsError:
        print(f"{args.name} is already stored; --replace rotates it", file=sys.stderr)
        return 1
    except ProfileConfigError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"stored {args.name}; reload_profiles to apply it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
