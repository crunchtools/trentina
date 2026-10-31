#!/usr/bin/env python3
"""Print a verifier for an approval password (#637).

    python scripts/approval_password.py

Or against the shipped image, which is where an operator will usually be:

    podman run --rm -it quay.io/crunchtools/trentina:latest \
        python /app/scripts/approval_password.py

The password is read from the terminal, never from a flag, so it does not land
in shell history. What is printed is a scrypt verifier: put THAT in the
gateway's config and keep the password in your head. The gateway can check a
password against the verifier and cannot recover one from it, which is the
point — a config mount is readable by anything running in the container,
including the operator agent this is meant to hold the decision away from.

A script rather than a module entry point because printing to a terminal is
what a script is for; the library half (`gateway/approver.py`) holds no print.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from trentina.gateway.approver import make_verifier


def main() -> int:
    password = getpass.getpass("Approval password: ")
    if password != getpass.getpass("Again: "):
        print("They do not match.", file=sys.stderr)
        return 1
    try:
        verifier = make_verifier(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print()
    print("Put this in the gateway's config — this, not the password:")
    print()
    print(f"  TRENTINA_APPROVAL_PASSWORD_HASH={verifier}")
    print()
    print("Better: write the value to a file in the read-only config mount and set")
    print("TRENTINA_APPROVAL_PASSWORD_HASH_FILE to its path, so it is never in an")
    print("environment variable at all.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
