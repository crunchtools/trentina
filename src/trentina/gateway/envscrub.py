"""Drop startup-only secrets from ``os.environ`` once they are held (#268).

One environment holds every profile's bearer and LLM key, the OAuth signing
key and the upstream Google secret. Code execution in this process can read
all of it through ``os.environ``. This removes the ones nothing reads after
startup, so reading ``os.environ`` later finds nothing, and neither does any
child process.

It does NOT protect ``/proc/self/environ``. The kernel serves that file from
the process's initial environment block, which ``unsetenv`` never rewrites,
so every value is still there for anything that can read the file (checked:
a popped variable still appears in it). The real fix for a secret is its
``_FILE`` form, which never enters the environment at all.

What is popped, and why each is safe:

- ``TRENTINA_OAUTH_JWT_SIGNING_KEY`` and ``TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET``
  are read once in ``_build_oauth_context``, and the provider derives its keys
  from them there. Enabling OAuth later needs a restart anyway.
- ``TRENTINA_BACKEND_TOKEN_KEY`` is read once by ``configure_backend_tokens``,
  which derives the grant store's keys from it before the scrub (#479).
- The ``Config`` keys (``GEMINI_API_KEY``, ``OPENAI_API_KEY``,
  ``ANTHROPIC_API_KEY``, ``OPENROUTER_API_KEY``) are read once, into the
  ``get_config()`` singleton, which is built before the scrub.
- Each ``llm_providers`` entry's ``api_key_env``: read by ``load_llm_providers``
  at startup, and ``reload_profiles`` refuses to change that section.

What is kept: every name a profile resolved a secret from
(``loader.profile_env_names``), because ``reload_profiles`` resolves them
again. A name on both lists is kept. A reload that introduces a reference to a
name already popped fails closed with the loader's usual "not set" error and
the running config stays; use the ``_FILE`` form for it.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from ..config import get_config
from .loader import profile_env_names

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

STARTUP_ONLY_SECRETS = (
    "TRENTINA_OAUTH_JWT_SIGNING_KEY",
    "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET",
    "TRENTINA_BACKEND_TOKEN_KEY",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
)


def scrub_startup_secrets(extra: Iterable[str] = ()) -> list[str]:
    """Pop the startup-only secrets, plus ``extra``, that no profile depends on.

    Returns the names removed. Names are the operator's configuration, never
    a caller's, so they are safe to log; values never are.
    """
    get_config()  # the singleton must hold its keys before they go
    keep = profile_env_names()
    removed = sorted(
        {
            name
            for name in (*STARTUP_ONLY_SECRETS, *extra)
            if name not in keep and os.environ.pop(name, None) is not None
        }
    )
    if removed:
        logger.info(
            "startup: removed %d secret(s) from os.environ after loading them: %s "
            "(still in /proc/self/environ; prefer the _FILE form)",
            len(removed),
            ", ".join(removed),
        )
    return removed
