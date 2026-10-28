"""Resolve a ``dist:name`` plugin reference to a built, contract-checked instance.

A transform plugin is an installed distribution exposing an entry point in the
``trentina.transforms.v1`` group whose value is a factory ``(config) ->
Transform``. The ``.v1`` suffix is the compat anchor: within a major version
core may only ADD methods-with-defaults to the ``Transform`` ABC, never change
``run``'s signature, so a plugin written against version 1 keeps resolving.
``SUPPORTED_TRANSFORM_API`` is the set of ``api_version`` values this build
accepts — an unsupported one is refused BY NAME at config load, never with an
``AttributeError`` at the first request.

Resolution failures here are ``ProfileConfigError`` and name the
operator-authored thing (the distribution, the entry point) — a config-load
refusal an operator reads, distinct from the closed reason codes an agent sees
at run time (#262/#263).

Discovery is lazy — ``entry_points`` is read only when a profile names a
plugin — so an installed distribution that no profile references costs nothing.
"""

from __future__ import annotations

import importlib.metadata as im
from typing import TYPE_CHECKING

from ..gateway.errors import ProfileConfigError
from ..transforms.base import Transform

if TYPE_CHECKING:
    from collections.abc import Mapping

#: The entry-point group a transform plugin registers under. The version is
#: part of the name: a v2 contract would be a new group, discovered separately.
TRANSFORM_GROUP = "trentina.transforms.v1"

#: The ``api_version`` values this build accepts. A plugin declaring anything
#: else is refused by name at load.
SUPPORTED_TRANSFORM_API: frozenset[int] = frozenset({1})


def discover(group: str) -> dict[str, im.EntryPoint]:
    """Map ``dist:name`` to the entry point, for every installed entry point in
    ``group``. The key is exactly what a profile names."""
    found: dict[str, im.EntryPoint] = {}
    for ep in im.entry_points(group=group):
        dist = ep.dist.name if ep.dist is not None else ""
        found[f"{dist}:{ep.name}"] = ep
    return found


def installed_version(dist: str) -> str | None:
    """The installed version of ``dist``, or None when it is not installed."""
    try:
        return im.version(dist)
    except im.PackageNotFoundError:
        return None


def resolve_transform(
    ref: str,
    config: Mapping[str, object],
    *,
    profile_name: str,
    catalog: dict[str, im.EntryPoint] | None = None,
) -> Transform:
    """Build the transform a ``dist:name`` reference names, or fail closed.

    Loads the entry point (operator-installed code), calls its factory with the
    chain's config, and holds the result to the contract: it must be a
    ``Transform`` subclass at a supported ``api_version``. The channel and kind
    locks are the caller's (``build_transforms``), the same as for a built-in.

    ``catalog`` is a pre-discovered entry-point map; ``build_transforms`` passes
    one so a chain naming several plugins scans ``entry_points`` once, not once
    per reference. Omitted, discovery runs here.
    """
    dist, _, entry = ref.partition(":")
    found = catalog if catalog is not None else discover(TRANSFORM_GROUP)
    if ref not in found:
        if installed_version(dist) is None:
            raise ProfileConfigError(
                f"Profile {profile_name!r}: plugin transform {ref!r} — distribution "
                f"{dist!r} is not installed; installed transform plugins: {sorted(found)}"
            )
        here = sorted(k for k in found if k.startswith(f"{dist}:"))
        raise ProfileConfigError(
            f"Profile {profile_name!r}: plugin transform {ref!r} — distribution {dist!r} "
            f"exposes no transform {entry!r}; it exposes: {here}"
        )
    try:
        instance = found[ref].load()(config)
    except Exception as exc:
        # A plugin the operator installed failed to import or build. Refuse the
        # profile with a named error instead of letting an arbitrary exception
        # abort the load; `from exc` keeps the real traceback for the operator
        # debugging their own plugin.
        raise ProfileConfigError(
            f"Profile {profile_name!r}: plugin transform {ref!r} failed to load or build"
        ) from exc
    if not isinstance(instance, Transform):
        raise ProfileConfigError(
            f"Profile {profile_name!r}: plugin transform {ref!r} did not return a "
            f"trentina.transforms.base.Transform (got {type(instance).__name__})"
        )
    if instance.name != entry:
        # The name is the transform's identity in records and the audit; a
        # profile naming `dist:entry` must receive a transform that calls itself
        # `entry`, not one masquerading under another name.
        raise ProfileConfigError(
            f"Profile {profile_name!r}: plugin transform {ref!r} exposes a transform "
            f"named {instance.name!r}, not {entry!r}"
        )
    try:
        api_version = instance.api_version
    except Exception as exc:
        raise ProfileConfigError(
            f"Profile {profile_name!r}: plugin transform {ref!r} has no readable api_version"
        ) from exc
    # `isinstance(int)` first: an unhashable api_version (a list, say) would
    # raise TypeError on the set membership rather than refuse cleanly.
    if not isinstance(api_version, int) or api_version not in SUPPORTED_TRANSFORM_API:
        raise ProfileConfigError(
            f"Profile {profile_name!r}: plugin transform {ref!r} declares api_version "
            f"{api_version!r}; this build supports {sorted(SUPPORTED_TRANSFORM_API)}"
        )
    return instance
