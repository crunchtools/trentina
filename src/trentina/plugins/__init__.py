"""Out-of-tree plugins, discovered from installed entry points.

A plugin is an installed distribution that exposes an entry point in a
versioned Trentina group (``trentina.transforms.v1`` today). The operator
installs the distribution INTO THE IMAGE — the container image is the only
distribution and nothing a verdict depends on is fetched at run time
(security-gateway constitution §I); this package never loads code from a path
or a URL, only names an entry point the environment already carries.

A profile opts in by naming a plugin ``dist:name`` in a processor chain. Until
a profile names one, nothing here runs: discovery is lazy, so an install that
no profile references costs nothing at startup.

The heavy lifting is in ``registry``. This package deliberately imports nothing
at module load (it is reached early, from ``gateway/drivers.py``), so importing
it drags in no gateway or layer code.
"""

from __future__ import annotations
