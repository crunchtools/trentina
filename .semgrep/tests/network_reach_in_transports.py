# Fixture for trentina-network-reach-in-transports.
# ruleid: trentina-network-reach-in-transports
import httpx

# ruleid: trentina-network-reach-in-transports
from trentina.gateway.upstream import pinned_send

# ruleid: trentina-network-reach-in-transports
from trentina.reach import egress

# ruleid: trentina-network-reach-in-transports
from ..gateway import upstream

# A route takes the contract, and the network only as the Upstream it is handed.
# ok: trentina-network-reach-in-transports
from trentina.transports.base import RefusedError
