# Fixture for trentina-httpx-client-outside-egress.
import httpx  # nosemgrep: trentina-network-reach-in-transports -- fixture for another rule

from trentina.egress import open_guarded


async def fetch(url):
    # ruleid: trentina-httpx-client-outside-egress
    async with httpx.AsyncClient(timeout=30) as client:
        return await client.get(url)


def sync_client():
    # ruleid: trentina-httpx-client-outside-egress
    return httpx.Client()


async def fetch_guarded(url):
    # ok: trentina-httpx-client-outside-egress
    async with open_guarded("GET", url, timeout=30) as resp:
        return resp.status_code


def provider_client():
    # ok: trentina-httpx-client-outside-egress
    return httpx.AsyncClient(timeout=10)  # nosemgrep: trentina-httpx-client-outside-egress -- fixed provider URL
