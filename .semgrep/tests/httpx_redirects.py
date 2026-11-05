# Fixture for trentina-httpx-follow-redirects.
import httpx  # nosemgrep: trentina-network-reach-in-transports -- fixture for another rule


async def fetch(url):
    # ruleid: trentina-httpx-follow-redirects, trentina-httpx-client-outside-egress
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        return await client.get(url)


def fetch_sync(url):
    # ruleid: trentina-httpx-follow-redirects
    return httpx.get(url, follow_redirects=True)


async def fetch_per_request(client, url):
    # ruleid: trentina-httpx-follow-redirects
    return await client.get(url, follow_redirects=True)


async def fetch_manual(client, url):
    # ok: trentina-httpx-follow-redirects
    return await client.get(url, follow_redirects=False)
