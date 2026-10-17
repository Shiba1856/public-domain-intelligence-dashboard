"""Shared helpers used by all data collectors."""
from datetime import datetime, timezone

import requests

# Every collector reports one of these statuses.
STATUS_LABELS = {
    "available": "Available",
    "not_found": "Not found",
    "unavailable": "Unavailable",
    "rate_limited": "Rate limited",
    "blocked": "Blocked",
}


class ResponseTooLargeError(Exception):
    """The remote response exceeded our size limit."""


def utc_now():
    """Current time as a readable UTC string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def make_result(source, source_url, status, message="", data=None):
    """Build the standard result structure every collector returns."""
    return {
        "source": source,
        "source_url": source_url,
        "retrieved_at": utc_now(),
        "status": status,
        "message": message,
        "data": data if data is not None else {},
    }


def fetch_limited(url, cfg, max_bytes, accept="application/json", params=None, timeout=None):
    """GET a public API URL with a timeout, redirect limit and size limit.

    Returns (status_code, final_url, body_bytes). Used only for the fixed
    public APIs (RDAP, crt.sh) - never for user-influenced hosts.
    """
    session = requests.Session()
    session.max_redirects = cfg["MAX_REDIRECTS"]
    response = session.get(
        url,
        params=params,
        headers={"User-Agent": cfg["USER_AGENT"], "Accept": accept},
        timeout=timeout or cfg["REQUEST_TIMEOUT"],
        stream=True,  # do not download everything before checking the size
    )
    try:
        chunks, total = [], 0
        for chunk in response.iter_content(chunk_size=8192):
            total += len(chunk)
            if total > max_bytes:
                raise ResponseTooLargeError()
            chunks.append(chunk)
        return response.status_code, response.url, b"".join(chunks)
    finally:
        response.close()
        session.close()