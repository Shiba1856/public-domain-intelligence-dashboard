"""Website metadata collector: ONE bounded request, not a security scan."""
import re
import time
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from ..validation import ResolutionError, UnsafeTargetError, check_url_is_safe
from . import make_result

SOURCE = "Direct HTTP(S) request to the submitted domain (requests + BeautifulSoup)"
# Small allowlist of response headers we are willing to display.
ALLOWED_HEADERS = ("server", "content-type", "content-language", "cache-control",
                   "last-modified", "strict-transport-security", "x-frame-options",
                   "x-content-type-options", "referrer-policy")
REDIRECT_CODES = {301, 302, 303, 307, 308}


class _TooManyRedirects(Exception):
    pass


def _read_limited(response, max_bytes, deadline):
    """Read at most ``max_bytes`` (decoded) and stop at the deadline."""
    chunks, total = [], 0
    for chunk in response.iter_content(chunk_size=8192):
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            return b"".join(chunks)[:max_bytes], True
        if time.monotonic() > deadline:
            return b"".join(chunks), True
    return b"".join(chunks), False


def _fetch(start_url, cfg, max_redirects, read_body):
    """GET a URL, following redirects by hand so every hop is re-validated.

    Known limit: DNS is checked just before connecting, not pinned to the
    connection, so a malicious DNS server could in theory change its answer
    in between ("DNS rebinding"). See README, Known limitations.
    """
    headers = {"User-Agent": cfg["USER_AGENT"],
               "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"}
    timeout = cfg["REQUEST_TIMEOUT"]
    deadline = time.monotonic() + timeout * 3
    redirects, current = [], start_url
    for hop in range(max_redirects + 1):
        check_url_is_safe(current)  # re-validate EVERY hop
        response = requests.get(current, headers=headers, timeout=timeout,
                                allow_redirects=False, stream=True)
        try:
            location = response.headers.get("Location")
            if response.status_code in REDIRECT_CODES and location:
                if hop == max_redirects:
                    raise _TooManyRedirects()
                current = urljoin(current, location[:2048])
                redirects.append(current)
                continue
            body, truncated = b"", False
            if read_body and "html" in response.headers.get("Content-Type", "").lower():
                body, truncated = _read_limited(response, cfg["MAX_RESPONSE_BYTES"], deadline)
            return {"status": response.status_code, "url": current,
                    "headers": response.headers, "body": body,
                    "truncated": truncated, "redirects": redirects}
        finally:
            response.close()


def _extract(body):
    """Pull the page title and meta description from (possibly cut-off) HTML."""
    title = description = None
    if body:
        soup = BeautifulSoup(body, "html.parser")  # parsing only; nothing is executed
        if soup.title and soup.title.string:
            title = " ".join(soup.title.string.split())[:200]
        tag = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        if tag and tag.get("content"):
            description = " ".join(tag["content"].split())[:400]
    return title, description


def _check_robots(page_url, cfg):
    """Is robots.txt publicly reachable? We never read or follow its contents."""
    parts = urlsplit(page_url)
    robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
    info = {"url": robots_url, "reachable": None, "http_status": None, "note": ""}
    try:
        result = _fetch(robots_url, cfg, 0, read_body=False)
        info["http_status"] = result["status"]
        info["reachable"] = result["status"] == 200
    except _TooManyRedirects:
        info["reachable"], info["note"] = False, "robots.txt redirects elsewhere (not followed)."
    except (UnsafeTargetError, ResolutionError):
        info["note"] = "Check skipped (target not allowed or not resolvable)."
    except (requests.exceptions.RequestException, UnicodeError):
        info["note"] = "Check failed (network error)."
    return info


def collect(domain, cfg):
    """Collect basic public metadata from the website of ``domain``."""
    page, last_error = None, "no response"
    for scheme in ("https", "http"):  # try HTTPS first, one HTTP fallback
        start_url = f"{scheme}://{domain}/"
        try:
            page = _fetch(start_url, cfg, cfg["MAX_REDIRECTS"], read_body=True)
            break
        except UnsafeTargetError as exc:
            return make_result(SOURCE, start_url, "blocked", f"No request was made: {exc}")
        except ResolutionError as exc:
            return make_result(SOURCE, start_url, "unavailable", str(exc))
        except _TooManyRedirects:
            return make_result(SOURCE, start_url, "unavailable",
                               f"Stopped: more than {cfg['MAX_REDIRECTS']} redirects.")
        except (requests.exceptions.RequestException, UnicodeError) as exc:
            last_error = type(exc).__name__
    if page is None:
        return make_result(SOURCE, f"https://{domain}/", "unavailable",
                           f"Could not connect over HTTPS or HTTP ({last_error}).")

    title, description = _extract(page["body"])
    public_headers = {}
    for name in ALLOWED_HEADERS:
        value = page["headers"].get(name)
        if value:
            public_headers[name] = value[:200]
    data = {
        "scheme_used": urlsplit(page["url"]).scheme,
        "http_status": page["status"],
        "final_url": page["url"][:500],
        "redirects": [u[:500] for u in page["redirects"]],
        "content_type": page["headers"].get("Content-Type", "")[:200],
        "title": title,
        "meta_description": description,
        "headers": public_headers,
        "body_truncated": page["truncated"],
        "robots": _check_robots(page["url"], cfg),
    }
    message = "Basic metadata collection only - this is not a security scan."
    if page["status"] >= 400:
        message += " The server answered with an error status, so metadata may be limited."
    return make_result(SOURCE, page["url"][:500], "available", message, data)