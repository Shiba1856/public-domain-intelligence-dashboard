"""Certificate Transparency collector using crt.sh (issuance history only)."""
import json
from datetime import datetime, timezone
from urllib.parse import quote

import requests

from . import ResponseTooLargeError, fetch_limited, make_result

CRT_URL = "https://crt.sh/"
SOURCE = "crt.sh - public Certificate Transparency log search"


def collect(domain, cfg):
    """Return recent certificate entries that name exactly ``domain``.

    We search for the exact domain only. Wildcard searches (%.domain) would
    enumerate subdomains, which is outside this project's scope.
    """
    search_url = f"https://crt.sh/?q={quote(domain, safe='')}"
    try:
        code, _final, body = fetch_limited(
            CRT_URL, cfg, cfg["CT_MAX_RESPONSE_BYTES"],
            params={"q": domain, "output": "json"}, timeout=cfg["CT_TIMEOUT"])
    except ResponseTooLargeError:
        return make_result(SOURCE, search_url, "unavailable",
                           "This domain has too many certificate records for this tool's "
                           "size limit. Use the crt.sh link to browse them directly.")
    except requests.exceptions.Timeout:
        return make_result(SOURCE, search_url, "unavailable",
                           "crt.sh timed out (it is often slow under load). Try again later.")
    except requests.exceptions.RequestException:
        return make_result(SOURCE, search_url, "unavailable", "crt.sh could not be reached.")

    if code == 429:
        return make_result(SOURCE, search_url, "rate_limited",
                           "crt.sh is rate limiting requests. Try again later.")
    if code != 200:
        return make_result(SOURCE, search_url, "unavailable",
                           f"crt.sh answered with HTTP {code}.")
    try:
        rows = json.loads(body)
        if not isinstance(rows, list):
            raise ValueError("unexpected JSON shape")
    except ValueError:
        return make_result(SOURCE, search_url, "unavailable",
                           "crt.sh returned a malformed response.")
    if not rows:
        return make_result(SOURCE, search_url, "not_found",
                           "No certificate entries were found for this exact domain name.")

    unique = {}
    for row in rows:
        if isinstance(row, dict) and row.get("id") is not None:
            unique[row["id"]] = row  # the same certificate can appear twice
    ordered = sorted(unique.values(), key=lambda r: str(r.get("not_before") or ""), reverse=True)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entries = []
    for row in ordered[: cfg["CT_MAX_ENTRIES"]]:
        try:
            cert_id = int(row["id"])
        except (TypeError, ValueError):
            continue
        names = [n.strip()[:120] for n in str(row.get("name_value", "")).splitlines() if n.strip()]
        not_after = str(row.get("not_after") or "")[:10]
        entries.append({
            "id": cert_id,
            "link": f"https://crt.sh/?id={cert_id}",
            "names": names[:6],
            "names_total": len(names),
            "issuer": str(row.get("issuer_name") or "")[:120],
            "not_before": str(row.get("not_before") or "")[:10],
            "not_after": not_after,
            "expired": bool(not_after) and not_after < today,
        })
    data = {"total": len(unique), "shown": len(entries), "entries": entries,
            "disclaimer": "Certificate issuance history only. It is not proof of current "
                          "ownership or of a currently running service."}
    return make_result(SOURCE, search_url, "available", "", data)