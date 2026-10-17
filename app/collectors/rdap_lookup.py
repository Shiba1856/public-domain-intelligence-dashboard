"""RDAP collector: public domain registration data (no registrant details)."""
import json
from datetime import datetime, timezone
from urllib.parse import quote

import requests

from . import ResponseTooLargeError, fetch_limited, make_result

# rdap.org is a public "bootstrap" service that redirects to the correct
# registry's RDAP server. Redirects here are limited by fetch_limited().
RDAP_BOOTSTRAP = "https://rdap.org/domain/"
RDAP_MAX_BYTES = 1_000_000
SOURCE = "RDAP (public registration data via the rdap.org bootstrap service)"


def _registrar_name(entities):
    """Find the registrar organisation name. Registrant entities are ignored."""
    for entity in entities or []:
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        try:
            for item in entity["vcardArray"][1]:
                if item[0] == "fn":
                    return str(item[3])[:150]
        except (KeyError, IndexError, TypeError):
            pass
    return None


def _parse(data):
    """Extract only the fields this project displays."""
    events = data.get("events") or []

    def event_date(action):
        for ev in events:
            if isinstance(ev, dict) and ev.get("eventAction") == action:
                return str(ev.get("eventDate", ""))[:10] or None
        return None

    nameservers = [str(ns["ldhName"]).lower()[:253]
                   for ns in (data.get("nameservers") or [])
                   if isinstance(ns, dict) and ns.get("ldhName")][:13]
    status = [str(s)[:60] for s in (data.get("status") or [])][:10]
    parsed = {
        "registrar": _registrar_name(data.get("entities")),
        "registered": event_date("registration"),
        "expires": event_date("expiration"),
        "last_changed": event_date("last changed"),
        "rdap_db_updated": event_date("last update of RDAP database"),
        "status": status,
        "nameservers": nameservers,
        "redacted_declared": "redacted" in data,
    }
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    parsed["expired"] = bool(parsed["expires"]) and parsed["expires"] < today
    labels = {"registrar": "registrar", "registered": "registration date",
              "expires": "expiration date", "status": "status", "nameservers": "name servers"}
    parsed["missing"] = [label for key, label in labels.items() if not parsed[key]]
    return parsed


def collect(domain, cfg):
    """Query RDAP for ``domain`` and return a standard result dict."""
    url = RDAP_BOOTSTRAP + quote(domain, safe="")
    try:
        code, final_url, body = fetch_limited(
            url, cfg, RDAP_MAX_BYTES, accept="application/rdap+json, application/json")
    except ResponseTooLargeError:
        return make_result(SOURCE, url, "unavailable",
                           "The RDAP response exceeded the safety size limit and was not read.")
    except requests.exceptions.Timeout:
        return make_result(SOURCE, url, "unavailable", "The RDAP service timed out.")
    except requests.exceptions.RequestException:
        return make_result(SOURCE, url, "unavailable", "The RDAP service could not be reached.")

    source_url = final_url if final_url.startswith("https://") else url
    if code == 404:
        return make_result(SOURCE, source_url, "not_found",
                           "No RDAP record found. The domain may be unregistered, or its "
                           "registry may not offer RDAP.")
    if code == 429:
        return make_result(SOURCE, source_url, "rate_limited",
                           "The RDAP service is rate limiting requests. Try again later.")
    if code != 200:
        return make_result(SOURCE, source_url, "unavailable",
                           f"The RDAP service answered with HTTP {code}.")
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("unexpected JSON shape")
        parsed = _parse(data)
    except (ValueError, TypeError, AttributeError, KeyError):
        return make_result(SOURCE, source_url, "unavailable",
                           "The RDAP response was malformed and could not be read.")

    notes = []
    if parsed["missing"]:
        notes.append("Incomplete record - not provided: " + ", ".join(parsed["missing"]) + ".")
    if parsed["redacted_declared"]:
        notes.append("The server declares some fields as redacted for privacy.")
    return make_result(SOURCE, source_url, "available", " ".join(notes), parsed)