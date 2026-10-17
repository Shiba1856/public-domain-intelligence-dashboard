"""DNS collector: A, AAAA, MX, NS, TXT and CNAME records via dnspython."""
import time

import dns.exception
import dns.resolver

from . import make_result, utc_now

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
MAX_RECORDS_PER_TYPE = 20
MAX_TEXT_LENGTH = 300


def _format_record(rtype, rdata):
    """Turn a dnspython record into {'value', 'detail'} for display."""
    if rtype == "MX":
        return {"value": str(rdata.exchange).rstrip("."),
                "detail": f"priority {rdata.preference}"}
    if rtype == "TXT":
        text = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if len(text) > MAX_TEXT_LENGTH:
            text = text[:MAX_TEXT_LENGTH] + "..."
        return {"value": text, "detail": ""}
    return {"value": str(rdata).rstrip("."), "detail": ""}


def _lookup_one(resolver, domain, rtype):
    """Query one record type. 'No records' and 'lookup failed' are kept apart."""
    entry = {"type": rtype, "status": "available", "message": "",
             "records": [], "query_ms": None, "retrieved_at": utc_now()}
    started = time.monotonic()
    try:
        answer = resolver.resolve(domain, rtype, raise_on_no_answer=True)
        rdatas = list(answer)
        entry["records"] = [_format_record(rtype, r) for r in rdatas[:MAX_RECORDS_PER_TYPE]]
        if len(rdatas) > MAX_RECORDS_PER_TYPE:
            entry["message"] = f"Showing the first {MAX_RECORDS_PER_TYPE} of {len(rdatas)} records."
    except dns.resolver.NXDOMAIN:
        entry["status"], entry["message"] = "not_found", "No records found (the domain does not exist - NXDOMAIN)."
    except dns.resolver.NoAnswer:
        entry["status"], entry["message"] = "not_found", "No records found."
    except dns.resolver.NoNameservers:
        entry["status"], entry["message"] = "unavailable", "Lookup failed: no name server could answer."
    except dns.exception.Timeout:
        entry["status"], entry["message"] = "unavailable", "Lookup failed: the query timed out."
    except dns.exception.DNSException as exc:
        entry["status"], entry["message"] = "unavailable", f"Lookup failed ({type(exc).__name__})."
    entry["query_ms"] = round((time.monotonic() - started) * 1000)
    return entry


def collect(domain, cfg):
    """Look up all record types and return a standard result dict."""
    try:
        resolver = dns.resolver.Resolver()  # uses this computer's DNS settings
    except dns.exception.DNSException:
        return make_result("DNS (dnspython)", None, "unavailable",
                           "No DNS resolver is configured on this computer.")
    resolver.timeout = cfg["DNS_TIMEOUT"]
    resolver.lifetime = cfg["DNS_TIMEOUT"]

    entries = [_lookup_one(resolver, domain, t) for t in RECORD_TYPES]

    statuses = {e["status"] for e in entries}
    if "available" in statuses:
        status = "available"
    elif "unavailable" in statuses:
        status = "unavailable"
    else:
        status = "not_found"
    message = ""
    if status == "available" and "unavailable" in statuses:
        message = "Some record types could not be looked up - see each section below."

    data = {"resolvers": list(resolver.nameservers), "types": entries}
    source = "DNS queries sent through this computer's configured resolver (dnspython)"
    return make_result(source, None, status, message, data)