"""Web routes: form, investigation, history, PDF download."""
import hmac
import secrets
import threading
import time
from pathlib import Path

from flask import (Blueprint, abort, current_app, redirect, render_template,
                   request, send_file, session, url_for)

from . import database, reporting
from .collectors import (STATUS_LABELS, certificate_transparency, dns_lookup,
                         make_result, rdap_lookup, utc_now, website_metadata)
from .validation import ValidationError, normalize_domain

bp = Blueprint("main", __name__)

# --- simple global cooldown so we do not hammer the public data sources -----
_lock = threading.Lock()
_last_run = -1e9


def _cooldown_remaining():
    """Return 0 and start the cooldown, or the seconds the user must wait."""
    global _last_run
    with _lock:
        wait = current_app.config["COOLDOWN_SECONDS"] - (time.monotonic() - _last_run)
        if wait > 0:
            return int(wait) + 1
        _last_run = time.monotonic()
        return 0


# --- CSRF protection for POST forms ----------------------------------------
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def _csrf_ok():
    sent = request.form.get("csrf_token", "")
    return hmac.compare_digest(sent, session.get("csrf_token", ""))


@bp.app_context_processor
def inject_helpers():
    return {"csrf_token": get_csrf_token}


@bp.app_template_filter("status_label")
def status_label(status):
    return STATUS_LABELS.get(status, "Unavailable")


@bp.app_template_filter("badge_class")
def badge_class(status):
    return status if status in STATUS_LABELS else "unavailable"


# --- investigation logic -----------------------------------------------------
def _safe_collect(module, name, domain):
    """Run one collector; a failure in one source never breaks the others."""
    try:
        return module.collect(domain, current_app.config)
    except Exception:  # deliberate catch-all; details go to the terminal log only
        current_app.logger.exception("Collector failed: %s", name)
        return make_result(name, None, "unavailable",
                           "An unexpected error occurred while collecting this data.")


def run_investigation(domain):
    return {
        "domain": domain,
        "checked_at": utc_now(),
        "dns": _safe_collect(dns_lookup, "DNS", domain),
        "rdap": _safe_collect(rdap_lookup, "RDAP", domain),
        "ct": _safe_collect(certificate_transparency, "Certificate Transparency", domain),
        "website": _safe_collect(website_metadata, "Website metadata", domain),
    }


def build_summary(results):
    """Short, factual one-liners for the summary cards (no conclusions)."""
    sections = []

    dns = results["dns"]
    types = dns["data"].get("types", [])
    total = sum(len(t["records"]) for t in types)
    with_records = sum(1 for t in types if t["records"])
    text = (f"{total} record(s) across {with_records} of {len(types)} record types."
            if dns["status"] == "available" else dns["message"] or "No DNS information.")
    sections.append({"name": "DNS", "status": dns["status"], "text": text})

    rdap = results["rdap"]
    d = rdap["data"]
    text = (f"Registrar: {d.get('registrar') or 'not provided'}. "
            f"Expires: {d.get('expires') or 'not provided'}."
            if rdap["status"] == "available" else rdap["message"])
    sections.append({"name": "RDAP", "status": rdap["status"], "text": text})

    ct = results["ct"]
    d = ct["data"]
    text = (f"{d.get('total', 0)} certificate record(s) found; showing {d.get('shown', 0)} most recent."
            if ct["status"] == "available" else ct["message"])
    sections.append({"name": "Certificates", "status": ct["status"], "text": text})

    web = results["website"]
    d = web["data"]
    text = (f"HTTP {d.get('http_status')} - {d.get('title') or 'no page title found'}"
            if web["status"] == "available" else web["message"])
    sections.append({"name": "Website", "status": web["status"], "text": text})
    return {"sections": sections}


# --- routes ------------------------------------------------------------------
def _render_index(error=None, domain_value="", code=200):
    return render_template("index.html", recent=database.list_recent(),
                           error=error, domain_value=domain_value), code


@bp.route("/")
def index():
    return _render_index()


@bp.route("/investigate", methods=["POST"])
def investigate():
    if not _csrf_ok():
        abort(400)
    raw = request.form.get("domain", "")
    try:
        domain = normalize_domain(raw)
    except ValidationError as exc:
        return _render_index(error=str(exc), domain_value=raw[:100], code=400)
    wait = _cooldown_remaining()
    if wait > 0:
        return _render_index(
            error=f"Please wait {wait} second(s) before the next investigation "
                  "(this protects the public data sources).",
            domain_value=domain, code=429)
    results = run_investigation(domain)
    inv_id = database.save_investigation(domain, build_summary(results), results)
    return redirect(url_for("main.show_investigation", inv_id=inv_id))


@bp.route("/investigation/<int:inv_id>")
def show_investigation(inv_id):
    record = database.get_investigation(inv_id)
    if record is None:
        abort(404)
    return render_template("result.html", record=record)


@bp.route("/investigation/<int:inv_id>/report.pdf")
def download_report(inv_id):
    record = database.get_investigation(inv_id)
    if record is None:
        abort(404)
    path = Path(current_app.config["REPORTS_DIR"]) / f"report_{inv_id}.pdf"
    path.write_bytes(reporting.build_pdf(record))
    # record["domain"] is validated (a-z, 0-9, '-', '.'), so the name is safe.
    return send_file(path, mimetype="application/pdf", as_attachment=True,
                     download_name=f"domain_report_{record['domain']}_{inv_id}.pdf")


@bp.route("/history/clear", methods=["POST"])
def clear_history():
    if not _csrf_ok():
        abort(400)
    if request.form.get("confirm") != "yes":
        return _render_index(error="Please tick the confirmation box to clear history.", code=400)
    database.clear_history()
    for pdf in Path(current_app.config["REPORTS_DIR"]).glob("report_*.pdf"):
        pdf.unlink(missing_ok=True)
    return redirect(url_for("main.index"))


# --- friendly error pages (never show stack traces) ----------------------------
ERROR_MESSAGES = {
    400: "The request could not be processed. The form may have expired - go back and try again.",
    404: "That page or investigation does not exist.",
    405: "That action is not allowed here.",
    413: "The submitted data was too large.",
    500: "Something went wrong. No technical details are shown here; please try again.",
}


def _error_page(error):
    code = getattr(error, "code", 500) or 500
    message = ERROR_MESSAGES.get(code, ERROR_MESSAGES[500])
    return render_template("error.html", code=code, message=message), code


for _code in ERROR_MESSAGES:
    bp.app_errorhandler(_code)(_error_page)