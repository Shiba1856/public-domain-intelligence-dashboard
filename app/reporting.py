"""PDF report generation with ReportLab."""
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .collectors import STATUS_LABELS

_styles = getSampleStyleSheet()
BODY = ParagraphStyle("Body", parent=_styles["BodyText"], fontSize=9, leading=12)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=8, leading=10)
HEAD = ParagraphStyle("Head", parent=SMALL, fontName="Helvetica-Bold")

LIMITATIONS = [
    "Findings come from public sources and may be incomplete, outdated or unavailable.",
    "DNS, registration and certificate records are NOT proof of ownership, identity, malicious intent or vulnerability.",
    "Shared IP addresses, name servers or hosting do not mean two systems have the same owner.",
    "Certificate Transparency shows issuance history, not current ownership or a running service.",
    "Website metadata is a single basic request. This report is not a security scan or vulnerability assessment.",
    "Use only for education and defensive research, within each data source's terms and the law.",
]


def _clean(text):
    """Built-in PDF fonts only support Latin-1; replace anything else with '?'."""
    text = "-" if text in (None, "") else str(text)
    return text.encode("latin-1", "replace").decode("latin-1")


def _p(text, style=SMALL):
    # escape() stops untrusted text (e.g. TXT records) being read as PDF markup.
    return Paragraph(escape(_clean(text)), style)


def _link(url, label="Source URL: "):
    if not str(url).startswith(("http://", "https://")):
        return _p(url)
    safe = escape(_clean(url), {'"': "&quot;"})
    return Paragraph(f'{escape(label)}<link href="{safe}" color="blue">{safe}</link>', SMALL)


def _table(rows, widths_mm, header=True):
    cells = []
    for i, row in enumerate(rows):
        style = HEAD if (header and i == 0) else SMALL
        cells.append([c if isinstance(c, Paragraph) else _p(c, style) for c in row])
    table = Table(cells, colWidths=[w * mm for w in widths_mm], repeatRows=1 if header else 0)
    commands = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef7")))
    table.setStyle(TableStyle(commands))
    return table


def _heading(text):
    return Paragraph(escape(text), _styles["Heading2"])


def _source_block(res):
    items = [_p(f"Source: {res.get('source', '-')}"),
             _p(f"Status: {STATUS_LABELS.get(res.get('status'), 'Unavailable')} | "
                f"Retrieved: {res.get('retrieved_at', '-')}")]
    if res.get("source_url"):
        items.append(_link(res["source_url"]))
    if res.get("message"):
        items.append(_p(f"Note: {res['message']}"))
    return items


def _dns_section(res):
    story = [_heading("2. DNS records")] + _source_block(res) + [Spacer(1, 4)]
    rows = [["Type", "Value", "Detail", "Status / query time"]]
    for entry in res["data"].get("types", []):
        label = f"{STATUS_LABELS.get(entry['status'], '')} ({entry['query_ms']} ms)"
        if entry["records"]:
            for rec in entry["records"]:
                rows.append([entry["type"], rec["value"], rec["detail"], label])
        else:
            rows.append([entry["type"], entry["message"], "", label])
    if len(rows) > 1:
        story.append(_table(rows, [16, 84, 30, 40]))
    return story


def _rdap_section(res):
    story = [_heading("3. RDAP registration information")] + _source_block(res) + [Spacer(1, 4)]
    d = res["data"]
    if res["status"] == "available":
        rows = [["Registrar", d.get("registrar")], ["Registered", d.get("registered")],
                ["Expires", (d.get("expires") or "-") + (" (already passed)" if d.get("expired") else "")],
                ["Last changed", d.get("last_changed")], ["RDAP database updated", d.get("rdap_db_updated")],
                ["Status", ", ".join(d.get("status", []))],
                ["Name servers", ", ".join(d.get("nameservers", []))]]
        story.append(_table(rows, [45, 125], header=False))
    return story


def _ct_section(res):
    story = [_heading("4. Certificate Transparency")] + _source_block(res) + [Spacer(1, 4)]
    d = res["data"]
    if res["status"] == "available":
        story.append(_p(d.get("disclaimer", "")))
        rows = [["Cert ID", "Names", "Issuer", "Valid from", "Valid to"]]
        for e in d["entries"]:
            id_cell = Paragraph(f'<link href="{e["link"]}" color="blue">{e["id"]}</link>', SMALL)
            names = ", ".join(e["names"]) + (f" (+{e['names_total'] - len(e['names'])} more)"
                                             if e["names_total"] > len(e["names"]) else "")
            valid_to = e["not_after"] + (" (expired)" if e["expired"] else "")
            rows.append([id_cell, names, e["issuer"], e["not_before"], valid_to])
        story.append(Spacer(1, 3))
        story.append(_table(rows, [20, 56, 50, 20, 24]))
        story.append(_p(f"Showing {d['shown']} of {d['total']} certificate records."))
    return story


def _website_section(res):
    story = [_heading("5. Website metadata")] + _source_block(res) + [Spacer(1, 4)]
    d = res["data"]
    if res["status"] == "available":
        robots = d.get("robots", {})
        robots_text = {True: "Reachable (HTTP 200)", False: "Not reachable"}.get(
            robots.get("reachable"), "Unknown") + (f" - {robots['note']}" if robots.get("note") else "")
        rows = [["HTTP status", d.get("http_status")], ["Final URL", d.get("final_url")],
                ["Redirects followed", len(d.get("redirects", []))], ["Page title", d.get("title")],
                ["Meta description", d.get("meta_description")], ["Content type", d.get("content_type")],
                ["robots.txt", robots_text]]
        rows += [[f"Header: {k}", v] for k, v in d.get("headers", {}).items()]
        story.append(_table(rows, [45, 125], header=False))
    return story


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(20 * mm, 10 * mm, "Public Domain Intelligence Dashboard - educational use only. "
                                         "Findings may be incomplete or outdated.")
    canvas.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(record):
    """Return the PDF bytes for one stored investigation record."""
    r = record["results"]
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            title=f"Domain report - {record['domain']}",
                            author="Public Domain Intelligence Dashboard")
    story = [Paragraph("Public Domain Intelligence Dashboard", _styles["Title"]),
             Paragraph("Investigation Report", _styles["Heading3"]),
             _table([["Investigation ID", record["id"]], ["Submitted domain", record["domain"]],
                     ["Report created", record["created_at"]], ["Last checked", r.get("checked_at")]],
                    [45, 125], header=False),
             _heading("1. Summary")]
    rows = [["Section", "Status", "Result"]]
    rows += [[s["name"], STATUS_LABELS.get(s["status"], "Unavailable"), s["text"]]
             for s in record["summary"]["sections"]]
    story.append(_table(rows, [30, 30, 110]))
    story += _dns_section(r["dns"]) + _rdap_section(r["rdap"])
    story += _ct_section(r["ct"]) + _website_section(r["website"])

    story.append(_heading("6. Sources used"))
    for key in ("dns", "rdap", "ct", "website"):
        res = r[key]
        story.append(_p(f"{res.get('source', '-')} (retrieved {res.get('retrieved_at', '-')})"))
        if res.get("source_url"):
            story.append(_link(res["source_url"]))
    story.append(_heading("7. Limitations and responsible use"))
    story += [_p("- " + item, BODY) for item in LIMITATIONS]
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()