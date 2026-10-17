# Public Domain Intelligence Dashboard

A college mini project: a small Flask web app that takes **one public domain name**, gathers a
limited set of **public** technical records (DNS, RDAP, Certificate Transparency, basic website
metadata), shows them in a clean dashboard, saves a short history in SQLite, and produces a PDF report.

**For education and defensive research only. It does NOT perform vulnerability scanning.**

## Objectives
- Practise Flask, SQLite, HTTP/DNS APIs, HTML/CSS/JS and PDF generation.
- Learn how public internet records work and why they must be interpreted carefully.
- Learn secure-coding habits: input validation, SSRF protection, timeouts, size limits, CSRF tokens.

## Features
- Domain validation and normalisation (rejects URLs, paths, ports, credentials, IPs, internal names)
- DNS: A, AAAA, MX, NS, TXT, CNAME ("No records found" is shown separately from "Lookup failed")
- RDAP registration data (registrar, dates, status, name servers; privacy redaction respected)
- Certificate Transparency history from crt.sh (limited recent entries, links to crt.sh records)
- Basic website metadata: one bounded request, redirect re-validation, allow-listed headers, robots.txt reachability
- Responsive dashboard with tabs, status badges, source links, "Last checked" time, optional raw details
- SQLite history with a confirmed "Clear history" button
- PDF report with sources, limitations and responsible-use statement

## System requirements
- Python 3.9 or newer, VS Code (recommended), internet access
- Windows 10/11, macOS or Linux

## Setup - Windows (PowerShell)
```powershell
cd path\to\public_domain_dashboard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
$key = python -c "import secrets; print(secrets.token_hex(32))"
(Get-Content .env) -replace 'FLASK_SECRET_KEY=.*', "FLASK_SECRET_KEY=$key" | Set-Content .env
python -m flask --app run init-db
python run.py
```
If activation is blocked: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`.

## Setup - macOS / Linux
```bash
cd path/to/public_domain_dashboard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
# put a random value in .env:  python -c "import secrets; print(secrets.token_hex(32))"
python -m flask --app run init-db
python run.py
```

## Configuration (.env)
| Setting | Meaning |
|---|---|
| FLASK_SECRET_KEY | Long random value used to sign the session cookie / CSRF token (required) |
| USER_AGENT | Identifies this app in outgoing requests - put your own contact info |
| REQUEST_TIMEOUT / DNS_TIMEOUT / CT_TIMEOUT | Seconds before a request gives up |
| MAX_RESPONSE_BYTES / CT_MAX_RESPONSE_BYTES | Maximum bytes read from a website / crt.sh |
| MAX_REDIRECTS | Maximum redirects followed for the website request |
| CT_MAX_ENTRIES | Certificate rows displayed |
| COOLDOWN_SECONDS | Minimum gap between investigations |
| DATABASE_PATH / REPORTS_DIR | Where history and PDFs are stored |

Never commit `.env`; `.gitignore` already excludes it.

## Running
`python run.py`, then open **http://127.0.0.1:5000**. Stop with `Ctrl+C`.

## Example workflow
1. Enter `example.com`, press **Investigate** (can take up to about a minute).
2. Read the four summary cards, then open each tab.
3. Check source links and "Last checked".
4. Press **Download PDF report**; a copy is also saved in `reports/`.
5. Return to the home page to see it in **Recent investigations**.

## Data sources
| Source | Data collected |
|---|---|
| DNS (your resolver, via dnspython) | A, AAAA, MX, NS, TXT, CNAME records |
| RDAP via rdap.org -> registry server | Registrar, registration/expiry/last-changed dates, status, name servers |
| crt.sh (Certificate Transparency) | Certificate IDs, names, issuer, validity dates (exact domain only) |
| The domain's own website | HTTP status, final URL, title, meta description, content type, allow-listed headers, robots.txt reachability |

Request budget per investigation: 6 DNS queries, 1 RDAP request (plus the registry redirect),
1 crt.sh request, 1 website request (HTTPS, with one HTTP fallback) plus at most `MAX_REDIRECTS`
redirect hops and 1 robots.txt request.

## Architecture
```
Browser -> Flask routes (routes.py) -> validation.py (clean the domain)
                                    -> collectors/ (dns, rdap, ct, website) -> standard result dict
                                    -> database.py (SQLite history)
                                    -> reporting.py (ReportLab PDF)
Templates + static files render the dashboard.
```
Every collector returns `{source, source_url, retrieved_at, status, message, data}`, so the
dashboard and the PDF treat all sources the same way. One failing source never breaks the others.

## Safety and legal-use statement
Use this tool only for education and defensive research, only with legally accessible public
information, and respecting each source's terms and rate limits. It does not log in, test
passwords, scan ports, fuzz, crawl, or probe for weaknesses. It blocks localhost, private,
link-local and other non-public addresses. A DNS, registration, certificate or hosting
relationship is NOT proof of common ownership, identity or intent.

**This application does not perform vulnerability scanning.**

## Known limitations
- Public data can be missing, redacted, cached or outdated.
- crt.sh is sometimes slow or rate limited; very large domains may exceed the size limit.
- rdap.org is a third-party bootstrap service and can be unavailable; some registries lack RDAP.
- DNS rebinding: DNS is validated just before each request but not pinned to the connection.
  A production tool would connect to the validated IP address directly.
- The cooldown is per running process, not per user. History is stored unencrypted on your computer.
- Non-Latin characters in TXT records appear as "?" in the PDF (built-in fonts).
- Website results depend on how the site treats automated requests (it may answer differently or block).

## Possible future improvements
IP pinning for outbound requests, a per-user rate limiter, CSV/JSON export, caching of results,
automated tests (pytest), and a comparison view between two investigations of the same domain.

## Viva demonstration script (about 5 minutes)
1. Show the project tree and say: "Collectors gather data, routes orchestrate, SQLite stores history, ReportLab builds the PDF."
2. Try `http://example.com/path` - the validation error appears. Try `localhost` - rejected.
3. Investigate `example.com`. Walk through the summary cards.
4. DNS tab: point out "No records found" versus "Lookup failed", with query times.
5. RDAP tab: dates and status; mention privacy redaction and that registrant data is not collected.
6. Certificates tab: explain it is issuance history, not proof of ownership.
7. Website tab: status, final URL, title, safe header allow-list; mention the "not a security scan" notice.
8. Download the PDF and show the sources and limitations pages.
9. Show Recent investigations and demonstrate the confirmed "Clear history".

## Suggested viva questions
1. **Why validate the domain?** To reject URLs, paths, credentials, IPs and internal names before any request is made.
2. **What is SSRF and how is it prevented?** Tricking a server into requesting internal resources. We resolve the host, require every address to be public, restrict ports and schemes, and re-check every redirect.
3. **Why handle redirects manually?** So each hop can be re-validated; automatic redirects could lead to a private address.
4. **What is RDAP?** The modern, JSON-based successor to WHOIS for registration data.
5. **What is Certificate Transparency?** Public logs of issued TLS certificates; crt.sh makes them searchable.
6. **Why is a shared IP not proof of common ownership?** Many unrelated sites share hosting, CDNs and name servers.
7. **How are SQL injection and XSS prevented?** Parameterised SQL (`?` placeholders) and Jinja2 auto-escaping (plus a strict Content-Security-Policy).
8. **What is the CSRF token for?** It stops other websites from submitting our POST forms (e.g. "clear history") from the user's browser.
9. **Why timeouts and size limits?** To stop slow or huge responses from hanging or exhausting the app.
10. **Is this a vulnerability scanner?** No. It collects basic public records and never tests for weaknesses.
11. **What is a known weakness of your design?** DNS rebinding - validation is not pinned to the connection.