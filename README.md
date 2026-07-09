# CVEHawk

Takes an Nmap scan (XML output) and tells you which of the services it found have known CVEs, pulled live from the NVD.

I built this after doing a bunch of manual "run nmap, then go look up every version number by hand on NVD" during coursework — wanted something that does that lookup automatically and puts it in one place.

## What it does

1. Upload an Nmap XML scan (`nmap -sV -oX scan.xml <target>`)
2. It parses out every open port/service/version Nmap found
3. For each service, it builds a CPE identifier and queries the NVD API for matching CVEs
4. Results show up in a dashboard: CVE ID, CVSS score, severity, and a confidence rating
5. You can filter by severity and export the findings as a Markdown report

## Confidence rating

Nmap sometimes reports a CPE directly (when its version detection is confident) — I treat those as `exact` matches. When it doesn't, I build a best-guess CPE from the raw product/version text instead, and mark those as `generic`. Generic matches are less reliable since they're not backed by NVD's own CPE dictionary, so I show that distinction rather than presenting every match as equally trustworthy.

## Stack

- FastAPI (backend + routes)
- PostgreSQL + SQLAlchemy (storage)
- Alembic (migrations)
- Jinja2 (dashboard templates, no frontend framework)
- NVD REST API for CVE data

## Running it locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Set up Postgres and copy `.env.example` to `.env` with your DB URL and an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key).

```bash
alembic upgrade head
uvicorn app.main:app --reload
```

Then go to `http://127.0.0.1:8000` and upload an Nmap XML file.

## Scope / what this isn't

- v1 only matches on service/version CVEs — no OS-level CVE matching
- No live scanning — you have to run Nmap yourself and upload the output
- Single-user, no auth
- The CPE-guessing logic for services without a Nmap-reported CPE is genuinely rough — it's a known limitation of matching without a proper vendor/product name dictionary, not something I'm pretending is more accurate than it is

## Example

Tested against `scanme.nmap.org` (Nmap's own public test target) — found real CVEs on the OpenSSH and Apache services it exposes, including a CVSS 9.8 critical.
