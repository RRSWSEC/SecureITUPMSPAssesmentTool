# Secure IT UP Assessment Suite

Secure IT UP Assessment Suite is an original, local-first IT assessment platform for authorized MSP work. It helps teams document small-business assets, track common operational and security risk indicators, import safe collector evidence, run YAML rules, and generate client-ready HTML/PDF reports.

## What This Is

- A self-hostable FastAPI + React assessment workbench.
- A safe collector/import workflow for local inventory, passive neighbor data, explicit authorized CIDR checks, and file imports.
- A rule-driven findings model for inventory, patching, endpoint security, backup, network, compliance-support evidence, and operational risk.
- Original report templates for executive summary, technical findings, asset inventory, remediation planning, and backup/recovery readiness.

## What This Is Not

- Not an exploitation framework.
- Not a vulnerability scanner that attempts compromise.
- Not a brute-force, credential collection, persistence, destructive test, or ransomware simulation tool.
- Not a compliance certification engine.

Use only on owned labs or explicitly authorized client environments.

## Quick Start

```bash
docker compose up --build
```

Open:

- Frontend: http://localhost:5173
- Backend API docs: http://localhost:8000/docs

Development seed account:

- Username: `admin@example.com`
- Password: `ChangeMeDevOnly!123`

The seed account is created only when `ENVIRONMENT` is development/test/local.

## Local Development

Backend:

```bash
cd backend
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Tests

Backend:

```bash
cd backend
pytest
```

Frontend:

```bash
cd frontend
npm install
npm test
```

## Sample Data

After login, open Settings and select `Load Sample Data`. The sample records are clearly fake, use `example.com` domains, and use RFC1918 private IP addresses.

You can also create a client and assessment, then import:

```text
examples/sample-data/collector-sample.json
```

## Collector Dry Run

Default collector mode performs local inventory only:

```bash
python collector/secure_it_up_collector.py --output collector-output.json
```

Validate an authorized network collection without scanning:

```bash
python collector/secure_it_up_collector.py --authorized --scope 192.168.44.0/24 --tcp-scan --dry-run
```

Network discovery requires `--authorized`, `--scope`, and an explicit discovery flag. Public IP scope is blocked unless `--allow-public-scope` is provided with written authorization.

## Reports

Use the Reports page to preview HTML and export PDF. PDF generation uses a local ReportLab fallback that covers the main tables; HTML previews contain the full report detail and styling.

## Repository Layout

- `backend/` FastAPI, SQLAlchemy models, auth, imports, rule engine, reports, tests.
- `frontend/` React, Vite, TypeScript, Tailwind UI.
- `collector/` Safe Python collector CLI.
- `reports/` Original Jinja report templates.
- `docs/` Architecture and operator safety documentation.
- `examples/` Fake sample collector payloads.
