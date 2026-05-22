# Architecture

```mermaid
flowchart LR
  Operator["MSP operator"] --> UI["React + Vite frontend"]
  UI --> API["FastAPI backend"]
  API --> DB[("SQLite dev / PostgreSQL")]
  API --> Rules["YAML rule engine"]
  API --> Reports["Jinja HTML + ReportLab PDF"]
  Collector["Safe Python collector"] --> JSON["Collector JSON"]
  JSON --> API
  API --> Audit["Audit log"]
```

## Data Model Overview

Core entities:

- Client, Site, Contact, Note.
- Assessment and ScopeRecord.
- Asset with ownership, platform, last-seen, criticality, tags, and metadata.
- Finding with severity, category, evidence, impact, recommended remediation, status, source, confidence, and affected assets.
- AuditLog for login, imports, assessment creation, scope changes, report export, and finding status changes.

## Collector / Import Flow

```mermaid
sequenceDiagram
  participant Operator
  participant Collector
  participant API
  participant DB
  Operator->>Collector: Run local/import or authorized scoped collection
  Collector->>Collector: Validate scope and safety flags
  Collector->>Operator: Write collector JSON
  Operator->>API: Upload collector JSON to assessment
  API->>API: Validate size and schema
  API->>DB: Create scope record and upsert assets
  API->>DB: Write audit log
```

## Rule Engine Flow

```mermaid
flowchart TD
  Import["Collector import"] --> Assets["Assessment assets"]
  Assets --> Rules["Load YAML rules"]
  Rules --> Match["Evaluate match conditions"]
  Match --> Findings["Create/update findings"]
  Findings --> Dashboard["Risk dashboard and reports"]
```

Rules live in `backend/app/rules/starter_rules.yml`. New rules can be added without changing Python code when they use supported operators such as `equals`, `contains`, `contains_any`, `in`, `not_in`, `missing`, `older_than_days`, `gte`, and `lt`.

## Report Generation Flow

```mermaid
flowchart LR
  Assessment["Assessment data"] --> Context["Report context"]
  Context --> HTML["Jinja HTML templates"]
  Context --> PDF["ReportLab PDF fallback"]
  HTML --> Preview["Frontend preview"]
  PDF --> Export["PDF export"]
  Preview --> Audit["Report export audit"]
  Export --> Audit
```
