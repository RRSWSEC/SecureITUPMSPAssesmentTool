# Contributing

Contributions should preserve the local-first, authorized-use design.

## Development Standards

- Keep collector behavior non-intrusive by default.
- Add rule content through YAML when possible.
- Avoid collecting secrets or client-sensitive data not needed for assessment evidence.
- Include tests for backend import/rule/report changes.
- Keep UI labels clear when data is sample, lab, or imported.

## Commands

Backend:

```bash
cd backend
ruff check .
black .
pytest
```

Frontend:

```bash
cd frontend
npm run lint
npm test
npm run build
```

## Pull Requests

Describe the change, the safety impact, and the tests run. Security-sensitive changes should call out scope validation, auditability, and evidence-handling effects.
