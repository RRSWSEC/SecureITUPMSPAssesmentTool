import os
import subprocess
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_secure_it_up.db")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-with-at-least-thirty-two-bytes")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def auth_headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"username": "admin@example.com", "password": "ChangeMeDevOnly!123"},
    )
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_collector_import_generates_findings_and_reports() -> None:
    with TestClient(app) as client:
        headers = auth_headers(client)
        create_client = client.post(
            "/api/clients",
            json={"name": "Test Example Client", "domain": "test-client.example.com"},
            headers=headers,
        )
        assert create_client.status_code == 201, create_client.text
        client_id = create_client.json()["id"]

        create_assessment = client.post(
            f"/api/clients/{client_id}/assessments",
            json={"name": "Test import assessment", "purpose": "Onboarding"},
            headers=headers,
        )
        assert create_assessment.status_code == 201, create_assessment.text
        assessment_id = create_assessment.json()["id"]

        sample_path = ROOT / "examples" / "sample-data" / "collector-sample.json"
        with sample_path.open("rb") as sample:
            import_response = client.post(
                f"/api/imports/collector?assessment_id={assessment_id}",
                files={"upload": ("collector-sample.json", sample, "application/json")},
                headers=headers,
            )
        assert import_response.status_code == 200, import_response.text
        result = import_response.json()
        assert result["assets_imported"] == 6
        assert result["findings_touched"] > 0

        dashboard = client.get(f"/api/dashboard/assessments/{assessment_id}", headers=headers)
        assert dashboard.status_code == 200, dashboard.text
        assert dashboard.json()["asset_count"] == 6
        assert dashboard.json()["top_risks"]

        html = client.get(f"/api/reports/{assessment_id}/executive-summary.html", headers=headers)
        assert html.status_code == 200, html.text
        assert "Executive Summary" in html.text
        assert "compliance certification" in html.text

        pdf = client.get(f"/api/reports/{assessment_id}/asset-inventory.pdf", headers=headers)
        assert pdf.status_code == 200, pdf.text
        assert pdf.content.startswith(b"%PDF")


def test_collector_dry_run_and_public_scope_guard() -> None:
    collector = ROOT / "collector" / "secure_it_up_collector.py"
    dry_run = subprocess.run(
        [
            sys.executable,
            str(collector),
            "--authorized",
            "--scope",
            "192.168.44.0/24",
            "--tcp-scan",
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert dry_run.returncode == 0
    assert "Dry run" in dry_run.stdout

    public_scope = subprocess.run(
        [
            sys.executable,
            str(collector),
            "--authorized",
            "--scope",
            "8.8.8.0/24",
            "--ping-sweep",
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert public_scope.returncode != 0
    assert "public scope" in public_scope.stderr.lower()
