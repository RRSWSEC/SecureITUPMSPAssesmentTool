from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

import jwt
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import create_access_token, decode_access_token, verify_password
from app.models import (
    Assessment,
    Asset,
    AuditLog,
    Client,
    Contact,
    Finding,
    Note,
    ScopeRecord,
    Site,
    User,
)
from app.schemas.api import (
    AssessmentCreate,
    ClientCreate,
    ContactCreate,
    FindingStatusUpdate,
    LoginRequest,
    NoteCreate,
    ScopeCreate,
    SiteCreate,
)
from app.services.audit import write_audit
from app.services.importer import (
    ImportErrorDetail,
    import_collector_payload,
    naive_utc,
    parse_collector_payload,
    validate_scope_record,
)
from app.services.reports import REPORT_TYPES, render_report_html, render_report_pdf
from app.services.rules import SEVERITY_ORDER
from app.services.sample_data import load_sample_data
from app.services.serializers import (
    assessment_to_dict,
    asset_to_dict,
    audit_to_dict,
    client_to_dict,
    contact_to_dict,
    finding_to_dict,
    scope_to_dict,
    site_to_dict,
)

router = APIRouter(prefix="/api")
bearer = HTTPBearer(auto_error=False)


def request_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from exc
    user_id = payload.get("sub")
    user = db.get(User, int(user_id)) if user_id else None
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    return user


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "secure-it-up-assessment-suite"}


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not verify_password(payload.password, user.password_hash):
        write_audit(
            db,
            action="login_failed",
            details={"username": payload.username},
            request_ip=request_ip(request),
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(str(user.id), {"role": user.role})
    write_audit(db, action="login", user=user, request_ip=request_ip(request))
    db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "username": user.username, "role": user.role},
    }


@router.get("/auth/me")
def me(user: User = Depends(get_current_user)) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role}


@router.get("/clients")
def list_clients(
    search: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    query = select(Client).order_by(Client.name)
    if search:
        query = query.where(Client.name.ilike(f"%{search}%"))
    return [client_to_dict(client) for client in db.scalars(query)]


@router.post("/clients", status_code=201)
def create_client(
    payload: ClientCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    client = Client(**payload.model_dump())
    db.add(client)
    db.flush()
    write_audit(
        db,
        action="client_created",
        user=user,
        entity_type="client",
        entity_id=client.id,
        client_id=client.id,
        request_ip=request_ip(request),
    )
    db.commit()
    db.refresh(client)
    return client_to_dict(client)


@router.get("/clients/{client_id}")
def get_client(
    client_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    client = db.scalar(
        select(Client)
        .where(Client.id == client_id)
        .options(
            selectinload(Client.sites),
            selectinload(Client.contacts),
            selectinload(Client.assessments),
        )
    )
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found")
    data = client_to_dict(client)
    data["sites"] = [site_to_dict(site) for site in client.sites]
    data["contacts"] = [contact_to_dict(contact) for contact in client.contacts]
    data["assessments"] = [assessment_to_dict(assessment) for assessment in client.assessments]
    return data


@router.post("/clients/{client_id}/sites", status_code=201)
def create_site(
    client_id: int,
    payload: SiteCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    if db.get(Client, client_id) is None:
        raise HTTPException(status_code=404, detail="Client not found")
    site = Site(client_id=client_id, **payload.model_dump())
    db.add(site)
    db.flush()
    write_audit(
        db,
        action="site_created",
        user=user,
        entity_type="site",
        entity_id=site.id,
        client_id=client_id,
        request_ip=request_ip(request),
    )
    db.commit()
    db.refresh(site)
    return site_to_dict(site)


@router.post("/clients/{client_id}/contacts", status_code=201)
def create_contact(
    client_id: int,
    payload: ContactCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    if db.get(Client, client_id) is None:
        raise HTTPException(status_code=404, detail="Client not found")
    contact = Contact(client_id=client_id, **payload.model_dump())
    db.add(contact)
    db.flush()
    write_audit(
        db,
        action="contact_created",
        user=user,
        entity_type="contact",
        entity_id=contact.id,
        client_id=client_id,
        request_ip=request_ip(request),
    )
    db.commit()
    db.refresh(contact)
    return contact_to_dict(contact)


@router.post("/clients/{client_id}/notes", status_code=201)
def create_note(
    client_id: int,
    payload: NoteCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    if db.get(Client, client_id) is None:
        raise HTTPException(status_code=404, detail="Client not found")
    note = Note(client_id=client_id, author=user.username, body=payload.body)
    db.add(note)
    db.flush()
    write_audit(
        db,
        action="note_created",
        user=user,
        entity_type="note",
        entity_id=note.id,
        client_id=client_id,
        request_ip=request_ip(request),
    )
    db.commit()
    return {"id": note.id, "body": note.body, "author": note.author, "created_at": note.created_at}


@router.get("/assessments")
def list_assessments(
    client_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    query = (
        select(Assessment)
        .options(selectinload(Assessment.client))
        .order_by(Assessment.created_at.desc())
    )
    if client_id:
        query = query.where(Assessment.client_id == client_id)
    return [assessment_to_dict(assessment) for assessment in db.scalars(query)]


@router.post("/clients/{client_id}/assessments", status_code=201)
def create_assessment(
    client_id: int,
    payload: AssessmentCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    if db.get(Client, client_id) is None:
        raise HTTPException(status_code=404, detail="Client not found")
    assessment = Assessment(client_id=client_id, **payload.model_dump())
    db.add(assessment)
    db.flush()
    write_audit(
        db,
        action="assessment_created",
        user=user,
        entity_type="assessment",
        entity_id=assessment.id,
        client_id=client_id,
        assessment_id=assessment.id,
        request_ip=request_ip(request),
    )
    db.commit()
    db.refresh(assessment)
    return assessment_to_dict(assessment)


@router.post("/assessments/{assessment_id}/scope", status_code=201)
def create_scope(
    assessment_id: int,
    payload: ScopeCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    assessment = db.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    try:
        validate_scope_record(payload)
    except ImportErrorDetail as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scope = ScopeRecord(
        assessment_id=assessment_id,
        client_name=payload.client_name,
        authorized_cidrs=payload.authorized_cidrs,
        authorized_domains=payload.authorized_domains,
        start_time=naive_utc(payload.start_time) or datetime.now(UTC).replace(tzinfo=None),
        requested_by=payload.requested_by,
        operator_notes=payload.operator_notes,
        public_scope_allowed=payload.public_scope_allowed,
    )
    db.add(scope)
    db.flush()
    write_audit(
        db,
        action="scope_created",
        user=user,
        entity_type="scope_record",
        entity_id=scope.id,
        client_id=assessment.client_id,
        assessment_id=assessment_id,
        request_ip=request_ip(request),
    )
    db.commit()
    db.refresh(scope)
    return scope_to_dict(scope)


@router.get("/assets")
def list_assets(
    client_id: int | None = None,
    assessment_id: int | None = None,
    search: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    query = (
        select(Asset)
        .options(selectinload(Asset.client), selectinload(Asset.site))
        .order_by(Asset.hostname)
    )
    if client_id:
        query = query.where(Asset.client_id == client_id)
    if assessment_id:
        query = query.where(Asset.assessment_id == assessment_id)
    if search:
        query = query.where(
            or_(
                Asset.hostname.ilike(f"%{search}%"),
                Asset.ip_address.ilike(f"%{search}%"),
                Asset.os_family.ilike(f"%{search}%"),
            )
        )
    return [asset_to_dict(asset) for asset in db.scalars(query)]


@router.get("/findings")
def list_findings(
    client_id: int | None = None,
    assessment_id: int | None = None,
    severity: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    category: str | None = None,
    search: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    query = (
        select(Finding)
        .options(selectinload(Finding.assets), selectinload(Finding.client))
        .order_by(Finding.last_seen.desc())
    )
    if client_id:
        query = query.where(Finding.client_id == client_id)
    if assessment_id:
        query = query.where(Finding.assessment_id == assessment_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status_filter:
        query = query.where(Finding.status == status_filter)
    if category:
        query = query.where(Finding.category == category)
    if search:
        query = query.where(Finding.title.ilike(f"%{search}%"))
    return [finding_to_dict(finding) for finding in db.scalars(query)]


@router.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = payload.status
    finding.last_seen = datetime.now(UTC).replace(tzinfo=None)
    write_audit(
        db,
        action="finding_status_changed",
        user=user,
        entity_type="finding",
        entity_id=finding.id,
        client_id=finding.client_id,
        assessment_id=finding.assessment_id,
        details={"status": payload.status},
        request_ip=request_ip(request),
    )
    db.commit()
    db.refresh(finding)
    return finding_to_dict(finding)


@router.post("/imports/collector")
async def import_collector(
    assessment_id: int,
    request: Request,
    upload: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    settings = get_settings()
    assessment = db.scalar(
        select(Assessment)
        .where(Assessment.id == assessment_id)
        .options(selectinload(Assessment.client))
    )
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    raw = await upload.read(settings.upload_max_bytes + 1)
    if len(raw) > settings.upload_max_bytes:
        raise HTTPException(status_code=413, detail="Collector upload exceeds size limit")
    try:
        payload = parse_collector_payload(raw)
        result = import_collector_payload(db, assessment, payload)
    except ImportErrorDetail as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    write_audit(
        db,
        action="collector_import",
        user=user,
        entity_type="assessment",
        entity_id=assessment.id,
        client_id=assessment.client_id,
        assessment_id=assessment.id,
        details={"filename": upload.filename, **result},
        request_ip=request_ip(request),
    )
    db.commit()
    return result


@router.get("/dashboard/assessments/{assessment_id}")
def assessment_dashboard(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    assessment = db.scalar(
        select(Assessment)
        .where(Assessment.id == assessment_id)
        .options(selectinload(Assessment.client), selectinload(Assessment.scopes))
    )
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    assets = list(db.scalars(select(Asset).where(Asset.assessment_id == assessment_id)))
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .options(selectinload(Finding.assets))
        )
    )
    open_findings = [finding for finding in findings if finding.status == "Open"]
    severity_counts = Counter(finding.severity for finding in open_findings)
    endpoint_reported = [
        asset
        for asset in assets
        if (asset.metadata_json or {}).get("endpoint_security_status")
        not in {None, "", "unknown", "not_reported", "none", "missing"}
    ]
    backup_covered = [
        asset
        for asset in assets
        if str((asset.metadata_json or {}).get("backup_status", "")).lower()
        in {"covered", "healthy", "success"}
    ]
    top_risks = sorted(
        open_findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 0),
            finding.confidence_score,
            finding.last_seen,
        ),
        reverse=True,
    )[:10]
    risk_score = min(100, sum((SEVERITY_ORDER.get(f.severity, 0) + 1) * 6 for f in open_findings))
    return {
        "assessment": assessment_to_dict(assessment),
        "scope_records": [scope_to_dict(scope) for scope in assessment.scopes],
        "asset_count": len(assets),
        "risk_score": risk_score,
        "open_findings_by_severity": {
            severity: severity_counts.get(severity, 0) for severity in SEVERITY_ORDER
        },
        "top_risks": [finding_to_dict(finding) for finding in top_risks],
        "endpoint_coverage_summary": {
            "reported": len(endpoint_reported),
            "total": len(assets),
            "percent": round((len(endpoint_reported) / len(assets)) * 100, 1) if assets else 0,
        },
        "backup_coverage_summary": {
            "covered": len(backup_covered),
            "total": len(assets),
            "percent": round((len(backup_covered) / len(assets)) * 100, 1) if assets else 0,
        },
        "patch_compliance_summary": {
            "status": "placeholder",
            "message": "Patch compliance evidence can be added through collector imports or future integrations.",
        },
    }


@router.get("/reports")
def list_report_types(user: User = Depends(get_current_user)) -> dict[str, str]:
    return REPORT_TYPES


@router.get("/reports/{assessment_id}/{report_type}.html", response_class=HTMLResponse)
def report_html(
    assessment_id: int,
    report_type: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    assessment = db.scalar(
        select(Assessment)
        .where(Assessment.id == assessment_id)
        .options(selectinload(Assessment.client))
    )
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    try:
        html = render_report_html(db, assessment, report_type)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    write_audit(
        db,
        action="report_export",
        user=user,
        entity_type="report",
        entity_id=report_type,
        client_id=assessment.client_id,
        assessment_id=assessment.id,
        details={"format": "html"},
        request_ip=request_ip(request),
    )
    db.commit()
    return HTMLResponse(html)


@router.get("/reports/{assessment_id}/{report_type}.pdf")
def report_pdf(
    assessment_id: int,
    report_type: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    assessment = db.scalar(
        select(Assessment)
        .where(Assessment.id == assessment_id)
        .options(selectinload(Assessment.client))
    )
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    try:
        pdf = render_report_pdf(db, assessment, report_type)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    write_audit(
        db,
        action="report_export",
        user=user,
        entity_type="report",
        entity_id=report_type,
        client_id=assessment.client_id,
        assessment_id=assessment.id,
        details={"format": "pdf"},
        request_ip=request_ip(request),
    )
    db.commit()
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{report_type}-{assessment_id}.pdf"'},
    )


@router.get("/audit-logs")
def audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    logs = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit))
    return [audit_to_dict(log) for log in logs]


@router.post("/sample-data/load")
def load_sample(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    if not get_settings().is_development:
        raise HTTPException(
            status_code=403, detail="Sample data loader is only enabled in development."
        )
    result = load_sample_data(db)
    write_audit(
        db,
        action="sample_data_loaded",
        user=user,
        details=result,
        request_ip=request_ip(request),
    )
    db.commit()
    return result
