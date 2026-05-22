from datetime import date, datetime
from typing import Any

from app.models import Assessment, Asset, AuditLog, Client, Contact, Finding, ScopeRecord, Site


def iso(value: datetime | date | None) -> str | None:
    return value.isoformat() if value else None


def client_to_dict(client: Client) -> dict[str, Any]:
    return {
        "id": client.id,
        "name": client.name,
        "legal_name": client.legal_name,
        "domain": client.domain,
        "status": client.status,
        "created_at": iso(client.created_at),
        "updated_at": iso(client.updated_at),
    }


def site_to_dict(site: Site) -> dict[str, Any]:
    return {
        "id": site.id,
        "client_id": site.client_id,
        "name": site.name,
        "address": site.address,
        "notes": site.notes,
        "created_at": iso(site.created_at),
    }


def contact_to_dict(contact: Contact) -> dict[str, Any]:
    return {
        "id": contact.id,
        "client_id": contact.client_id,
        "name": contact.name,
        "email": contact.email,
        "phone": contact.phone,
        "role": contact.role,
        "created_at": iso(contact.created_at),
    }


def assessment_to_dict(assessment: Assessment) -> dict[str, Any]:
    return {
        "id": assessment.id,
        "client_id": assessment.client_id,
        "client_name": assessment.client.name if assessment.client else None,
        "name": assessment.name,
        "purpose": assessment.purpose,
        "status": assessment.status,
        "created_at": iso(assessment.created_at),
        "updated_at": iso(assessment.updated_at),
    }


def scope_to_dict(scope: ScopeRecord) -> dict[str, Any]:
    return {
        "id": scope.id,
        "assessment_id": scope.assessment_id,
        "client_name": scope.client_name,
        "authorized_cidrs": scope.authorized_cidrs,
        "authorized_domains": scope.authorized_domains,
        "start_time": iso(scope.start_time),
        "requested_by": scope.requested_by,
        "operator_notes": scope.operator_notes,
        "public_scope_allowed": scope.public_scope_allowed,
        "created_at": iso(scope.created_at),
    }


def asset_to_dict(asset: Asset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "client_id": asset.client_id,
        "client_name": asset.client.name if asset.client else None,
        "site_id": asset.site_id,
        "site_name": asset.site.name if asset.site else None,
        "assessment_id": asset.assessment_id,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "mac_address": asset.mac_address,
        "os_family": asset.os_family,
        "os_version": asset.os_version,
        "last_seen": iso(asset.last_seen),
        "source": asset.source,
        "tags": asset.tags or [],
        "criticality": asset.criticality,
        "owner": asset.owner,
        "metadata": asset.metadata_json or {},
        "created_at": iso(asset.created_at),
        "updated_at": iso(asset.updated_at),
    }


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "assessment_id": finding.assessment_id,
        "client_id": finding.client_id,
        "client_name": finding.client.name if finding.client else None,
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category,
        "description": finding.description,
        "evidence": finding.evidence,
        "impact": finding.impact,
        "recommended_remediation": finding.recommended_remediation,
        "status": finding.status,
        "first_seen": iso(finding.first_seen),
        "last_seen": iso(finding.last_seen),
        "source": finding.source,
        "confidence_score": finding.confidence_score,
        "affected_assets": [asset_to_dict(asset) for asset in finding.assets],
        "metadata": finding.metadata_json or {},
    }


def audit_to_dict(audit: AuditLog) -> dict[str, Any]:
    return {
        "id": audit.id,
        "actor_user_id": audit.actor_user_id,
        "action": audit.action,
        "entity_type": audit.entity_type,
        "entity_id": audit.entity_id,
        "client_id": audit.client_id,
        "assessment_id": audit.assessment_id,
        "details": audit.details,
        "request_ip": audit.request_ip,
        "created_at": iso(audit.created_at),
    }
