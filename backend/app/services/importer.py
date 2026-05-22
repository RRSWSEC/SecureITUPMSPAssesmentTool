from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Assessment, Asset, ScopeRecord, Site
from app.schemas.api import CollectorPayload, ScopeCreate
from app.services.rules import run_rules_for_assessment


class ImportErrorDetail(ValueError):
    pass


def public_scope_requires_flag(network: ipaddress._BaseNetwork) -> bool:
    return not (
        network.is_private or network.is_loopback or network.is_link_local or network.is_reserved
    )


def validate_scope_record(scope: ScopeCreate) -> None:
    for cidr in scope.authorized_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ImportErrorDetail(f"Invalid authorized CIDR: {cidr}") from exc

        if network.prefixlen == 0:
            raise ImportErrorDetail("Default-route scopes are not allowed.")
        if network.version == 4 and network.prefixlen < 16:
            raise ImportErrorDetail("IPv4 scopes broader than /16 are rejected by default.")
        if network.version == 6 and network.prefixlen < 112:
            raise ImportErrorDetail("IPv6 scopes broader than /112 are rejected by default.")
        if public_scope_requires_flag(network) and not scope.public_scope_allowed:
            raise ImportErrorDetail(
                f"Public scope {cidr} requires explicit public_scope_allowed authorization."
            )


def parse_collector_payload(raw: bytes) -> CollectorPayload:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImportErrorDetail("Collector upload must be valid UTF-8 JSON.") from exc
    try:
        return CollectorPayload.model_validate(data)
    except ValidationError as exc:
        raise ImportErrorDetail(f"Collector JSON failed schema validation: {exc}") from exc


def naive_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def get_or_create_site(db: Session, assessment: Assessment, site_name: str | None) -> Site | None:
    if not site_name:
        return None
    site = db.scalar(
        select(Site).where(Site.client_id == assessment.client_id, Site.name == site_name)
    )
    if site is None:
        site = Site(client_id=assessment.client_id, name=site_name)
        db.add(site)
        db.flush()
    return site


def asset_identity_filters(
    assessment: Assessment, hostname: str, ip_address: str | None
) -> list[Any]:
    filters: list[Any] = [
        Asset.client_id == assessment.client_id,
        Asset.assessment_id == assessment.id,
        Asset.hostname == hostname,
    ]
    if ip_address:
        filters.append(Asset.ip_address == ip_address)
    return filters


def upsert_asset(db: Session, assessment: Assessment, payload_asset: Any) -> Asset:
    existing = db.scalar(
        select(Asset).where(
            *asset_identity_filters(assessment, payload_asset.hostname, payload_asset.ip_address)
        )
    )
    site = get_or_create_site(db, assessment, payload_asset.site_name)
    metadata = {
        "open_ports": payload_asset.open_ports,
        "backup_status": payload_asset.backup_status,
        "backup_storage_usage_percent": payload_asset.backup_storage_usage_percent,
        "endpoint_security_status": payload_asset.endpoint_security_status,
        "unsupported_os": payload_asset.unsupported_os,
        "packages": payload_asset.packages,
    }
    extra = payload_asset.model_extra or {}
    for key, value in extra.items():
        if key not in {"password", "token", "secret", "private_key", "browser_data"}:
            metadata[key] = value

    if existing is None:
        asset = Asset(
            client_id=assessment.client_id,
            site_id=site.id if site else None,
            assessment_id=assessment.id,
            hostname=payload_asset.hostname,
            ip_address=payload_asset.ip_address,
            mac_address=payload_asset.mac_address,
            os_family=payload_asset.os_family,
            os_version=payload_asset.os_version,
            last_seen=naive_utc(payload_asset.last_seen),
            source=payload_asset.source,
            tags=payload_asset.tags,
            criticality=payload_asset.criticality,
            owner=payload_asset.owner,
            metadata_json=metadata,
        )
        db.add(asset)
        return asset

    existing.site_id = site.id if site else existing.site_id
    existing.mac_address = payload_asset.mac_address or existing.mac_address
    existing.os_family = payload_asset.os_family or existing.os_family
    existing.os_version = payload_asset.os_version or existing.os_version
    existing.last_seen = naive_utc(payload_asset.last_seen) or existing.last_seen
    existing.source = payload_asset.source
    existing.tags = payload_asset.tags or existing.tags
    existing.criticality = payload_asset.criticality or existing.criticality
    existing.owner = payload_asset.owner or existing.owner
    existing.metadata_json = {**(existing.metadata_json or {}), **metadata}
    return existing


def import_collector_payload(
    db: Session, assessment: Assessment, payload: CollectorPayload
) -> dict[str, Any]:
    scope_create = ScopeCreate(
        client_name=payload.scope.client_name,
        authorized_cidrs=payload.scope.authorized_cidrs,
        authorized_domains=payload.scope.authorized_domains,
        start_time=payload.scope.start_time,
        requested_by=payload.scope.requested_by,
        operator_notes=payload.scope.operator_notes,
        public_scope_allowed=payload.scope.public_scope_allowed,
    )
    validate_scope_record(scope_create)
    scope = ScopeRecord(
        assessment_id=assessment.id,
        client_name=scope_create.client_name,
        authorized_cidrs=scope_create.authorized_cidrs,
        authorized_domains=scope_create.authorized_domains,
        start_time=naive_utc(scope_create.start_time) or datetime.now(UTC).replace(tzinfo=None),
        requested_by=scope_create.requested_by,
        operator_notes=scope_create.operator_notes,
        public_scope_allowed=scope_create.public_scope_allowed,
    )
    db.add(scope)

    imported_assets = [upsert_asset(db, assessment, asset) for asset in payload.assets]
    db.flush()
    findings = run_rules_for_assessment(db, assessment)
    return {
        "assets_imported": len(imported_assets),
        "findings_touched": len(findings),
        "scope_id": scope.id,
        "collector_version": payload.collector_version,
        "collection_method": payload.collection_method,
    }
