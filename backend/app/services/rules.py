from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Assessment, Asset, Finding

SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def load_rules(path: Path | None = None) -> list[dict[str, Any]]:
    rules_path = path or Path(__file__).resolve().parents[1] / "rules" / "starter_rules.yml"
    with rules_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data.get("rules", [])


def get_field(asset: Asset, field: str) -> Any:
    if field.startswith("metadata."):
        value: Any = asset.metadata_json or {}
        for part in field.split(".")[1:]:
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value
    if field == "last_seen":
        return asset.last_seen
    return getattr(asset, field, None)


def is_missing(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def compare(value: Any, op: str, expected: Any) -> bool:
    if op == "missing":
        return is_missing(value)
    if op == "present":
        return not is_missing(value)
    if op == "equals":
        return str(value).lower() == str(expected).lower()
    if op == "not_equals":
        return str(value).lower() != str(expected).lower()
    if op == "contains":
        if isinstance(value, list):
            return expected in value or str(expected) in {str(item) for item in value}
        return str(expected).lower() in str(value or "").lower()
    if op == "contains_any":
        values = expected if isinstance(expected, list) else [expected]
        haystack = str(value or "").lower()
        if isinstance(value, list):
            haystack = " ".join(str(item).lower() for item in value)
        return any(str(item).lower() in haystack for item in values)
    if op == "in":
        values = expected if isinstance(expected, list) else [expected]
        return str(value).lower() in {str(item).lower() for item in values}
    if op == "not_in":
        values = expected if isinstance(expected, list) else [expected]
        if is_missing(value):
            return True
        return str(value).lower() not in {str(item).lower() for item in values}
    if op in {"gte", "gt", "lte", "lt"}:
        try:
            left = float(value)
            right = float(expected)
        except (TypeError, ValueError):
            return False
        return {
            "gte": left >= right,
            "gt": left > right,
            "lte": left <= right,
            "lt": left < right,
        }[op]
    if op == "older_than_days":
        if not isinstance(value, datetime):
            return False
        return (utcnow() - value).days > int(expected)
    return False


def matches_condition(asset: Asset, condition: dict[str, Any]) -> bool:
    return compare(get_field(asset, condition["field"]), condition["op"], condition.get("value"))


def matches_rule(asset: Asset, rule: dict[str, Any]) -> bool:
    match = rule.get("match", {})
    if "all" in match:
        return all(matches_condition(asset, condition) for condition in match["all"])
    if "any" in match:
        return any(matches_condition(asset, condition) for condition in match["any"])
    return False


def build_evidence(rule: dict[str, Any], assets: list[Asset]) -> str:
    lines = [f"Rule {rule['id']} matched {len(assets)} asset(s)."]
    for asset in assets[:25]:
        parts = [asset.hostname]
        if asset.ip_address:
            parts.append(asset.ip_address)
        if asset.os_family or asset.os_version:
            parts.append(" ".join(item for item in [asset.os_family, asset.os_version] if item))
        metadata = asset.metadata_json or {}
        if metadata.get("open_ports"):
            parts.append(f"open ports: {metadata['open_ports']}")
        if metadata.get("backup_status"):
            parts.append(f"backup: {metadata['backup_status']}")
        if metadata.get("endpoint_security_status"):
            parts.append(f"endpoint security: {metadata['endpoint_security_status']}")
        lines.append(" - " + " | ".join(parts))
    if len(assets) > 25:
        lines.append(
            f" - {len(assets) - 25} additional matched asset(s) omitted from evidence preview."
        )
    return "\n".join(lines)


def run_rules_for_assessment(db: Session, assessment: Assessment) -> list[Finding]:
    rules = load_rules()
    assets = list(
        db.scalars(
            select(Asset).where(Asset.assessment_id == assessment.id).order_by(Asset.hostname)
        )
    )
    updated: list[Finding] = []
    now = utcnow()

    for rule in rules:
        matched_assets = [asset for asset in assets if matches_rule(asset, rule)]
        source = f"rule:{rule['id']}"
        existing = db.scalar(
            select(Finding).where(
                Finding.assessment_id == assessment.id,
                Finding.source == source,
                Finding.title == rule["title"],
            )
        )
        if not matched_assets:
            if existing and existing.status == "Open":
                existing.status = "Resolved"
                existing.last_seen = now
                updated.append(existing)
            continue

        finding_payload = rule.get("finding", {})
        if existing is None:
            existing = Finding(
                assessment_id=assessment.id,
                client_id=assessment.client_id,
                title=rule["title"],
                severity=rule["severity"],
                category=rule["category"],
                description=finding_payload.get("description", ""),
                evidence=build_evidence(rule, matched_assets),
                impact=finding_payload.get("impact", ""),
                recommended_remediation=finding_payload.get("remediation", ""),
                source=source,
                confidence_score=float(rule.get("confidence", 0.7)),
                metadata_json={"rule_id": rule["id"]},
            )
            db.add(existing)
        else:
            existing.severity = rule["severity"]
            existing.category = rule["category"]
            existing.description = finding_payload.get("description", existing.description)
            existing.evidence = build_evidence(rule, matched_assets)
            existing.impact = finding_payload.get("impact", existing.impact)
            existing.recommended_remediation = finding_payload.get(
                "remediation", existing.recommended_remediation
            )
            existing.last_seen = now
            existing.confidence_score = float(rule.get("confidence", existing.confidence_score))
            if existing.status == "Resolved":
                existing.status = "Open"
        existing.assets = matched_assets
        updated.append(existing)

    return updated
