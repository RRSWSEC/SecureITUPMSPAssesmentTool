from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=256)


class ClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    legal_name: str | None = Field(default=None, max_length=255)
    domain: str | None = Field(default=None, max_length=255)
    status: str = Field(default="Active", max_length=50)


class SiteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    address: str | None = None
    notes: str | None = None


class ContactCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    phone: str | None = Field(default=None, max_length=100)
    role: str | None = Field(default=None, max_length=100)


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    purpose: str = Field(default="Onboarding", max_length=100)
    status: str = Field(default="Draft", max_length=50)


class ScopeCreate(BaseModel):
    client_name: str = Field(min_length=1, max_length=255)
    authorized_cidrs: list[str] = Field(default_factory=list)
    authorized_domains: list[str] = Field(default_factory=list)
    start_time: datetime | None = None
    requested_by: str = Field(min_length=1, max_length=255)
    operator_notes: str | None = None
    public_scope_allowed: bool = False


class NoteCreate(BaseModel):
    body: str = Field(min_length=1)


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern="^(Open|Accepted Risk|In Progress|Resolved|False Positive)$")


class ScopePackage(BaseModel):
    client_name: str = Field(min_length=1)
    authorized_cidrs: list[str] = Field(default_factory=list)
    authorized_domains: list[str] = Field(default_factory=list)
    start_time: datetime | None = None
    requested_by: str = Field(min_length=1)
    operator_notes: str | None = None
    public_scope_allowed: bool = False


class CollectorAsset(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str | None = None
    mac_address: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    last_seen: datetime | None = None
    source: str = "collector"
    tags: list[str] = Field(default_factory=list)
    criticality: str = "Medium"
    owner: str | None = None
    site_name: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    backup_status: str | None = None
    backup_storage_usage_percent: float | None = None
    endpoint_security_status: str | None = None
    unsupported_os: bool | None = None
    packages: list[dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class CollectorPayload(BaseModel):
    collector_version: str = Field(min_length=1)
    timestamp: datetime
    operator: str = Field(min_length=1)
    scope: ScopePackage
    collection_method: str = Field(min_length=1)
    assets: list[CollectorAsset] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
