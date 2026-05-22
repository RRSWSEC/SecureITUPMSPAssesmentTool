#!/usr/bin/env python3
"""Safe local-first collector for Secure IT UP Assessment Suite.

The collector defaults to local host inventory and import modes. Network discovery requires
--authorized, --scope, and explicit scan flags.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

COLLECTOR_VERSION = "0.1.0"
DEFAULT_PORTS = [22, 80, 443, 445, 3389]
ALLOWLIST_PORTS = {22, 80, 135, 139, 443, 445, 3389, 1433, 3306, 5432, 27017}
SENSITIVE_KEYS = {"password", "token", "secret", "private_key", "browser_data", "cookie"}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def is_public_scope(network: ipaddress._BaseNetwork) -> bool:
    return not (
        network.is_private or network.is_loopback or network.is_link_local or network.is_reserved
    )


def validate_scopes(scopes: list[str], allow_public_scope: bool) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for raw_scope in scopes:
        try:
            network = ipaddress.ip_network(raw_scope, strict=False)
        except ValueError as exc:
            raise SystemExit(f"Invalid scope {raw_scope}: {exc}") from exc
        if network.prefixlen == 0:
            raise SystemExit("Refusing default-route scope. 0.0.0.0/0 and ::/0 are not allowed.")
        if network.version == 4 and network.prefixlen < 24:
            raise SystemExit("Refusing IPv4 scopes broader than /24 in the collector MVP.")
        if network.version == 6 and network.prefixlen < 120:
            raise SystemExit("Refusing IPv6 scopes broader than /120 in the collector MVP.")
        if network.num_addresses > 1024:
            raise SystemExit("Refusing scopes with more than 1024 addresses in the collector MVP.")
        if is_public_scope(network) and not allow_public_scope:
            raise SystemExit(f"Refusing public scope {network}; pass --allow-public-scope only with written authorization.")
        networks.append(network)
    return networks


def normalize_asset(asset: dict[str, Any], source: str) -> dict[str, Any]:
    cleaned = {key: value for key, value in asset.items() if key.lower() not in SENSITIVE_KEYS}
    cleaned.setdefault("hostname", cleaned.get("ip_address") or "unknown-device")
    cleaned.setdefault("source", source)
    cleaned.setdefault("tags", [])
    cleaned.setdefault("criticality", "Medium")
    cleaned.setdefault("open_ports", [])
    cleaned.setdefault("last_seen", utc_now())
    return cleaned


def local_inventory() -> list[dict[str, Any]]:
    hostname = socket.gethostname()
    addresses: list[str] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family in {socket.AF_INET, socket.AF_INET6}:
                addresses.append(str(sockaddr[0]))
    except socket.gaierror:
        pass
    mac_value = uuid.getnode()
    mac = ":".join(f"{(mac_value >> bits) & 0xFF:02x}" for bits in range(40, -1, -8))
    return [
        normalize_asset(
            {
                "hostname": hostname,
                "ip_address": next((ip for ip in addresses if not ip.startswith("127.")), None),
                "mac_address": mac,
                "os_family": platform.system() or None,
                "os_version": " ".join(part for part in [platform.release(), platform.version()] if part),
                "source": "local_inventory",
                "tags": ["collector-local"],
                "criticality": "Medium",
                "backup_status": "not_reported",
                "endpoint_security_status": "not_reported",
            },
            "local_inventory",
        )
    ]


def ping_host(ip: str, timeout_ms: int = 1000) -> bool:
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def tcp_connect(ip: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return f"host-{ip.replace('.', '-')}"


def network_discovery(
    networks: list[ipaddress._BaseNetwork],
    *,
    ping_sweep: bool,
    tcp_scan: bool,
    ports: list[int],
    rate_limit: float,
) -> list[dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    delay = 1.0 / max(rate_limit, 0.1)
    for network in networks:
        hosts = list(network.hosts()) if network.version == 4 else list(network.hosts())[:1024]
        for host in hosts:
            ip = str(host)
            seen = False
            open_ports: list[int] = []
            if ping_sweep:
                seen = ping_host(ip)
                time.sleep(delay)
            if tcp_scan:
                for port in ports:
                    if tcp_connect(ip, port):
                        seen = True
                        open_ports.append(port)
                    time.sleep(delay)
            if seen:
                results[ip] = normalize_asset(
                    {
                        "hostname": reverse_dns(ip),
                        "ip_address": ip,
                        "source": "authorized_safe_discovery",
                        "tags": ["authorized-discovery"],
                        "open_ports": open_ports,
                        "backup_status": "not_reported",
                        "endpoint_security_status": "not_reported",
                    },
                    "authorized_safe_discovery",
                )
    return list(results.values())


def parse_arp_table() -> list[dict[str, Any]]:
    try:
        output = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    assets = []
    for match in re.finditer(
        r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})",
        output.stdout,
    ):
        assets.append(
            normalize_asset(
                {
                    "hostname": f"arp-{match.group('ip').replace('.', '-')}",
                    "ip_address": match.group("ip"),
                    "mac_address": match.group("mac").replace("-", ":").lower(),
                    "source": "arp_table",
                    "tags": ["passive-neighbor-table"],
                },
                "arp_table",
            )
        )
    return assets


def import_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = csv.DictReader(handle)
        return [normalize_asset(dict(row), "csv_import") for row in rows]


def import_json(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict) and "assets" in data:
        assets = data["assets"]
    elif isinstance(data, list):
        assets = data
    else:
        raise SystemExit("JSON import must contain an assets array or be an array of assets.")
    return [normalize_asset(dict(asset), "json_import") for asset in assets]


def import_nmap_xml(path: Path) -> list[dict[str, Any]]:
    tree = ElementTree.parse(path)
    root = tree.getroot()
    assets: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue
        ip_address = None
        mac_address = None
        for address in host.findall("address"):
            if address.attrib.get("addrtype") == "ipv4":
                ip_address = address.attrib.get("addr")
            if address.attrib.get("addrtype") == "mac":
                mac_address = address.attrib.get("addr")
        hostname = None
        hostname_node = host.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.attrib.get("name")
        open_ports: list[int] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None and state.attrib.get("state") == "open":
                try:
                    open_ports.append(int(port.attrib["portid"]))
                except (KeyError, ValueError):
                    pass
        if ip_address or hostname:
            assets.append(
                normalize_asset(
                    {
                        "hostname": hostname or f"nmap-{ip_address}",
                        "ip_address": ip_address,
                        "mac_address": mac_address,
                        "source": "nmap_xml_import",
                        "tags": ["imported-nmap-xml"],
                        "open_ports": open_ports,
                        "backup_status": "not_reported",
                        "endpoint_security_status": "not_reported",
                    },
                    "nmap_xml_import",
                )
            )
    return assets


def parse_ports(raw_ports: str) -> list[int]:
    ports = []
    for raw in raw_ports.split(","):
        try:
            port = int(raw.strip())
        except ValueError as exc:
            raise SystemExit(f"Invalid TCP port: {raw}") from exc
        if port not in ALLOWLIST_PORTS:
            raise SystemExit(f"TCP port {port} is not in the collector allowlist: {sorted(ALLOWLIST_PORTS)}")
        ports.append(port)
    return ports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure IT UP safe collector")
    parser.add_argument("--output", default="collector-output.json", help="Output JSON path")
    parser.add_argument("--operator", default=getpass.getuser(), help="Operator name for evidence metadata")
    parser.add_argument("--client-name", default="Local Authorized Assessment", help="Client name for scope record")
    parser.add_argument("--requested-by", default=None, help="Person who requested the collection")
    parser.add_argument("--operator-notes", default="", help="Scope and handling notes")
    parser.add_argument("--scope", action="append", default=[], help="Authorized CIDR scope; repeatable")
    parser.add_argument("--authorized", action="store_true", help="Required for any network discovery")
    parser.add_argument("--allow-public-scope", action="store_true", help="Permit public CIDR scope with written authorization")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print planned collection without scanning")
    parser.add_argument("--ping-sweep", action="store_true", help="Optional ICMP ping sweep")
    parser.add_argument("--tcp-scan", action="store_true", help="Optional TCP connect scan against allowlisted ports")
    parser.add_argument("--ports", default=",".join(str(port) for port in DEFAULT_PORTS), help="Comma-separated allowlisted TCP ports")
    parser.add_argument("--rate-limit", type=float, default=10.0, help="Approximate probes per second")
    parser.add_argument("--arp-table", action="store_true", help="Parse local ARP table without active scanning")
    parser.add_argument("--import-csv", type=Path, help="Import assets from CSV")
    parser.add_argument("--import-json", type=Path, help="Import assets from JSON")
    parser.add_argument("--import-nmap-xml", type=Path, help="Import Nmap XML without requiring nmap")
    parser.add_argument("--no-local", action="store_true", help="Skip local host inventory")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    network_requested = args.ping_sweep or args.tcp_scan
    if network_requested and not args.authorized:
        raise SystemExit("Network discovery requires --authorized and an explicit --scope.")
    if network_requested and not args.scope:
        raise SystemExit("Network discovery requires at least one --scope CIDR.")
    networks = validate_scopes(args.scope, args.allow_public_scope)
    ports = parse_ports(args.ports)

    methods: list[str] = []
    if not args.no_local:
        methods.append("local_inventory")
    if args.arp_table:
        methods.append("arp_table")
    if args.import_csv:
        methods.append("csv_import")
    if args.import_json:
        methods.append("json_import")
    if args.import_nmap_xml:
        methods.append("nmap_xml_import")
    if args.ping_sweep:
        methods.append("authorized_ping_sweep")
    if args.tcp_scan:
        methods.append("authorized_tcp_connect")

    if args.dry_run:
        print("Dry run: no network probes will be sent.")
        print(f"Operator: {args.operator}")
        print(f"Client/scope record: {args.client_name}")
        print(f"Requested methods: {', '.join(methods) or 'none'}")
        if networks:
            print(f"Authorized CIDRs: {', '.join(str(network) for network in networks)}")
            print(f"TCP ports: {ports if args.tcp_scan else 'not requested'}")
            print(f"Rate limit: {args.rate_limit} probes/second")
        return 0

    assets: list[dict[str, Any]] = []
    if not args.no_local:
        assets.extend(local_inventory())
    if args.arp_table:
        assets.extend(parse_arp_table())
    if args.import_csv:
        assets.extend(import_csv(args.import_csv))
    if args.import_json:
        assets.extend(import_json(args.import_json))
    if args.import_nmap_xml:
        assets.extend(import_nmap_xml(args.import_nmap_xml))
    if network_requested:
        assets.extend(
            network_discovery(
                networks,
                ping_sweep=args.ping_sweep,
                tcp_scan=args.tcp_scan,
                ports=ports,
                rate_limit=args.rate_limit,
            )
        )

    payload = {
        "collector_version": COLLECTOR_VERSION,
        "timestamp": utc_now(),
        "operator": args.operator,
        "scope": {
            "client_name": args.client_name,
            "authorized_cidrs": [str(network) for network in networks],
            "authorized_domains": [],
            "start_time": utc_now(),
            "requested_by": args.requested_by or args.operator,
            "operator_notes": args.operator_notes,
            "public_scope_allowed": args.allow_public_scope,
        },
        "collection_method": ",".join(methods) if methods else "none",
        "assets": assets,
    }
    output_path = Path(args.output)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {len(assets)} asset record(s) to {output_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
