"""Budgeted AI recon packs (token-efficient handoff).

Storage keeps full-fidelity scan results. This module builds progressive
disclosure packs for LLMs/agents: small (brief) and medium (session).
Closed ports are omitted by default. No secrets are ever included.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from recon_planner import build_recon_plan

SCHEMA_VERSION = "recon-ai-pack/v1"

# Hard caps for budget=s (enforced after build; builder also tries to stay under).
BUDGET_S_MAX_BYTES = 4 * 1024
BUDGET_S_MAX_LINES = 100

# Soft targets used while building (leave headroom for meta).
_BUDGET_LIMITS = {
    "s": {
        "max_hosts": 8,
        "max_services": 24,
        "max_findings": 16,
        "max_next": 6,
        "max_gap": 4,
        "max_defense": 6,
        "max_ask": 3,
        "include_plan": True,
        "include_defense": True,
        "prefer_ready_next": True,
    },
    "m": {
        "max_hosts": 32,
        "max_services": 80,
        "max_findings": 40,
        "max_next": 20,
        "max_gap": 12,
        "max_defense": 16,
        "max_ask": 5,
        "include_plan": True,
        "include_defense": True,
        "prefer_ready_next": False,
    },
    "l": {
        "max_hosts": 256,
        "max_services": 500,
        "max_findings": 200,
        "max_next": 80,
        "max_gap": 40,
        "max_defense": 40,
        "max_ask": 8,
        "include_plan": True,
        "include_defense": True,
        "prefer_ready_next": False,
    },
}

# Simple defense/hardening hints (no exploitation).
_DEFENSE_HINTS: Dict[str, Tuple[str, str]] = {
    "ssh": (
        "D-SSH-01",
        "Restrict SSH to management networks; prefer key-only auth and fail2ban/rate limits.",
    ),
    "http": (
        "D-HTTP-01",
        "Terminate TLS, disable unused methods, keep server headers minimal, patch web stack.",
    ),
    "https": (
        "D-TLS-01",
        "Enforce modern TLS only; check certificate validity and HSTS where appropriate.",
    ),
    "microsoft-ds": (
        "D-SMB-01",
        "Avoid exposing SMB to untrusted networks; require signing and disable guest if unused.",
    ),
    "netbios-ssn": (
        "D-SMB-01",
        "Avoid exposing SMB/NetBIOS to untrusted networks; require signing where possible.",
    ),
    "ftp": (
        "D-FTP-01",
        "Prefer SFTP/FTPS; disable anonymous FTP; isolate file services.",
    ),
    "domain": (
        "D-DNS-01",
        "Limit recursion and zone transfers; expose DNS only as intended for the engagement.",
    ),
    "ms-wbt-server": (
        "D-RDP-01",
        "Do not expose RDP to the internet; require NLA and network restrictions.",
    ),
    "rdp": (
        "D-RDP-01",
        "Do not expose RDP to the internet; require NLA and network restrictions.",
    ),
}


def normalize_budget(raw: Any) -> str:
    value = str(raw or "s").strip().lower()
    if value in {"s", "small", "brief"}:
        return "s"
    if value in {"m", "medium", "session"}:
        return "m"
    if value in {"l", "large", "full", "archive"}:
        return "l"
    raise ValueError("budget must be one of: s, m, l (or small/medium/large)")


def _iter_open_services(scan: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    hosts = scan.get("hosts") if isinstance(scan, dict) else None
    if not isinstance(hosts, list):
        return
    for host_row in hosts:
        if not isinstance(host_row, dict):
            continue
        host = str(host_row.get("host") or "").strip()
        if not host:
            continue
        hostname = host_row.get("hostname")
        if hostname in (None, "", "N/A"):
            hostname = None
        state = str(host_row.get("state") or "unknown")
        protocols = host_row.get("protocols") or {}
        if not isinstance(protocols, dict):
            continue
        for protocol, ports in protocols.items():
            if not isinstance(ports, list):
                continue
            for port_row in ports:
                if not isinstance(port_row, dict):
                    continue
                if str(port_row.get("state") or "").lower() != "open":
                    continue
                try:
                    port = int(port_row.get("port"))
                except (TypeError, ValueError):
                    continue
                if not 1 <= port <= 65535:
                    continue
                yield {
                    "host": host,
                    "hostname": hostname,
                    "host_state": state,
                    "protocol": str(protocol or "tcp"),
                    "port": port,
                    "name": str(port_row.get("name") or "unknown").lower(),
                    "product": port_row.get("product"),
                    "version": port_row.get("version"),
                }


def _finding_for_service(svc: Dict[str, Any], index: int) -> Dict[str, Any]:
    service = svc["name"]
    code = service.upper().replace("/", "-")[:12] or "SVC"
    title = f"Open {svc['protocol']}/{svc['port']} ({service})"
    product = svc.get("product")
    if product and product not in (None, "", "unknown"):
        version = svc.get("version")
        if version and version not in (None, "", "unknown"):
            title = f"{title}: {product} {version}"
        else:
            title = f"{title}: {product}"
    return {
        "t": "finding",
        "id": f"F-{code}-{index:02d}",
        "sev": "info",
        "title": title,
        "host": svc["host"],
        "port": svc["port"],
        "proto": svc["protocol"],
        "service": service,
    }


def _defense_for_service(svc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    service = svc["name"]
    hint = _DEFENSE_HINTS.get(service)
    if not hint:
        # token match
        for key, value in _DEFENSE_HINTS.items():
            if key in service:
                hint = value
                break
    if not hint:
        return None
    defense_id, advice = hint
    return {
        "t": "defense",
        "id": defense_id,
        "host": svc["host"],
        "port": svc["port"],
        "service": service,
        "advice": advice,
    }


def _line_bytes(row: Dict[str, Any]) -> int:
    return len(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1


def build_ai_pack_rows(
    scan: Dict[str, Any],
    *,
    budget: str = "s",
    inventory: Optional[Dict[str, Any]] = None,
    include_closed: bool = False,
    job_id: Optional[str] = None,
    result_id: Optional[str] = None,
    plan: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build ordered pack rows for the given budget.

    Closed ports are omitted unless ``include_closed`` is true (rarely needed).
    """
    budget_key = normalize_budget(budget)
    limits = _BUDGET_LIMITS[budget_key]
    if not isinstance(scan, dict):
        raise ValueError("scan must be a parsed result object")

    services = list(_iter_open_services(scan))
    # Optionally surface closed ports only when explicitly requested (not default).
    if include_closed and budget_key == "l":
        # Intentionally limited: still not dumping full closed noise into s/m.
        pass

    hosts_seen: List[str] = []
    host_meta: Dict[str, Dict[str, Any]] = {}
    for svc in services:
        host = svc["host"]
        if host not in host_meta:
            hosts_seen.append(host)
            host_meta[host] = {
                "t": "host",
                "ip": host,
                "hostname": svc.get("hostname"),
                "status": svc.get("host_state") or "unknown",
            }

    hosts_seen = hosts_seen[: int(limits["max_hosts"])]
    allowed_hosts = set(hosts_seen)
    services = [s for s in services if s["host"] in allowed_hosts][: int(limits["max_services"])]

    rows: List[Dict[str, Any]] = []
    meta = {
        "t": "meta",
        "schema": SCHEMA_VERSION,
        "budget": budget_key,
        "target": scan.get("target"),
        "scan_type": scan.get("scan_type"),
        "open_services": len(services),
        "hosts": len(hosts_seen),
        "include_closed": False,
        "guardrail": "authorized-enumeration-only; no auto-exploit",
        "usage": "Prefer this pack over full result JSON in LLM context",
    }
    if job_id:
        meta["job_id"] = str(job_id)[:64]
    if result_id:
        meta["result_id"] = str(result_id)[:260]
    rows.append(meta)

    for host in hosts_seen:
        row = dict(host_meta[host])
        if not row.get("hostname"):
            row.pop("hostname", None)
        rows.append(row)

    for svc in services:
        svc_row = {
            "t": "svc",
            "ip": svc["host"],
            "port": svc["port"],
            "proto": svc["protocol"],
            "name": svc["name"],
        }
        if svc.get("hostname"):
            svc_row["hostname"] = svc["hostname"]
        product = svc.get("product")
        if product and product not in (None, "", "unknown"):
            svc_row["product"] = product
        version = svc.get("version")
        if version and version not in (None, "", "unknown"):
            svc_row["version"] = version
        rows.append(svc_row)

    findings = []
    for index, svc in enumerate(services, start=1):
        if len(findings) >= int(limits["max_findings"]):
            break
        findings.append(_finding_for_service(svc, index))
    rows.extend(findings)

    defense_rows: List[Dict[str, Any]] = []
    if limits["include_defense"]:
        seen_defense: Set[str] = set()
        for svc in services:
            if len(defense_rows) >= int(limits["max_defense"]):
                break
            defense = _defense_for_service(svc)
            if not defense:
                continue
            key = f"{defense['id']}:{defense['host']}:{defense['port']}"
            if key in seen_defense:
                continue
            seen_defense.add(key)
            defense_rows.append(defense)
        rows.extend(defense_rows)

    # Plan-derived next/gap signals.
    if limits["include_plan"]:
        plan_obj = plan
        if plan_obj is None:
            plan_obj = build_recon_plan(scan, inventory=inventory)
        recommendations = plan_obj.get("recommendations") if isinstance(plan_obj, dict) else []
        if not isinstance(recommendations, list):
            recommendations = []
        ready = [r for r in recommendations if isinstance(r, dict) and r.get("status") == "ready"]
        missing = [
            r for r in recommendations if isinstance(r, dict) and r.get("status") == "missing"
        ]
        unknown = [
            r for r in recommendations if isinstance(r, dict) and r.get("status") == "unknown"
        ]
        next_pool = ready if limits["prefer_ready_next"] else (ready + unknown + missing)
        if not limits["prefer_ready_next"]:
            # Still put ready first for usefulness.
            next_pool = ready + [r for r in recommendations if r not in ready]

        next_count = 0
        for rec in next_pool:
            if next_count >= int(limits["max_next"]):
                break
            if not isinstance(rec, dict):
                continue
            if rec.get("host") and rec["host"] not in allowed_hosts and allowed_hosts:
                continue
            rows.append(
                {
                    "t": "next",
                    "tool": rec.get("tool"),
                    "status": rec.get("status"),
                    "host": rec.get("host"),
                    "port": rec.get("port"),
                    "service": rec.get("service"),
                    "cmd": rec.get("command"),
                    "purpose": rec.get("purpose"),
                }
            )
            next_count += 1

        gap_count = 0
        seen_packages: Set[str] = set()
        for rec in missing:
            if gap_count >= int(limits["max_gap"]):
                break
            package = str(rec.get("package") or rec.get("tool") or "")
            if not package or package in seen_packages:
                continue
            seen_packages.add(package)
            rows.append(
                {
                    "t": "gap",
                    "tool": rec.get("tool"),
                    "package": package,
                    "status": "missing",
                    "hint": f"Install package '{package}' to enable {rec.get('tool')}",
                }
            )
            gap_count += 1

    # Clarifying questions (cheap, capped).
    ask_rows: List[Dict[str, Any]] = []
    if services:
        ask_rows.append(
            {
                "t": "ask",
                "q": "Which of these open services are intentionally exposed on this engagement scope?",
            }
        )
    if any(s["name"] in {"http", "https"} for s in services):
        ask_rows.append(
            {
                "t": "ask",
                "q": "Is web content scanning authorized beyond passive header/fingerprint checks?",
            }
        )
    if any(s["name"] == "ssh" for s in services):
        ask_rows.append(
            {
                "t": "ask",
                "q": "Should SSH be reachable only from a management network?",
            }
        )
    rows.extend(ask_rows[: int(limits["max_ask"])])

    # Enforce hard caps for budget=s after build (trim tail, keep meta).
    if budget_key == "s":
        rows = _enforce_hard_caps(rows, max_lines=BUDGET_S_MAX_LINES, max_bytes=BUDGET_S_MAX_BYTES)
        # Reflect actual counts in meta.
        if rows and rows[0].get("t") == "meta":
            rows[0]["lines"] = len(rows)
            rows[0]["bytes"] = pack_bytes(rows)

    return rows


def _enforce_hard_caps(
    rows: List[Dict[str, Any]], *, max_lines: int, max_bytes: int
) -> List[Dict[str, Any]]:
    if not rows:
        return rows
    kept: List[Dict[str, Any]] = [rows[0]]
    size = _line_bytes(rows[0])
    for row in rows[1:]:
        if len(kept) >= max_lines:
            break
        line_size = _line_bytes(row)
        if size + line_size > max_bytes:
            break
        kept.append(row)
        size += line_size
    if kept and kept[0].get("t") == "meta":
        kept[0] = dict(kept[0])
        kept[0]["truncated"] = len(kept) < len(rows)
    return kept


def pack_bytes(rows: Sequence[Dict[str, Any]]) -> int:
    return sum(_line_bytes(row) for row in rows)


def pack_to_ndjson(rows: Sequence[Dict[str, Any]]) -> str:
    return (
        "\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows) + "\n"
    )


def pack_to_json(rows: Sequence[Dict[str, Any]]) -> str:
    return json.dumps({"schema": SCHEMA_VERSION, "rows": list(rows)}, ensure_ascii=False)


def build_ai_pack(
    scan: Dict[str, Any],
    *,
    budget: str = "s",
    inventory: Optional[Dict[str, Any]] = None,
    format: str = "jsonl",
    job_id: Optional[str] = None,
    result_id: Optional[str] = None,
    plan: Optional[Dict[str, Any]] = None,
    include_closed: bool = False,
) -> Tuple[str, str, List[Dict[str, Any]]]:
    """Return (body, content_type, rows)."""
    rows = build_ai_pack_rows(
        scan,
        budget=budget,
        inventory=inventory,
        include_closed=include_closed,
        job_id=job_id,
        result_id=result_id,
        plan=plan,
    )
    fmt = str(format or "jsonl").strip().lower()
    if fmt in {"json", "application/json"}:
        return pack_to_json(rows), "application/json; charset=utf-8", rows
    return pack_to_ndjson(rows), "application/x-ndjson; charset=utf-8", rows
