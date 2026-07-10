#!/usr/bin/env python3
"""AI-readable Nmap runner/parser for Kali-style workflows.

Nmap stays the scanner; this script runs it without a shell and reshapes its
XML into artifacts that are easy for humans and LLMs to consume after an
authorized assessment. XML parsing uses defusedxml for untrusted input safety.
"""

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from defusedxml import ElementTree as ET

SCHEMA_VERSION = "ai-nmap-report/v1"
MAX_XML_BYTES = 64 * 1024 * 1024
SCAN_PROFILES = {
    "ping": ["-sn"],
    "tcp": ["-sT"],
    "syn": ["-sS"],
    "version": ["-sV"],
    "safe": ["-sV", "--script", "safe"],
}
TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/,*?\[\]-]+$")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def reject_suspicious_target(target: str) -> None:
    if not target or len(target) > 512 or not TARGET_RE.match(target):
        raise SystemExit("Refusing suspicious target syntax. Use a host, IP, CIDR, or Nmap range.")


def run_command(args: list, timeout: int = 10) -> dict:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": str(exc), "command": args}

    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "command": args,
    }


def package_status(packages: list) -> dict:
    if not shutil.which("dpkg-query"):
        return {"available": False, "reason": "dpkg-query not found", "packages": {}}

    status = {}
    for package in packages:
        result = run_command(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n", package]
        )
        status[package] = result
    return {"available": True, "packages": status}


def apt_policy(package: str) -> dict:
    if not shutil.which("apt-cache"):
        return {"available": False, "reason": "apt-cache not found"}
    return run_command(["apt-cache", "policy", package])


def nmap_version() -> dict:
    return run_command(["nmap", "--version"])


def primary_host_id(host: dict) -> str:
    for address in host["addresses"]:
        if address.get("type") in {"ipv4", "ipv6"}:
            return address["addr"]
    if host["addresses"]:
        return host["addresses"][0]["addr"]
    if host["hostnames"]:
        return host["hostnames"][0]
    return "unknown"


def parse_nmap_xml(xml_path: Path) -> dict:
    if not xml_path.is_file():
        raise FileNotFoundError(f"Nmap XML file not found: {xml_path}")
    if xml_path.stat().st_size > MAX_XML_BYTES:
        raise ValueError(f"Nmap XML exceeds the {MAX_XML_BYTES // (1024 * 1024)} MiB safety limit")
    root = ET.parse(xml_path).getroot()
    if root.tag != "nmaprun":
        raise ValueError(f"Expected <nmaprun> root, found <{root.tag}>")
    hosts = []

    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        addresses = [
            {"addr": node.attrib.get("addr", ""), "type": node.attrib.get("addrtype", "")}
            for node in host_node.findall("address")
        ]
        hostnames = [
            node.attrib.get("name", "")
            for node in host_node.findall("./hostnames/hostname")
            if node.attrib.get("name")
        ]
        ports = []

        for port_node in host_node.findall("./ports/port"):
            try:
                port_number = int(port_node.attrib.get("portid", "0"))
            except (TypeError, ValueError):
                continue
            if not 1 <= port_number <= 65535:
                continue
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            ports.append(
                {
                    "protocol": port_node.attrib.get("protocol", ""),
                    "port": port_number,
                    "state": state_node.attrib.get("state", "unknown")
                    if state_node is not None
                    else "unknown",
                    "reason": state_node.attrib.get("reason", "") if state_node is not None else "",
                    "service": {
                        "name": service_node.attrib.get("name", "")
                        if service_node is not None
                        else "",
                        "product": service_node.attrib.get("product", "")
                        if service_node is not None
                        else "",
                        "version": service_node.attrib.get("version", "")
                        if service_node is not None
                        else "",
                        "extrainfo": service_node.attrib.get("extrainfo", "")
                        if service_node is not None
                        else "",
                        "tunnel": service_node.attrib.get("tunnel", "")
                        if service_node is not None
                        else "",
                    },
                }
            )

        host = {
            "id": "",
            "status": status_node.attrib.get("state", "unknown")
            if status_node is not None
            else "unknown",
            "addresses": addresses,
            "hostnames": hostnames,
            "ports": sorted(ports, key=lambda item: (item["protocol"], item["port"])),
        }
        host["id"] = primary_host_id(host)
        hosts.append(host)

    open_ports = sum(1 for host in hosts for port in host["ports"] if port["state"] == "open")
    return {
        "schema": SCHEMA_VERSION,
        "scanner": root.attrib.get("scanner", "nmap"),
        "nmap_version": root.attrib.get("version", ""),
        "xmloutputversion": root.attrib.get("xmloutputversion", ""),
        "started_at_epoch": root.attrib.get("start", ""),
        "raw_args": root.attrib.get("args", ""),
        "stats": {
            "hosts": len(hosts),
            "hosts_up": sum(1 for host in hosts if host["status"] == "up"),
            "open_ports": open_ports,
        },
        "hosts": hosts,
    }


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_observations(path: Path, report: dict) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for host in report["hosts"]:
            handle.write(
                json.dumps(
                    {
                        "schema": SCHEMA_VERSION,
                        "type": "host",
                        "host": host["id"],
                        "status": host["status"],
                        "addresses": host["addresses"],
                        "hostnames": host["hostnames"],
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            for port in host["ports"]:
                service_name = port["service"].get("name") or "unknown"
                handle.write(
                    json.dumps(
                        {
                            "schema": SCHEMA_VERSION,
                            "type": "service",
                            "host": host["id"],
                            "port": port["port"],
                            "protocol": port["protocol"],
                            "state": port["state"],
                            "service": port["service"],
                            "llm_hint": f"{host['id']} has {port['protocol']}/{port['port']} {port['state']} ({service_name})",
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )


def write_markdown(path: Path, report: dict) -> None:
    lines = [
        "# Nmap AI Report",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Scanner: `{report['scanner']} {report['nmap_version']}`",
        f"- Hosts: `{report['stats']['hosts']}`",
        f"- Hosts up: `{report['stats']['hosts_up']}`",
        f"- Open ports: `{report['stats']['open_ports']}`",
        "",
        "## Hosts",
        "",
    ]

    for host in report["hosts"]:
        lines.append(f"### {host['id']} ({host['status']})")
        if host["hostnames"]:
            lines.append(f"- Hostnames: {', '.join(host['hostnames'])}")
        open_ports = [port for port in host["ports"] if port["state"] == "open"]
        if not open_ports:
            lines.append("- Open ports: none observed")
            lines.append("")
            continue
        for port in open_ports:
            service = port["service"]
            label = service.get("name") or "unknown"
            product = " ".join(
                value for value in [service.get("product"), service.get("version")] if value
            )
            suffix = f" - {product}" if product else ""
            lines.append(f"- `{port['protocol']}/{port['port']}` {label}{suffix}")
        lines.append("")

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def create_artifacts(xml_path: Path, out_dir: Path, manifest_extra: dict = None) -> dict:
    report = parse_nmap_xml(xml_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    xml_copy = out_dir / "nmap.xml"
    if xml_path.resolve() != xml_copy.resolve():
        xml_copy.write_bytes(xml_path.read_bytes())

    hosts_path = out_dir / "hosts.json"
    observations_path = out_dir / "observations.jsonl"
    summary_path = out_dir / "summary.md"
    manifest_path = out_dir / "manifest.json"

    write_json(hosts_path, report)
    write_observations(observations_path, report)
    write_markdown(summary_path, report)

    manifest = {
        "schema": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "artifacts": {
            "raw_nmap_xml": str(xml_copy),
            "hosts_json": str(hosts_path),
            "observations_jsonl": str(observations_path),
            "summary_markdown": str(summary_path),
            "manifest_json": str(manifest_path),
        },
        "stats": report["stats"],
        "toolchain": {
            "nmap_version": nmap_version(),
            "dpkg": package_status(["nmap", "llm-tools-nmap", "python3"]),
            "apt_policy": {
                "nmap": apt_policy("nmap"),
                "llm-tools-nmap": apt_policy("llm-tools-nmap"),
            },
        },
    }
    if manifest_extra:
        manifest.update(manifest_extra)

    write_json(manifest_path, manifest)
    return manifest


def run_scan(args: argparse.Namespace) -> int:
    nmap_executable = shutil.which("nmap")
    if not nmap_executable:
        print(
            "nmap not found. On Kali: sudo apt update && sudo apt install -y nmap", file=sys.stderr
        )
        return 127

    reject_suspicious_target(args.target)
    scan_id = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out) / f"{scan_id}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', args.target)[:80]}"
    out_dir.mkdir(parents=True, exist_ok=True)

    xml_path = out_dir / "nmap.xml"
    normal_path = out_dir / "nmap.txt"
    command = [
        nmap_executable,
        *SCAN_PROFILES[args.profile],
        "--host-timeout",
        args.host_timeout,
        "--max-retries",
        str(args.max_retries),
    ]
    if args.ports:
        command.extend(["-p", args.ports])
    command.extend(["-oX", str(xml_path), "-oN", str(normal_path), args.target])

    try:
        completed = subprocess.run(
            command,
            check=False,
            timeout=args.scan_timeout,
        )
    except subprocess.TimeoutExpired:
        print(
            f"nmap exceeded the {args.scan_timeout}-second scan timeout",
            file=sys.stderr,
        )
        return 124
    if completed.returncode != 0:
        print(f"nmap exited with status {completed.returncode}", file=sys.stderr)
        return completed.returncode

    manifest = create_artifacts(
        xml_path,
        out_dir,
        {
            "scan": {
                "target": args.target,
                "profile": args.profile,
                "command": command,
                "normal_output": str(normal_path),
            }
        },
    )
    print(json.dumps({"manifest": manifest["artifacts"], "stats": manifest["stats"]}, indent=2))
    return 0


def parse_existing(args: argparse.Namespace) -> int:
    create_artifacts(Path(args.xml), Path(args.out), {"source": {"xml": args.xml}})
    print(f"Wrote AI-readable artifacts to {args.out}")
    return 0


def check_deps(_: argparse.Namespace) -> int:
    print(
        json.dumps(
            {
                "recommended_kali_install": "sudo apt update && sudo apt install -y nmap llm-tools-nmap",
                "nmap_version": nmap_version(),
                "dpkg": package_status(["nmap", "llm-tools-nmap", "python3"]),
                "apt_policy": {
                    "nmap": apt_policy("nmap"),
                    "llm-tools-nmap": apt_policy("llm-tools-nmap"),
                },
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run or parse Nmap into AI-readable artifacts.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    run_parser = subcommands.add_parser("run", help="Run nmap and generate artifacts")
    run_parser.add_argument("target")
    run_parser.add_argument("--profile", choices=sorted(SCAN_PROFILES), default="tcp")
    run_parser.add_argument(
        "--ports", help="Optional Nmap port expression, e.g. 22,80,443 or 1-1000"
    )
    run_parser.add_argument("--host-timeout", default="300s")
    run_parser.add_argument("--max-retries", type=int, default=2)
    run_parser.add_argument(
        "--scan-timeout",
        type=int,
        default=1800,
        help="Maximum total Nmap runtime in seconds (default: 1800)",
    )
    run_parser.add_argument("--out", default="ai_reports")
    run_parser.set_defaults(func=run_scan)

    parse_parser = subcommands.add_parser("parse", help="Parse an existing Nmap XML file")
    parse_parser.add_argument("xml")
    parse_parser.add_argument("--out", required=True)
    parse_parser.set_defaults(func=parse_existing)

    deps_parser = subcommands.add_parser("deps", help="Show Kali package provenance checks")
    deps_parser.set_defaults(func=check_deps)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
