import ipaddress
import re

import nmap
from flask import current_app


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"\.)*"
    r"[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def validate_target(target: str) -> str:
    target = (target or "").strip()

    if not target:
        raise ValueError("Target is required.")

    # Accept IP addresses, CIDR networks and normal DNS hostnames.
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    if not _HOSTNAME_RE.fullmatch(target):
        raise ValueError(
            "Invalid target. Enter an IP address, CIDR range, or hostname."
        )

    return target


def run_nmap_scan(target: str):
    """Perform service/version discovery only; PwnTrace never executes exploits."""
    target = validate_target(target)

    scanner = nmap.PortScanner()

    scanner.scan(
        hosts=target,
        arguments="-sV --top-ports 100 --open --reason",
        timeout=current_app.config["NMAP_TIMEOUT"],
    )

    results = []

    for host in scanner.all_hosts():
        host_data = scanner[host]

        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                service = host_data[proto][port]

                results.append(
                    {
                        "host": host,
                        "protocol": proto,
                        "port": int(port),
                        "state": service.get("state"),
                        "service": service.get("name") or "unknown",
                        "product": service.get("product") or "",
                        "version": service.get("version") or "",
                        "extrainfo": service.get("extrainfo") or "",
                        "reason": service.get("reason") or "",
                    }
                )

    return results
