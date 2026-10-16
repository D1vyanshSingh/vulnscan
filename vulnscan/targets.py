"""Parsing of target specs (hosts, CIDR) and port specs (lists, ranges)."""

from __future__ import annotations

import ipaddress
import re

# Default port set: common services worth checking on a single host.
COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 587, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049,
    2181, 2375, 2376, 3000, 3128, 3306, 3389, 4443, 5000, 5432, 5601,
    5672, 5900, 5985, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8088,
    8443, 8888, 9000, 9090, 9200, 9300, 9418, 11211, 15672, 27017, 50000,
]

MAX_HOSTS = 1024
MAX_PORTS = 65535

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                          r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


class SpecError(ValueError):
    """Raised for an unparseable target or port specification."""


def parse_targets(specs: list[str]) -> list[str]:
    """Expand hostnames, IPs and CIDR ranges into a deduplicated host list."""
    hosts: list[str] = []
    for raw in specs:
        for item in raw.split(","):
            spec = item.strip()
            if not spec:
                continue
            if "/" in spec:
                try:
                    network = ipaddress.ip_network(spec, strict=False)
                except ValueError as exc:
                    raise SpecError(f"invalid network {spec!r}: {exc}") from exc
                if network.version == 6:
                    addresses = [str(network.network_address)]
                    if addresses == [str(spec)]:
                        raise SpecError(f"IPv6 range too large: {spec!r}")
                else:
                    if network.num_addresses > MAX_HOSTS:
                        raise SpecError(
                            f"{spec!r} has {network.num_addresses} addresses "
                            f"(max {MAX_HOSTS}); narrow the range")
                    hosts.extend(str(ip) for ip in network.hosts())
                continue
            try:
                ipaddress.ip_address(spec)
                hosts.append(spec)
                continue
            except ValueError:
                pass
            if _HOSTNAME_RE.match(spec):
                hosts.append(spec)
            else:
                raise SpecError(f"invalid target {spec!r}")
    seen: set[str] = set()
    unique: list[str] = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            unique.append(host)
    if not unique:
        raise SpecError("no targets given")
    if len(unique) > MAX_HOSTS:
        raise SpecError(f"too many targets ({len(unique)}); max {MAX_HOSTS}")
    return unique


def parse_ports(spec: str | None) -> list[int]:
    """Parse a port spec: 'top' (default set), 'all', or '22,80,8000-8100'."""
    if spec is None or spec.strip() == "" or spec.strip().lower() == "top":
        return sorted(COMMON_PORTS)
    spec = spec.strip().lower()
    if spec == "all":
        return list(range(1, MAX_PORTS + 1))
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError as exc:
                raise SpecError(f"invalid port range {chunk!r}") from exc
            if not (1 <= start <= end <= MAX_PORTS):
                raise SpecError(f"port range out of bounds: {chunk!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise SpecError(f"invalid port {chunk!r}") from exc
            if not 1 <= port <= MAX_PORTS:
                raise SpecError(f"port out of range: {port}")
            ports.add(port)
    if not ports:
        raise SpecError("no ports selected")
    return sorted(ports)
