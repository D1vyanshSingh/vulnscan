"""Async TCP connect scan with banner grabbing, TLS and HTTP probing."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
import tempfile
import time
import os
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = 2.5
MAX_BANNER = 4096
MAX_HTTP_BODY = 65536

# Ports that need a purpose-built payload to make the service talk.
PROBES: dict[int, bytes] = {
    25: b"EHLO vulnscan.local\r\n",
    587: b"EHLO vulnscan.local\r\n",
    6379: b"INFO server\r\n",     # redis: reveals version + auth state
    11211: b"stats\r\n",          # memcached
    2181: b"ruok\r\n",            # zookeeper
}

# Services that will never answer HTTP; skip the HTTP probe for them.
NON_HTTP_PORTS = {
    21, 22, 23, 25, 53, 110, 119, 135, 139, 143, 445, 512, 513, 514,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 6443, 11211,
    27017,
}

# Ports where an HTTP response is expected and worth trying first.
HTTP_PORTS = {
    80, 81, 591, 593, 2080, 2480, 3000, 4567, 5000, 5104, 5800, 6080,
    8000, 8008, 8080, 8081, 8083, 8088, 8090, 8180, 8280, 8888, 9000,
    9080, 9090, 9443, 16080, 18090, 28080,
}

# Well-known port → service name (used when the banner is inconclusive).
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "ms-sql-s", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 3000: "http", 3128: "squid",
    3306: "mysql", 3389: "ms-wbt", 4443: "https", 5000: "http",
    5432: "postgresql", 5672: "amqp", 5900: "vnc", 5985: "winrm",
    6379: "redis", 6443: "https", 7001: "http", 8000: "http", 8008: "http",
    8080: "http", 8081: "http", 8088: "http", 8443: "https", 8888: "http",
    9000: "http", 9090: "http", 9200: "http", 9300: "elasticsearch",
    9418: "git", 11211: "memcached", 15672: "http", 27017: "mongodb",
    50000: "db2",
}

# Banner/product/version fingerprints.
_SSH_RE = re.compile(r"SSH-[\d.]+-([A-Za-z0-9_.]+?)[_\s]?", re.IGNORECASE)
_FTP_RE = re.compile(r"\((vsFTPD|Pure-FTPd|ProFTPD|wu-ftpd)[ /]([0-9][\w.]+)", re.IGNORECASE)
_SMTP_RE = re.compile(r"^(?:\d{3}[ -].*?\s)?([A-Za-z][\w.-]*)\s([0-9][\w.]+)", re.IGNORECASE)
_MYSQL_RE = re.compile(r"^([\d]+(?:\.[\d]+){1,3})[-\w.]*")
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class PortService:
    """Result of probing one host:port."""
    host: str
    ip: str
    port: int
    state: str = "closed"            # open | closed | filtered
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    probe: str = ""                  # what we sent, if anything
    tls: dict | None = None
    http: dict | None = None
    scanned_at: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def http_service_name(self) -> str:
        return "https" if (self.tls or {}).get("ok") else "http"


def guess_service(port: int) -> str:
    return PORT_SERVICES.get(port, "")


def _decode_der_cert(der: bytes) -> dict:
    """Decode a DER certificate into Python's dict form (no verification)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(pem)
        return ssl._ssl._test_decode_cert(path) or {}
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _name_map(name_part) -> dict[str, str]:
    """Flatten a certificate name tuple into a key/value map.

    The nesting depth differs between Python versions and decode paths
    (e.g. ((('commonName', 'host'),),) vs (('commonName', 'host'),)),
    so flatten recursively and keep the last value per key.
    """
    out: dict[str, str] = {}

    def walk(nodes) -> None:
        for item in nodes or ():
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
                out[item[0]] = item[1]
            elif isinstance(item, tuple):
                walk(item)

    walk(name_part)
    return out


def summarize_cert(cert: dict, host: str) -> dict:
    """Turn a decoded certificate into the fields the report needs."""
    subject = tuple(cert.get("subject") or ())
    issuer = tuple(cert.get("issuer") or ())
    subject_map = _name_map(subject)
    issuer_map = _name_map(issuer)
    sans = [v for kind, v in (cert.get("subjectAltName") or ()) if kind == "DNS"]
    info: dict = {
        "subject": subject_map.get("commonName") or str(subject_map) or "",
        "issuer": issuer_map.get("commonName") or str(issuer_map) or "",
        "self_signed": subject_map == issuer_map or subject == issuer,
        "san": sans[:25],
        "not_before": cert.get("notBefore") or "",
        "not_after": cert.get("notAfter") or "",
    }
    now = time.time()
    try:
        end = ssl.cert_time_to_seconds(info["not_after"])
        start = ssl.cert_time_to_seconds(info["not_before"])
        info["days_remaining"] = int((end - now) // 86400)
        info["expired"] = now > end
        info["not_yet_valid"] = now < start
    except (ValueError, TypeError):
        info["days_remaining"] = None
        info["expired"] = False
        info["not_yet_valid"] = False
    info["hostname_matches"] = _hostname_matches(host, sans)
    return info


def _hostname_matches(host: str, sans: list[str]) -> bool | None:
    """Best-effort hostname check against SANs; None when undecidable."""
    if host.replace(".", "").isdigit():
        return None  # IP verification needs iPAddress SANs we did not parse
    if not sans:
        return None
    host = host.lower().rstrip(".")
    for san in sans:
        san = san.lower().rstrip(".")
        if san == host:
            return True
        if san.startswith("*.") and host.endswith(san[1:]) and host.count(".") == san.count("."):
            return True
    return False


async def probe_tls(host: str, port: int, timeout: float) -> dict:
    """Attempt a TLS handshake; returns protocol and certificate details."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout)
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    try:
        sslobj = writer.get_extra_info("ssl_object")
        cipher = sslobj.cipher()
        info: dict = {
            "ok": True,
            "version": sslobj.version() or "",
            "cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher else 0,
        }
        der = sslobj.getpeercert(binary_form=True)
        if der:
            info["cert"] = summarize_cert(_decode_der_cert(der), host)
        return info
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def supports_tls_version(host: str, port: int, version: ssl.TLSVersion,
                               timeout: float) -> bool:
    """True when the service completes a handshake pinned to one TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError, AttributeError):
        return False
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), min(timeout, 2.0))
    except Exception:
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return True


async def grab_banner(host: str, port: int, timeout: float) -> tuple[str, str]:
    """Read the service's opening line. Returns (banner, what_was_sent)."""
    probe = PROBES.get(port)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return "", "connect-timeout"
    except Exception as exc:
        return "", f"connect-failed ({type(exc).__name__})"
    try:
        if probe:
            writer.write(probe)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(MAX_BANNER), timeout)
        text = data.decode("latin-1", "replace").strip()
        return text[:1024], probe.decode("latin-1", "replace").strip() if probe else ""
    except asyncio.TimeoutError:
        return "", probe.decode("latin-1", "replace").strip() if probe else ""
    except Exception as exc:
        return "", f"read-failed ({type(exc).__name__})"
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def send_recv(host: str, port: int, payload: bytes, timeout: float,
                    rounds: int = 1) -> str:
    """Send payloads and return the concatenated response text (for checks)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except Exception:
        return ""
    chunks: list[str] = []
    try:
        for _ in range(max(1, rounds)):
            writer.write(payload)
            await writer.drain()
            await asyncio.sleep(0.3)      # let multi-line replies fully arrive
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(MAX_BANNER), 0.6)
                    if not data:
                        break
                    chunks.append(data.decode("latin-1", "replace"))
            except asyncio.TimeoutError:
                pass
            break
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return "".join(chunks)[:2048]


async def http_fetch(host: str, port: int, scheme: str, timeout: float,
                     path: str = "/") -> dict | None:
    """Issue a single HTTP GET and parse status, headers, title and a snippet."""
    ctx = None
    if scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            host, port, ssl=ctx,
            server_hostname=host if ctx is not None else None), timeout)
    except Exception:
        return None
    try:
        host_hdr = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = 443 if scheme == "https" else 80
        authority = host_hdr if port == default_port else f"{host_hdr}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: vulnscan/0.1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode("latin-1"))
        await writer.drain()
        raw = await _read_response(reader, timeout)
    except Exception:
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    if not raw:
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0].startswith(b"HTTP/"):
        return None
    try:
        parts = lines[0].decode("latin-1", "replace").split()
        status = int(parts[1]) if len(parts) > 1 else 0
        reason = parts[2] if len(parts) > 2 else ""
    except (ValueError, IndexError):
        status, reason = 0, ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        key_s = key.decode("latin-1", "replace").strip().lower()
        value_s = value.decode("latin-1", "replace").strip()
        headers[key_s] = f"{headers[key_s]}, {value_s}" if key_s in headers else value_s
    title = ""
    match = _TITLE_RE.search(body)
    if match:
        title = match.group(1).decode("utf-8", "replace").strip()[:200]
    return {
        "scheme": scheme,
        "path": path,
        "status": status,
        "reason": reason,
        "headers": headers,
        "server": headers.get("server", ""),
        "powered_by": headers.get("x-powered-by", ""),
        "title": title,
        "location": headers.get("location", ""),
        "content_type": headers.get("content-type", ""),
        "body_preview": body[:4000].decode("utf-8", "replace"),
        "body_length": len(body),
    }


async def _read_response(reader: asyncio.StreamReader, timeout: float) -> bytes:
    """Read until the server closes, we time out, or we hit the size cap."""
    buffer = bytearray()
    deadline = time.monotonic() + timeout
    while len(buffer) < MAX_HTTP_BODY:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(8192, MAX_HTTP_BODY - len(buffer))), remaining)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        buffer.extend(chunk)
        # Headers complete → short grace period for the body only.
        if b"\r\n\r\n" in buffer and deadline - time.monotonic() > timeout / 2:
            deadline = min(deadline, time.monotonic() + max(0.4, timeout / 2))
    return bytes(buffer)


def _extract_product(service: str, banner: str, http: dict | None) -> tuple[str, str]:
    """Pull (product, version) out of a banner or HTTP headers."""
    # FTP server fingerprints — match wherever they appear in the banner.
    match = _FTP_RE.search(banner)
    if match:
        return match.group(1), match.group(2)
    if not banner:
        if http and http.get("server"):
            server = http["server"]
            return _split_server(server)
        return "", ""
    if service == "ssh":
        match = _SSH_RE.search(banner)
        if match:
            token = match.group(1)
            name, _, version = token.partition("_")
            return name, version
    if service == "ftp":
        match = _FTP_RE.search(banner)
        if match:
            return match.group(1), match.group(2)
    if service in ("smtp", "submission", "smtps"):
        first = banner.splitlines()[0] if banner else ""
        match = _SMTP_RE.match(first)
        if match and match.group(1).lower() not in {"220"}:
            return match.group(1), match.group(2)
        m2 = re.search(r"\b(Postfix|Exim|sendmail|Exchange)\b[ /]?([\d.]+)?", first, re.IGNORECASE)
        if m2:
            return m2.group(1), m2.group(2) or ""
    if service == "mysql":
        match = _MYSQL_RE.match(banner)
        if match and "mysql" in banner.lower():
            return "MySQL", match.group(1)
    if service == "redis" and "redis_version" in banner:
        match = re.search(r"redis_version:([\d.]+)", banner)
        if match:
            return "Redis", match.group(1)
    if service == "memcached" and "STAT version" in banner:
        match = re.search(r"STAT version ([\w.]+)", banner)
        if match:
            return "Memcached", match.group(1)
    if http and http.get("server"):
        return _split_server(http["server"])
    if banner.startswith("HTTP/"):
        return "", ""
    return "", ""


def _split_server(server: str) -> tuple[str, str]:
    """'nginx/1.18.0 (Ubuntu)' → ('nginx', '1.18.0')."""
    server = server.strip()
    match = re.match(r"([A-Za-z0-9._+-]+)[/ ]([0-9][\w.]*)", server)
    if match:
        return match.group(1), match.group(2)
    return server.split()[0] if server.split() else "", ""


async def probe_port(host: str, ip: str, port: int, timeout: float) -> PortService:
    """Full probe of a single host:port: connect, TLS, banner, HTTP."""
    svc = PortService(host=host, ip=ip, port=port,
                      scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except asyncio.TimeoutError:
        svc.state = "filtered"
        return svc
    except (ConnectionRefusedError, OSError):
        svc.state = "closed"
        return svc
    svc.state = "open"

    svc.tls = await probe_tls(ip, port, timeout)
    tls_ok = bool(svc.tls.get("ok"))

    if not tls_ok:
        svc.banner, svc.probe = await grab_banner(ip, port, timeout)
    else:
        svc.probe = svc.tls.get("version", "")

    scheme = "https" if tls_ok else "http"
    wants_http = (port in HTTP_PORTS or (not svc.banner and port not in NON_HTTP_PORTS)
                  or svc.banner.startswith("HTTP/"))
    if wants_http and port not in NON_HTTP_PORTS:
        svc.http = await http_fetch(ip, port, scheme, timeout)
        if svc.http is None and not tls_ok and port in HTTP_PORTS:
            # Plain failed on a web-ish port — try TLS before giving up.
            alt = await probe_tls(ip, port, timeout)
            if alt.get("ok"):
                svc.tls = alt
                tls_ok = True
                svc.http = await http_fetch(ip, port, "https", timeout)

    svc.service = guess_service(port)
    if svc.http:
        svc.service = "https" if tls_ok else svc.http_service_name()
    svc.product, svc.version = _extract_product(svc.service, svc.banner, svc.http)
    if not svc.service and svc.banner:
        lowered = svc.banner.lower()
        for token, name in (("ssh-", "ssh"), ("220", "ftp/smtp"), ("rfb ", "vnc"),
                            ("+pong", "redis"), ("vsftpd", "ftp"),
                            ("proftpd", "ftp"), ("pure-ftpd", "ftp")):
            if token in lowered:
                svc.service = name
                break
    return svc


async def run_scan(hosts: list[str], ports: list[int], timeout: float = DEFAULT_TIMEOUT,
                   concurrency: int = 256,
                   progress=None) -> list[PortService]:
    """Scan every host × port with a bounded concurrency budget."""
    ip_cache: dict[str, str] = {}
    for host in hosts:
        if host in ip_cache:
            continue
        try:
            ip_cache[host] = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
        except OSError:
            ip_cache[host] = host
    total = len(hosts) * len(ports)
    semaphore = asyncio.Semaphore(concurrency)
    done = 0

    async def _one(host: str, port: int) -> PortService:
        nonlocal done
        async with semaphore:
            result = await probe_port(host, ip_cache[host], port, timeout)
        done += 1
        if progress and (done % 25 == 0 or done == total):
            progress(done, total, result)
        return result

    tasks = [_one(host, port) for host in hosts for port in ports]
    results = await asyncio.gather(*tasks)
    open_services = [r for r in results if r.state == "open"]
    open_services.sort(key=lambda r: (r.host, r.port))
    return open_services
