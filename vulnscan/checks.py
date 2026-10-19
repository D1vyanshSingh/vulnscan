"""Vulnerability checks: exposure, TLS, HTTP config, and version fingerprints."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .scanner import PORT_SERVICES, PortService, http_fetch, send_recv

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

CITATION = "https://cwe.mitre.org/data/definitions/{n}.html"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    impact: str
    evidence: str
    remediation: str
    asset: dict
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    status: str = "open"
    id: str = ""

    @property
    def sort_key(self) -> int:
        return SEVERITY_ORDER.index(self.severity) if self.severity in SEVERITY_ORDER else 99


def _asset(svc: PortService, path: str = "") -> dict:
    asset = {
        "host": svc.host,
        "ip": svc.ip,
        "port": svc.port,
        "protocol": "tcp",
        "service": svc.service or "",
    }
    if path:
        scheme = "https" if (svc.tls or {}).get("ok") else "http"
        asset["url"] = f"{scheme}://{svc.host}:{svc.port}{path}"
    return asset


def _ref(*urls: str) -> list[str]:
    return list(urls)


def _cwe(*numbers: int) -> list[str]:
    return [f"CWE-{n}" for n in numbers]


# --------------------------------------------------------------------------
# 1. Exposed-service checks (port/banner based)
# --------------------------------------------------------------------------

# rule_id, title, severity, cwe, description, impact, remediation
EXPOSURE_RULES: dict[int, tuple] = {
    23: ("VS-EXP-TELNET", "Telnet service exposed", "high", _cwe(319, 284),
         "A Telnet service is reachable on this host. Telnet transmits credentials "
         "and session data, including passwords, in cleartext.",
         "Anyone able to reach this port can capture credentials with a passive "
         "sniffer and may gain interactive shell access to the system.",
         "Disable Telnet and use SSH instead. If Telnet must stay, restrict it to a "
         "management network with firewall rules."),
    2323: ("VS-EXP-TELNET-ALT", "Telnet service exposed on alternate port", "high",
           _cwe(319, 284),
           "A Telnet service is reachable on a non-standard port. Telnet transmits "
           "credentials and session data in cleartext.",
           "Cleartext credentials can be captured by anyone on the network path, and "
           "an interactive shell may be available to remote attackers.",
           "Remove the service or replace it with SSH; restrict management ports to "
           "a trusted network."),
    3389: ("VS-EXP-RDP", "Remote Desktop (RDP) exposed to the network", "high",
           _cwe(284, 20),
           "The Microsoft Remote Desktop service is reachable from the scan source. "
           "Exposed RDP is a frequent target of brute-force attacks and credential "
           "stuffing, and was the primary vector for wormable flaws such as BlueKeep.",
           "Compromise of a workstation or server via guessed or reused credentials, "
           "leading to full user-session control and potential domain impact.",
           "Restrict RDP to a VPN or management network with firewall rules, enforce "
           "NLA, and disable direct internet exposure."),
    445: ("VS-EXP-SMB", "SMB file sharing exposed to the network", "high",
          _cwe(284, 319),
          "SMB (port 445) is reachable from the scan source. Exposed SMB exposes file "
          "shares to brute-force and exploitation attempts, and SMBv1 in particular "
          "is vulnerable to wormable flaws such as EternalBlue (CVE-2017-0144).",
          "Unauthorized access to shared files and directories, credential relay "
          "attacks, or remote code execution when SMBv1 is enabled.",
          "Block ports 445/139 at the perimeter, require VPN access for file sharing, "
          "and disable SMBv1."),
    5900: ("VS-EXP-VNC", "VNC service exposed to the network", "high",
           _cwe(319, 284),
           "A VNC service is reachable from the scan source. VNC streams the remote "
           "desktop in cleartext unless tunneled, and many deployments run without "
           "authentication or with passwords that are trivial to guess.",
           "A remote attacker can observe or take over the desktop session, gaining "
           "the same access as the logged-in user.",
           "Expose VNC only over an SSH or TLS tunnel, require strong passwords, and "
           "firewall the port to trusted hosts."),
    5901: ("VS-EXP-VNC", "VNC service exposed to the network", "high",
           _cwe(319, 284),
           "A VNC service is reachable from the scan source. VNC streams the remote "
           "desktop in cleartext unless tunneled, and many deployments run without "
           "authentication or with passwords that are trivial to guess.",
           "A remote attacker can observe or take over the desktop session.",
           "Expose VNC only over an SSH or TLS tunnel, require strong passwords, and "
           "firewall the port to trusted hosts."),
    2376: ("VS-EXP-DOCKER-TLS", "Docker daemon API exposed with TLS", "high",
           _cwe(306, 284),
           "The Docker daemon API is reachable over the network with TLS enabled. "
           "Anyone who can authenticate to it controls containers on this host.",
           "Full control of containers and images, container escape potential, and "
           "host-level compromise via privileged containers or mounted host paths.",
           "Restrict the Docker socket to localhost or a trusted management network "
           "and use client-certificate authentication."),
    10250: ("VS-EXP-KUBELET", "Kubelet API exposed to the network", "high",
            _cwe(306, 284),
            "The Kubernetes kubelet API (10250) is reachable from the scan source. "
            "Unauthenticated kubelet APIs allow listing and exec-ing into pods.",
            "Container takeover, secret theft from pod environments, and lateral "
            "movement inside the cluster.",
            "Enable kubelet authentication (--anonymous-auth=false) and restrict "
            "10250 to cluster-internal traffic."),
    2379: ("VS-EXP-ETCD", "etcd API exposed to the network", "high",
           _cwe(306, 284),
           "The etcd key-value store used by Kubernetes is reachable from the scan "
           "source. Unauthenticated etcd holds all cluster state including secrets.",
           "Read and write access to every secret in the cluster, enabling full "
           "cluster takeover.",
           "Bind etcd to localhost, require client certificates, and firewall the "
           "port."),
    3306: ("VS-EXP-MYSQL", "MySQL server exposed to the network", "medium",
           _cwe(284),
           "The MySQL listener is reachable from the scan source, so the database "
           "accepts connection attempts from hosts outside its own network.",
           "Database credentials become subject to brute-force and known server "
           "exploits from any reachable host.",
           "Bind MySQL to localhost or restrict port 3306 to application servers with "
           "firewall rules."),
    5432: ("VS-EXP-POSTGRES", "PostgreSQL server exposed to the network", "medium",
           _cwe(284),
           "The PostgreSQL listener is reachable from the scan source, so the "
           "database accepts connection attempts from outside its own network.",
           "Database credentials become subject to brute-force and known server "
           "exploits from any reachable host.",
           "Bind PostgreSQL to localhost or restrict port 5432 to application servers "
           "with firewall rules."),
    1433: ("VS-EXP-MSSQL", "MS SQL Server exposed to the network", "medium",
           _cwe(284),
           "The MS SQL Server listener is reachable from the scan source.",
           "Database credentials become subject to brute-force and known server "
           "exploits from any reachable host.",
           "Restrict port 1433 to trusted application servers and disable remote "
           "sa logins."),
    1521: ("VS-EXP-ORACLE", "Oracle TNS listener exposed to the network", "medium",
           _cwe(284),
           "The Oracle TNS listener is reachable from the scan source.",
           "Database credentials become subject to brute-force and listener exploits "
           "from any reachable host.",
           "Restrict port 1521 to trusted networks and enable Valid Node Checking."),
    5985: ("VS-EXP-WINRM", "WinRM service exposed over cleartext HTTP", "high",
           _cwe(319, 284),
           "Windows Remote Management (HTTP) is reachable from the scan source. "
           "WinRM over HTTP sends credentials and shell traffic unencrypted.",
           "Credential theft and remote shell access to the Windows host.",
           "Require WinRM over HTTPS (5986) with Kerberos, and firewall port 5985."),
    15672: ("VS-EXP-RABBITMQ", "RabbitMQ management console exposed", "medium",
            _cwe(284, 200),
            "The RabbitMQ management interface is reachable from the scan source. "
            "Internet-facing management consoles are routinely brute-forced.",
            "Exposure of message queues, credentials and routing topology, plus the "
            "ability to publish or consume messages.",
            "Bind the management plugin to localhost or restrict it to an admin "
            "network with strong credentials."),
    5601: ("VS-EXP-KIBANA", "Kibana dashboard exposed to the network", "medium",
           _cwe(284, 200),
           "Kibana is reachable from the scan source. Without authentication it "
           "discovers and visualizes the contents of the Elasticsearch index.",
           "Exposure of indexed data such as logs, user records or business data.",
           "Place Kibana behind authentication and restrict it to an internal "
           "network."),
    2049: ("VS-EXP-NFS", "NFS file sharing exposed to the network", "medium",
           _cwe(284),
           "The NFS service is reachable from the scan source.",
           "Unauthorized mounts and reads of exported filesystems, subject to "
           "client-side export and uid-mapping weaknesses.",
           "Restrict exports with squash options and firewall port 2049 to trusted "
           "hosts."),
    873: ("VS-EXP-RSYNC", "rsync daemon exposed to the network", "medium",
          _cwe(284, 319),
          "The rsync daemon is reachable from the scan source and often allows "
          "anonymous reads of configured modules.",
          "Read (and sometimes write) access to synced directories and disclosure of "
          "sensitive files.",
          "Disable the rsync daemon where unused, require auth, and firewall the "
          "port."),
    6443: ("VS-EXP-K8S-API", "Kubernetes API server exposed", "informational",
           _cwe(284),
           "The Kubernetes API server is reachable from the scan source. Exposure is "
           "expected for managed clusters, but unauthenticated endpoints should be "
           "audited.",
           "Anonymous or stolen-credential access to cluster resources if RBAC "
           "misconfigures anonymous-auth endpoints.",
           "Verify anonymous-auth is disabled and API access is gated by network "
           "policy."),
    9090: ("VS-EXP-PROMETHEUS", "Prometheus metrics endpoint exposed", "low",
           _cwe(200),
           "A Prometheus metrics endpoint is reachable from the scan source. Metrics "
           "often include hostnames, process lists and internal service names.",
           "Internal topology and host details become visible to an attacker "
           "scanning from outside.",
           "Restrict metrics endpoints to an internal monitoring network or require "
           "authentication."),
    9201: ("VS-EXP-ADMIN", "Administrative service on a public interface", "low",
           _cwe(284),
           "A service commonly used for administration is reachable from the scan "
           "source.",
           "Administrative interfaces facing untrusted networks are prime brute-force "
           "and exploit targets.",
           "Move administrative services behind a VPN or management network."),
}


def check_exposure(svc: PortService) -> list[Finding]:
    findings: list[Finding] = []
    rule = EXPOSURE_RULES.get(svc.port)
    if rule:
        rule_id, title, severity, cwe, desc, impact, fix = rule
        findings.append(Finding(
            rule_id=rule_id, title=title, severity=severity, confidence="firm",
            description=desc, impact=impact,
            evidence=_banner_evidence(svc),
            remediation=fix, asset=_asset(svc),
            cwe=cwe, references=_ref(CITATION.format(n=cwe[0].split("-")[1]))))

    # Services whose checks depend on probe evidence (banner / HTTP status).
    if svc.port == 6379:
        findings.extend(_check_redis(svc))
    else:
        findings.extend(_check_special_service(svc))
    return findings


def _banner_evidence(svc: PortService) -> str:
    if svc.banner:
        return f"Port {svc.port}/tcp is open and identified as " \
               f"{svc.service or 'unknown service'}. Banner: {svc.banner[:300]!r}"
    return f"Port {svc.port}/tcp is open and identified as " \
           f"{svc.service or PORT_SERVICES.get(svc.port, 'a service')}."


def _check_redis(svc: PortService) -> list[Finding]:
    banner = svc.banner or ""
    if "redis_version" in banner:
        return [Finding(
            rule_id="VS-EXP-REDIS-NOAUTH",
            title="Redis exposed without authentication",
            severity="critical", confidence="certain",
            description="The INFO command returned server details without requiring "
                        "authentication, confirming that this Redis instance accepts "
                        "commands from unauthenticated clients.",
            impact="Full read and write access to cached data, session tokens and "
                   "job queues. Crafted payloads can lead to remote code execution "
                   "via CONFIG SET and module loading.",
            evidence=f"INFO server response (no AUTH required): {banner[:300]!r}",
            remediation="Set 'requirepass' (or ACL users), bind Redis to trusted "
                        "interfaces only, and firewall port 6379.",
            asset=_asset(svc), cwe=_cwe(306),
            references=_ref(CITATION.format(n=306),
                            "https://redis.io/docs/latest/operate/oss_and_stack/"
                            "management/security/"))]
    if "NOAUTH" in banner or "authentication required" in banner.lower():
        return [Finding(
            rule_id="VS-EXP-REDIS-AUTH",
            title="Redis reachable from the network",
            severity="medium", confidence="firm",
            description="A Redis instance is reachable from the scan source and "
                        "requires authentication (the INFO command was rejected).",
            impact="The instance is exposed to password-guessing attacks; weak or "
                   "default passwords would give access to cached data and queues.",
            evidence=f"INFO server response: {banner[:300]!r}",
            remediation="Bind Redis to localhost or a private network and firewall "
                        "port 6379 even when authentication is enabled.",
            asset=_asset(svc), cwe=_cwe(284),
            references=_ref(CITATION.format(n=284)))]
    return [Finding(
        rule_id="VS-EXP-REDIS", title="Redis reachable from the network",
        severity="medium", confidence="tentative",
        description="Port 6379 is open and responded like Redis, but the banner did "
                    "not reveal whether authentication is required.",
        impact="If authentication is absent or weak, cached data and session tokens "
               "are readable and writable by remote clients.",
        evidence=_banner_evidence(svc),
        remediation="Set 'requirepass', bind to trusted interfaces, and firewall "
                    "port 6379.",
        asset=_asset(svc), cwe=_cwe(306),
        references=_ref(CITATION.format(n=306)))]


def _check_special_service(svc: PortService) -> list[Finding]:
    """Checks that need the probe evidence collected during scanning.

    Only fires for ports whose finding depends on probe evidence; everything
    else returned [] means no applicable rule for this port.
    """
    banner = svc.banner or ""
    if svc.port == 11211:
        if "STAT " in banner:
            return [Finding(
                rule_id="VS-EXP-MEMCACHED-NOAUTH",
                title="Memcached exposed without authentication",
                severity="critical", confidence="certain",
                description="The memcached stats command returned server statistics "
                            "without authentication, confirming unauthenticated access.",
                impact="Read/write access to cached objects (sessions, tokens), plus "
                       "historical use of memcached for UDP amplification DDoS.",
                evidence=f"stats response: {banner[:300]!r}",
                remediation="Disable UDP listeners (-U 0), bind to localhost, set "
                            "'-A' access control, and firewall port 11211.",
                asset=_asset(svc), cwe=_cwe(306),
                references=_ref(CITATION.format(n=306)))]
        return [Finding(
            rule_id="VS-EXP-MEMCACHED", title="Memcached reachable from the network",
            severity="medium", confidence="firm",
            description="A memcached listener is reachable from the scan source.",
            impact="Cached sessions or tokens may be readable, and UDP exposure can "
                   "abuse the service for amplification attacks.",
            evidence=_banner_evidence(svc),
            remediation="Bind memcached to localhost, disable UDP, and firewall the "
                        "port.",
            asset=_asset(svc), cwe=_cwe(306), references=_ref(CITATION.format(n=306)))]
    if svc.port == 2375:
        return [Finding(
            rule_id="VS-EXP-DOCKER", title="Docker daemon API exposed without TLS",
            severity="critical", confidence="firm",
            description="The Docker daemon API is reachable over plain HTTP on port "
                        "2375. Anyone who can reach it fully controls the Docker "
                        "daemon on this host.",
            impact="Remote code execution: an attacker can start a privileged "
                   "container, mount the host filesystem, and take over the machine.",
            evidence=_banner_evidence(svc),
            remediation="Disable the plain-HTTP Docker socket (-H fd:// without "
                        "tcp:// binding), require TLS on 2376, and firewall the port.",
            asset=_asset(svc), cwe=_cwe(306), references=_ref(CITATION.format(n=306)))]
    if svc.port == 27017:
        return [Finding(
            rule_id="VS-EXP-MONGODB", title="MongoDB exposed to the network",
            severity="high", confidence="firm",
            description="The MongoDB listener is reachable from the scan source. "
                        "Unauthenticated MongoDB instances are scanned and exploited "
                        "within minutes of being exposed.",
            impact="Read and write access to the entire database; historically the "
                   "most common cause of large cloud data leaks.",
            evidence=_banner_evidence(svc),
            remediation="Enable authorization (security.authorization: enabled), bind "
                        "to trusted interfaces, and firewall port 27017.",
            asset=_asset(svc), cwe=_cwe(306), references=_ref(CITATION.format(n=306)))]
    if svc.port == 21:
        return []  # covered by the anonymous-FTP check
    return []


async def check_ftp_anonymous(services: list[PortService], timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    for svc in services:
        if svc.state != "open" or not (svc.port == 21 or svc.service == "ftp"
                                       or "vsftpd" in svc.banner.lower()
                                       or "Multicraft" in svc.banner):
            continue
        response = await send_recv(
            svc.ip, svc.port, b"USER anonymous\r\nPASS guest@vulnscan.local\r\n",
            timeout)
        if re.search(r"\b230\b", response):
            findings.append(Finding(
                rule_id="VS-FTP-ANON",
                title="Anonymous FTP login allowed", severity="high",
                confidence="certain",
                description="The FTP server accepted an anonymous login, letting any "
                            "unauthenticated client list and transfer files.",
                impact="Unauthorized read (and on misconfigured sites, write) access "
                       "to every file in the public tree, including backups or "
                       "credentials left there.",
                evidence=f"USER anonymous → server replied: {response[:300]!r}",
                remediation="Set 'anon_enable=NO' in the FTP configuration, or "
                            "restrict anonymous accounts to a read-only empty jail.",
                asset=_asset(svc), cwe=_cwe(22, 306),
                references=_ref(CITATION.format(n=306))))
        if svc.port == 21 or svc.service == "ftp":
            findings.append(Finding(
                rule_id="VS-FTP-CLEARTEXT",
                title="FTP credentials sent in cleartext", severity="low",
                confidence="certain",
                description="The FTP service exchanges usernames and "
                            "passwords without encryption (no TLS observed).",
                impact="Credentials can be captured by anyone able to observe "
                       "traffic on the network path.",
                evidence=f"Port {svc.port} open. Banner: {svc.banner[:200]!r}",
                remediation="Require FTPS (explicit TLS) or replace FTP with SFTP.",
                asset=_asset(svc), cwe=_cwe(319),
                references=_ref(CITATION.format(n=319))))
    return findings


# --------------------------------------------------------------------------
# 2. TLS certificate and protocol checks
# --------------------------------------------------------------------------

def check_tls(svc: PortService, legacy_versions: dict | None = None) -> list[Finding]:
    tls = svc.tls or {}
    if not tls.get("ok"):
        return []
    findings: list[Finding] = []
    cert = tls.get("cert") or {}

    if cert.get("expired"):
        findings.append(Finding(
            rule_id="VS-TLS-EXPIRED", title="TLS certificate has expired",
            severity="high", confidence="certain",
            description="The presented certificate is past its notAfter date, so "
                        "clients reject the connection as untrusted.",
            impact="Users see a security warning, and automated clients fail; an "
                   "expired cert on an HTTPS endpoint often signals an abandoned or "
                   "unmonitored system.",
            evidence=f"Subject {cert.get('subject')!r}, issuer {cert.get('issuer')!r}, "
                     f"expired {cert.get('not_after')!r}.",
            remediation="Renew the certificate and automate renewal before expiry.",
            asset=_asset(svc), cwe=_cwe(295),
            references=_ref(CITATION.format(n=295))))
    elif cert.get("not_yet_valid"):
        findings.append(Finding(
            rule_id="VS-TLS-NOT-YET-VALID", title="TLS certificate is not yet valid",
            severity="medium", confidence="certain",
            description="The certificate's notBefore date is in the future, usually "
                        "caused by clock skew or a misconfigured deployment.",
            impact="Clients reject the connection until the clock or certificate is "
                   "corrected.",
            evidence=f"Valid from {cert.get('not_before')!r}.",
            remediation="Check host clock sync (NTP) and redeploy the certificate.",
            asset=_asset(svc), cwe=_cwe(295),
            references=_ref(CITATION.format(n=295))))
    else:
        days = cert.get("days_remaining")
        if isinstance(days, int) and days < 14:
            findings.append(Finding(
                rule_id="VS-TLS-EXPIRING", title="TLS certificate expires soon",
                severity="medium", confidence="certain",
                description=f"The certificate expires in {days} day(s); "
                            "once expired, clients will refuse the connection.",
                impact="Service outage for TLS clients once the certificate lapses.",
                evidence=f"notAfter {cert.get('not_after')!r} ({days} days remaining).",
                remediation="Renew the certificate now and automate renewal.",
                asset=_asset(svc), cwe=_cwe(295),
                references=_ref(CITATION.format(n=295))))

    if cert.get("self_signed"):
        findings.append(Finding(
            rule_id="VS-TLS-SELF-SIGNED", title="Self-signed TLS certificate",
            severity="low", confidence="certain",
            description="The certificate is signed by its own subject rather than a "
                        "trusted certificate authority, so clients cannot establish "
                        "trust in the server's identity.",
            impact="Browsers warn users, training them to click through warnings; "
                   "man-in-the-middle attacks become indistinguishable from the "
                   "legitimate certificate.",
            evidence=f"Subject {cert.get('subject')!r} == issuer {cert.get('issuer')!r}.",
            remediation="Issue the certificate from a trusted CA (Let's Encrypt is "
                        "free) or add the internal CA to trusted stores.",
            asset=_asset(svc), cwe=_cwe(295),
            references=_ref(CITATION.format(n=295))))

    if cert.get("hostname_matches") is False:
        findings.append(Finding(
            rule_id="VS-TLS-HOSTNAME", title="Certificate does not match the hostname",
            severity="medium", confidence="firm",
            description="None of the certificate's subject alternative names cover "
                        "the scanned host, so clients fail hostname verification.",
            impact="TLS clients reject the connection; if users bypass the warning, "
                   "the connection may be a spoof.",
            evidence=f"Scanned host {svc.host!r}; SANs {cert.get('san')!r}.",
            remediation="Reissue the certificate including this host in the SAN list.",
            asset=_asset(svc), cwe=_cwe(295),
            references=_ref(CITATION.format(n=295))))

    cipher = (tls.get("cipher") or "").upper()
    if any(token in cipher for token in ("NULL", "EXPORT", "RC4", "DES-CBC3", "Anon")):
        findings.append(Finding(
            rule_id="VS-TLS-WEAK-CIPHER", title="Weak TLS cipher negotiated",
            severity="high", confidence="certain",
            description="The handshake selected a cipher suite with broken or "
                        "obsolete encryption.",
            impact="Session traffic can be decrypted or tampered with offline.",
            evidence=f"Negotiated cipher: {tls.get('cipher')!r} "
                     f"({tls.get('cipher_bits')} bits), {tls.get('version')}.",
            remediation="Disable export, NULL, RC4 and 3DES cipher suites; prefer "
                        "AEAD suites (AES-GCM, ChaCha20-Poly1305).",
            asset=_asset(svc), cwe=_cwe(327),
            references=_ref(CITATION.format(n=327))))

    if legacy_versions:
        legacy = [name for name, supported in legacy_versions.items() if supported]
        if legacy:
            findings.append(Finding(
                rule_id="VS-TLS-LEGACY",
                title=f"Legacy TLS versions accepted ({', '.join(legacy)})",
                severity="medium", confidence="firm",
                description="The server completes handshakes with outdated TLS "
                            "versions, which are subject to downgrade and padding "
                            "oracle style attacks (BEAST, POODLE).",
                impact="Downgrade attacks and weak-cipher exploitation against "
                       "legacy protocol versions.",
                evidence=f"Handshake succeeded with: {', '.join(legacy)}; "
                         f"current version: {tls.get('version')}.",
                remediation="Set the minimum protocol version to TLS 1.2 "
                            "(ideally TLS 1.3) and disable TLS 1.0/1.1.",
                asset=_asset(svc), cwe=_cwe(326),
                references=_ref(CITATION.format(n=326))))

    return findings


# --------------------------------------------------------------------------
# 3. HTTP configuration checks
# --------------------------------------------------------------------------

SECURITY_HEADERS = [
    ("strict-transport-security", "VS-HTTP-HSTS", "missing HTTP Strict "
     "Transport Security (HSTS) header", "medium", _cwe(319),
     "The HTTPS response does not set Strict-Transport-Security, so browsers will "
     "still honour plain-HTTP requests to this host.",
     "An attacker can strip the connection down to HTTP and capture credentials or "
     "session cookies (SSL stripping).",
     "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all "
     "HTTPS responses."),
    ("content-security-policy", "VS-HTTP-CSP", "missing Content-Security-Policy "
     "header", "medium", _cwe(693),
     "The response has no Content-Security-Policy, leaving cross-site scripting "
     "defences to browser defaults.",
     "Injected scripts execute freely, turning any XSS into full account takeover.",
     "Define a CSP that restricts script sources and disallows inline script; start "
     "with report-only mode and tighten."),
    ("x-frame-options", "VS-HTTP-XFO", "missing X-Frame-Options / frame-ancestors "
     "protection", "low", _cwe(1021),
     "The response can be framed by third-party pages because neither X-Frame-Options "
     "nor a frame-ancestors CSP directive is set.",
     "Clickjacking: attackers overlay the page to trick users into clicking controls "
     "they cannot see.",
     "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a "
     "'frame-ancestors' CSP directive."),
    ("x-content-type-options", "VS-HTTP-XCTO", "missing X-Content-Type-Options "
     "header", "low", _cwe(693),
     "The response omits X-Content-Type-Options: nosniff, so browsers may guess the "
     "content type of responses.",
     "MIME-sniffing attacks can turn an uploaded file or text response into active "
     "script in the page's origin.",
     "Send 'X-Content-Type-Options: nosniff' on every response."),
    ("referrer-policy", "VS-HTTP-REFPOL", "missing Referrer-Policy header",
     "informational", _cwe(200),
     "Without Referrer-Policy, full URLs (including query strings and session "
     "tokens) leak to third-party sites through the Referer header.",
     "Disclosure of URLs, tokens or identifiers to external origins.",
     "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
]

HEADER_RULE_BY_KEY = {entry[1]: entry for entry in SECURITY_HEADERS}


def check_http(svc: PortService) -> list[Finding]:
    http = svc.http
    if not http or http.get("status", 0) == 0:
        return []
    findings: list[Finding] = []
    headers = http.get("headers", {}) or {}
    is_https = http.get("scheme") == "https"
    is_admin_path = svc.port in (2375, 2376, 5601, 9200, 15672, 9090, 8500)

    for key, rule_id, title, severity, cwe, desc, impact, fix in SECURITY_HEADERS:
        if key in headers:
            continue
        if key == "strict-transport-security" and not is_https:
            continue
        if key == "x-frame-options" and "frame-ancestors" in headers.get(
                "content-security-policy", "").lower():
            continue
        findings.append(Finding(
            rule_id=rule_id, title=f"Web service on port {svc.port} is {title}",
            severity=severity, confidence="certain",
            description=desc, impact=impact,
            evidence=f"GET {http.get('path', '/')} {http.get('scheme')}://{svc.host}:"
                     f"{svc.port} returned {http.get('status')} without a "
                     f"{key!r} header. Response headers: "
                     f"{', '.join(sorted(headers))}.",
            remediation=fix, asset=_asset(svc, http.get("path", "/")),
            cwe=cwe, references=_ref(CITATION.format(n=cwe[0].split("-")[1]))))

    server = http.get("server", "")
    if re.search(r"/\d+[\d.]*", server):
        findings.append(Finding(
            rule_id="VS-HTTP-SERVER-VERSION",
            title=f"Server version disclosed in HTTP header ({server})",
            severity="low", confidence="certain",
            description="The Server header reveals the exact web server software and "
                        "version, removing the guessing an attacker would otherwise "
                        "do when matching CVEs.",
            impact="Targeted exploitation of version-specific vulnerabilities.",
            evidence=f"Server: {server!r}",
            remediation="Suppress version information (e.g. 'server_tokens off;' in "
                        "nginx, 'ServerTokens Prod' in Apache).",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(200),
            references=_ref(CITATION.format(n=200))))

    powered = http.get("powered_by", "")
    if powered:
        findings.append(Finding(
            rule_id="VS-HTTP-POWERED-BY",
            title=f"Framework version disclosed (X-Powered-By: {powered})",
            severity="low", confidence="certain",
            description="An X-Powered-By header discloses the application stack to "
                        "any unauthenticated client.",
            impact="Easier targeted exploitation using stack-specific exploits.",
            evidence=f"X-Powered-By: {powered!r}",
            remediation="Remove the X-Powered-By header in the framework or "
                        "web-server configuration.",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(200),
            references=_ref(CITATION.format(n=200))))

    body = http.get("body_preview", "") or ""
    if re.search(r"(?i)index of\s*/", body) or "Parent Directory" in body:
        findings.append(Finding(
            rule_id="VS-HTTP-DIR-LISTING", title="Directory listing enabled",
            severity="medium", confidence="certain",
            description="The web server returns an automatic directory index, "
                        "revealing every file in the folder.",
            impact="Disclosure of files never meant to be linked — backups, config "
                   "dumps, source archives — which are trivial to download.",
            evidence=f"GET {http.get('path', '/')} returned {http.get('status')} "
                     f"with an autoindex page; title {http.get('title')!r}.",
            remediation="Disable autoindex/directory listing and serve an explicit "
                        "index file or 404.",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(548),
            references=_ref(CITATION.format(n=548))))

    if re.search(r"(?i)(traceback \(most recent call last\)|java\.lang\.\w+Exception|"
                 r"System\.\w+Exception|Stack trace:)", body):
        findings.append(Finding(
            rule_id="VS-HTTP-STACKTRACE", title="Verbose error page leaks stack trace",
            severity="medium", confidence="certain",
            description="The application returned a raw exception stack trace to an "
                        "unauthenticated request.",
            impact="Discloses internal paths, framework versions and query structure "
                   "that directly aid injection and path-traversal attacks.",
            evidence=f"Response body contains a stack trace; snippet: "
                     f"{body[:300]!r}",
            remediation="Return generic error pages in production and log details "
                        "server-side only.",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(209),
            references=_ref(CITATION.format(n=209))))

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookies = set_cookie
        if "secure" not in cookies.lower():
            findings.append(Finding(
                rule_id="VS-HTTP-COOKIE-NO-SECURE",
                title="Cookie set without the Secure attribute", severity="medium",
                confidence="firm",
                description="A cookie is issued without the Secure flag, so browsers "
                            "send it over plain-HTTP connections.",
                impact="Session cookies can be stolen by an attacker on the network "
                       "path (credential/session hijacking).",
                evidence=f"Set-Cookie: {cookies[:300]!r}",
                remediation="Add the Secure attribute to all cookies issued over "
                            "HTTPS.",
                asset=_asset(svc, http.get("path", "/")), cwe=_cwe(614),
                references=_ref(CITATION.format(n=614))))
        if "httponly" not in cookies.lower():
            findings.append(Finding(
                rule_id="VS-HTTP-COOKIE-NO-HTTPONLY",
                title="Cookie set without the HttpOnly attribute", severity="low",
                confidence="firm",
                description="A cookie lacks the HttpOnly flag, so page scripts can "
                            "read it.",
                impact="Any cross-site scripting bug becomes a direct session-theft "
                       "bug.",
                evidence=f"Set-Cookie: {cookies[:300]!r}",
                remediation="Add the HttpOnly attribute to session cookies.",
                asset=_asset(svc, http.get("path", "/")), cwe=_cwe(1004),
                references=_ref(CITATION.format(n=1004))))

    if not is_https and svc.port not in (2375, 2376) and not is_admin_path:
        findings.append(Finding(
            rule_id="VS-HTTP-CLEARTEXT",
            title=f"Web service on port {svc.port} served over plaintext HTTP",
            severity="informational", confidence="certain",
            description="The service answers plain HTTP with no TLS listener "
                        "observed, so all request and response traffic crosses the "
                        "network unencrypted.",
            impact="Credentials, cookies and page content are readable and modifiable "
                   "by anyone on the path.",
            evidence=f"HTTP GET {http.get('scheme')}://{svc.host}:{svc.port}"
                     f"{http.get('path', '/')} → {http.get('status')} "
                     f"{http.get('reason', '')} (no TLS).",
            remediation="Terminate TLS in front of the service and redirect HTTP to "
                        "HTTPS.",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(319),
            references=_ref(CITATION.format(n=319))))

    findings.extend(_check_admin_exposure(svc, http))
    return findings


def _check_admin_exposure(svc: PortService, http: dict) -> list[Finding]:
    """Management consoles and framework fingerprints visible over HTTP."""
    findings: list[Finding] = []
    body = http.get("body_preview", "") or ""
    title = (http.get("title") or "").lower()

    if svc.port == 9200:
        if http.get("status") == 200 and "cluster" in body.lower():
            findings.append(Finding(
                rule_id="VS-HTTP-ES-OPEN",
                title="Elasticsearch cluster accessible without authentication",
                severity="critical", confidence="certain",
                description="The Elasticsearch root endpoint answered successfully "
                            "without credentials, so the cluster is open to anyone "
                            "who can reach it.",
                impact="Full read of indexed data (often logs or personal records) "
                       "and write access via the update and delete APIs.",
                evidence=f"GET http://{svc.host}:9200/ → {http.get('status')}; "
                         f"body: {body[:300]!r}",
                remediation="Enable X-Pack security or place Elasticsearch behind an "
                            "authenticated reverse proxy; bind to localhost.",
                asset=_asset(svc, "/"), cwe=_cwe(306),
                references=_ref(CITATION.format(n=306))))
        elif http.get("status") in (401, 403):
            findings.append(Finding(
                rule_id="VS-HTTP-ES-EXPOSED",
                title="Elasticsearch reachable from the network", severity="medium",
                confidence="firm",
                description="Elasticsearch responds to unauthenticated requests with "
                            "401/403 — authentication is on, but the port is exposed.",
                impact="Subject to brute-force and known vulnerability scans; index "
                       "data is at risk if credentials are weak.",
                evidence=f"GET http://{svc.host}:9200/ → {http.get('status')}.",
                remediation="Restrict port 9200 to trusted networks.",
                asset=_asset(svc, "/"), cwe=_cwe(284),
                references=_ref(CITATION.format(n=284))))

    if svc.port in (2375, 2376) and http.get("status") == 200:
        findings.append(Finding(
            rule_id="VS-HTTP-DOCKER-VERSION",
            title="Docker daemon API responds over HTTP", severity="critical",
            confidence="certain",
            description="The Docker engine API answered an unauthenticated request "
                        "on this port.",
            impact="Remote code execution: containers, images and volumes are fully "
                   "controllable by anyone who can reach the API.",
            evidence=f"GET {http.get('scheme')}://{svc.host}:{svc.port}/version → "
                     f"{http.get('status')}; body: {body[:300]!r}",
            remediation="Remove the tcp:// Docker socket binding; keep the API on a "
                        "UNIX socket with TLS client auth if remote access is needed.",
            asset=_asset(svc, "/"), cwe=_cwe(306),
            references=_ref(CITATION.format(n=306))))

    if svc.port in (5601, 15672, 9090, 8500, 8983, 5985) and http.get("status") == 200:
        findings.append(Finding(
            rule_id="VS-HTTP-ADMIN-OPEN",
            title=f"Administrative web console responding without authentication "
                  f"({svc.service or svc.port})",
            severity="high", confidence="firm",
            description="A management console returned HTTP 200 to an "
                        "unauthenticated request from the scan source.",
            impact="Exposure of operational data and, depending on the product, "
                   "control over the underlying system.",
            evidence=f"GET {http.get('scheme')}://{svc.host}:{svc.port}/ → "
                     f"{http.get('status')}; title {http.get('title')!r}.",
            remediation="Put the console behind authentication and restrict it to an "
                        "administrative network.",
            asset=_asset(svc, "/"), cwe=_cwe(306),
            references=_ref(CITATION.format(n=306))))
    return findings


# --------------------------------------------------------------------------
# 4. Version fingerprints → known CVEs and end-of-life software
# --------------------------------------------------------------------------

def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:4])


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    size = max(len(a), len(b))
    return a + (0,) * (size - len(a)), b + (0,) * (size - len(b))


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return _pad(a, b)[0] < _pad(a, b)[1]


def _le(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return _pad(a, b)[0] <= _pad(a, b)[1]


def check_fingerprints(svc: PortService) -> list[Finding]:
    """Match detected product/version against a small rule set of known flaws."""
    product = (svc.product or "").lower()
    version = svc.version
    if not product or not version:
        return []
    ver = _version_tuple(version)
    findings: list[Finding] = []

    if "vsftpd" in product and ver == (2, 3, 4):
        findings.append(Finding(
            rule_id="VS-CVE-2011-2523",
            title="vsftpd 2.3.4 backdoor (CVE-2011-2523)", severity="critical",
            confidence="certain",
            description="The banner identifies vsftpd 2.3.4, the release shipped "
                        "with a deliberate backdoor that opens a shell on a "
                        "non-standard port when the username contains ':)' .",
            impact="Trivial remote code execution as the FTP server user.",
            evidence=f"Banner: {svc.banner[:300]!r}",
            remediation="Reinstall a current vsftpd release immediately and audit "
                        "the host for signs of compromise.",
            asset=_asset(svc), cwe=_cwe(912), cve=["CVE-2011-2523"],
            references=_ref("https://nvd.nist.gov/vuln/detail/CVE-2011-2523")))

    if "apache" in product:
        if ver == (2, 4, 49):
            findings.append(Finding(
                rule_id="VS-CVE-2021-41773",
                title="Apache 2.4.49 path traversal and RCE (CVE-2021-41773)",
                severity="critical", confidence="firm",
                description="Apache HTTP Server 2.4.49 contains a path traversal "
                            "flaw in its normalisation code that, with CGI scripts "
                            "enabled, allows arbitrary command execution.",
                impact="Unauthenticated remote code execution as the web-server user.",
                evidence=f"Server banner reports Apache/{version}; "
                         f"product fingerprint from {svc.http.get('server')!r}"
                         if svc.http else f"Version {version} detected.",
                remediation="Upgrade to Apache 2.4.51 or later immediately.",
                asset=_asset(svc), cwe=_cwe(22), cve=["CVE-2021-41773"],
                references=_ref("https://nvd.nist.gov/vuln/detail/CVE-2021-41773")))
        elif ver == (2, 4, 50):
            findings.append(Finding(
                rule_id="VS-CVE-2021-42013",
                title="Apache 2.4.50 path traversal and RCE (CVE-2021-42013)",
                severity="critical", confidence="firm",
                description="Apache HTTP Server 2.4.50 is an incomplete fix for "
                            "CVE-2021-41773 and remains vulnerable to path "
                            "traversal and code execution.",
                impact="Unauthenticated remote code execution as the web-server user.",
                evidence=f"Server: {svc.http.get('server')!r}" if svc.http
                         else f"Version {version} detected.",
                remediation="Upgrade to Apache 2.4.51 or later immediately.",
                asset=_asset(svc), cwe=_cwe(22), cve=["CVE-2021-42013"],
                references=_ref("https://nvd.nist.gov/vuln/detail/CVE-2021-42013")))

    if "openssh" in product:
        # CVE-2024-6387 (regreSSHion): portable OpenSSH 8.5p1 – 9.7p1.
        portable = re.search(r"p\d+", version) is not None
        if portable and (8, 5) <= ver <= (9, 7):
            findings.append(Finding(
                rule_id="VS-CVE-2024-6387",
                title="OpenSSH affected by regreSSHion (CVE-2024-6387)",
                severity="medium", confidence="tentative",
                description=f"OpenSSH {version} falls in the range affected by "
                            "regreSSHion, a signal-handler race condition in the "
                            "SSH-2.0 handshake. Exploitation is hard but the flaw "
                            "is unauthenticated.",
                impact="In the worst case, unauthenticated remote code execution as "
                       "root; practical exploitation requires many connections and "
                       "is timing dependent.",
                evidence=f"SSH banner: {svc.banner[:200]!r}",
                remediation="Upgrade to OpenSSH 9.8p1 or later, or set "
                            "LoginGraceTime to 0 as a mitigation.",
                asset=_asset(svc), cwe=_cwe(362), cve=["CVE-2024-6387"],
                references=_ref("https://nvd.nist.gov/vuln/detail/CVE-2024-6387")))

    # End-of-life / unsupported version notices.
    eol = None
    if "apache" in product and _lt(ver, (2, 4, 0)):
        eol = ("Apache HTTP Server 2.2.x", "2.2 reached end of life in 2017")
    elif product == "php" and _lt(ver, (8, 0, 0)):
        eol = (f"PHP {version}", "PHP 7.x and older are end of life")
    elif "mysql" in product and _lt(ver, (8, 0, 0)):
        eol = (f"MySQL {version}", "MySQL 5.7 and older are end of life")
    elif "nginx" in product and _lt(ver, (1, 24, 0)):
        eol = (f"nginx {version}", "this release is far behind the maintained branch")
    if eol:
        findings.append(Finding(
            rule_id="VS-EOL-SOFTWARE",
            title=f"End-of-life software detected: {eol[0]}",
            severity="medium", confidence="firm",
            description=f"{eol[1]}; it no longer receives security patches, so every "
                        "newly disclosed vulnerability stays permanently exploitable.",
            impact="Accumulating unpatched CVEs with no vendor fix available.",
            evidence=f"Detected {svc.product} {version} on port {svc.port}.",
            remediation="Upgrade to a currently supported release of this software.",
            asset=_asset(svc), cwe=_cwe(1104),
            references=_ref("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")))
    return findings


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

async def run_checks(services: list[PortService], timeout: float,
                     check_legacy_tls: bool = False) -> list[Finding]:
    """Run every check against the collected services, newest evidence first."""
    from .scanner import supports_tls_version  # local import avoids cycles

    findings: list[Finding] = []
    for svc in services:
        findings.extend(check_exposure(svc))
        findings.extend(check_http(svc))
        findings.extend(check_fingerprints(svc))

    findings.extend(await check_ftp_anonymous(services, timeout))

    for svc in services:
        if not (svc.tls or {}).get("ok"):
            continue
        legacy: dict | None = None
        if check_legacy_tls:
            legacy = {
                "TLS 1.0": await supports_tls_version(
                    svc.ip, svc.port, _tls_version("TLSv1"), timeout),
                "TLS 1.1": await supports_tls_version(
                    svc.ip, svc.port, _tls_version("TLSv1_1"), timeout),
            }
        findings.extend(check_tls(svc, legacy))

    # Stable IDs ordered by severity, then by host/port for determinism.
    findings.sort(key=lambda f: (f.sort_key, f.asset.get("host", ""),
                                 f.asset.get("port", 0), f.rule_id))
    for index, finding in enumerate(findings, start=1):
        finding.id = f"VS-{index:04d}"

    # Attach playbook steps (scan-to-exploit validation recipes).
    from .playbook import steps_for  # local import avoids cycles
    for finding in findings:
        finding.next_steps = steps_for(
            finding.rule_id, finding.asset.get("host", ""),
            finding.asset.get("port", ""))
    return findings


def _tls_version(name: str):
    import ssl
    return getattr(ssl.TLSVersion, name)
