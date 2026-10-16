# Project Report — vulnscan

**Generated:** 2026-10-16
**Status:** Complete and verified (v0.1.0)

---

## 1. What the project is

`vulnscan` is a network/service vulnerability scanner written entirely in
Python 3.14 using only the standard library — **zero pip dependencies**. In a
single command it:

1. TCP-connect scans targets (hosts, IPs, or CIDR ranges) on a chosen port set
2. Fingerprints every open service (TLS certificates, protocol banners, HTTP
   responses)
3. Runs ~34 attack-surface rules over that evidence
4. Produces three artifacts: a styled **HTML report**, a machine-readable
   **JSON report**, and — with `--pdf` — a **PDF that lands automatically in
   the user's Downloads folder**

The report format was modeled on the project's own reference document (a
PurpleSec/Nessus-style vulnerability assessment sample), matching its
Executive Summary → Scan Results → Methodology → Findings by severity →
Recommendations → Appendix structure.

## 2. Deliverables

| Artifact | Purpose |
|---|---|
| [vulnscan/scanner.py](vulnscan/scanner.py) | Async connect scan; TLS/banners/HTTP evidence collection |
| [vulnscan/checks.py](vulnscan/checks.py) | Rule engine → `Finding` objects (severity, confidence, CWE/CVE, evidence, remediation) |
| [vulnscan/report.py](vulnscan/report.py) | HTML / JSON / terminal rendering |
| [vulnscan/pdf.py](vulnscan/pdf.py) | Headless-Edge PDF rendering with auto-download |
| [vulnscan/cli.py](vulnscan/cli.py) + [targets.py](vulnscan/targets.py) | CLI and target/port parsing |
| [tests/fake_services.py](tests/fake_services.py) | Deliberately vulnerable mock-service rig |
| [README.md](README.md) | Full usage, severity model, formats, limits |

**Size:** ~2,683 lines total (~2,560 Python, 7 modules + 2 test scripts).

## 3. Rule coverage (34 discrete rule IDs)

- **Exposed services (18 rules):** Docker API (plain & TLS), Redis (separates
  unauthenticated vs. authenticated via a live `INFO` probe), memcached,
  MongoDB, MS SQL, PostgreSQL, Oracle, NFS, rsync, RDP, SMB, VNC, Telnet,
  WinRM, kubelet, etcd, RabbitMQ and Kibana consoles, Kubernetes API,
  Prometheus
- **Anonymous access:** FTP anonymous login (banner-aware — fires on
  nonstandard FTP ports too), FTP cleartext credentials
- **TLS (8 rules):** expired / expiring <14 days / not-yet-valid / self-signed
  certificates, hostname mismatch, weak negotiated cipher, legacy TLS 1.0/1.1
  (opt-in `--legacy-tls`)
- **HTTP configuration (10 rules):** missing HSTS / CSP / X-Frame-Options /
  XCTO / Referrer-Policy, server and framework version disclosure, directory
  listing, stack-trace leakage, cookie flags (Secure, HttpOnly), plaintext
  HTTP
- **Version fingerprints:** vsftpd 2.3.4 backdoor (CVE-2011-2523), Apache
  2.4.49/2.4.50 path traversal (CVE-2021-41773 / -42013), OpenSSH regreSSHion
  range (CVE-2024-6387), and end-of-life software detection (Apache 2.2,
  PHP < 8, MySQL < 8, old nginx)

Severity (Critical → Informational) and confidence (certain / firm /
tentative) are reported independently; no finding is auto-upgraded.

## 4. Verification results

Tested end-to-end against the local rig of planted vulnerabilities
(open Redis, no-auth memcached, anonymous vsftpd 2.3.4, plain HTTP, self-signed
HTTPS, plain-HTTP Docker API):

| Check | Result |
|---|---|
| Compile (`py_compile` all modules) | ✅ pass |
| Full rig scan (7 ports) | ✅ **25 findings in all 5 severity tiers, all planted vulns detected, no false positives on clean ports observed in the run** |
| CLI exit codes | ✅ 1 with findings / 0 clean (CI-gate behavior) |
| JSON report | ✅ valid, schema `report_version` 1.0, counts exact |
| HTML report | ✅ all 6 sections render; verified in headless browser |
| PDF auto-download | ✅ `vulnscan-report_<timestamp>.pdf` written to Downloads; content verified by text extraction |
| Port-conflict resilience | ✅ rig skips occupied ports instead of crashing |

Bugs found and fixed during verification: an unreachable Redis rule
(routing bug), a Python 3.14 certificate-nesting assumption, a `server_hostname`
misuse in plain-HTTP probes, an FTP reply race in `send_recv`, an orphaned
`return` after edits, and the port-10048 crash in the test rig.

## 5. Design decisions worth knowing

- **Evidence-first architecture:** probing (scanner) is strictly separate from
  judgment (checks); findings cite the raw probe output that produced them.
- **No exploitation, no destructive probes** — a benign login attempt for FTP
  is the most invasive action taken.
- **Stdlib-only:** asyncio + ssl + socket carry everything, including PDF
  (rendered through the machine's own Edge/Chrome).
- **Honest uncertainty:** every rule carries its confidence tier, and the
  report's methodology section discloses scan limitations.

## 6. Known limitations

1. Banner-based detection can mislabel services — mitigated by the confidence
   field, not eliminated.
2. Version fingerprinting only fires when a service reveals its version.
3. PDF rendering requires a local Edge or Chrome install.
4. It is a surface scanner — it does **not** replace an authenticated patch
   audit (the reference PDF's own point).
5. Windows drives some port handling (reserved ranges, port 21 shadowed), so
   the test rig falls back to 2121.

## 7. Suggested next steps

- NVD/OSV API lookup to enrich detected versions with live CVE data
- SARIF 2.1.0 export for GitHub code-scanning integration
- `--exclude`, scan-tag/bookmark, and diff-against-previous-scan features
- Real-target validation pass on a lab machine or scanme.org

---

*All artifacts live in the project root; the last verified scan report and PDF
are in `out/` and the user's Downloads folder respectively.*
