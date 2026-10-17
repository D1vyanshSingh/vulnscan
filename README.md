# vulnscan

A network/service vulnerability scanner written in Python — **standard library
only, zero dependencies** — that produces a proper assessment report: HTML
(styled, printable), JSON (machine-readable) and a colored terminal summary.
The report follows the classic vulnerability-assessment format (modeled on
PurpleSec/Nessus-style sample reports): Executive Summary →
Scan Results → Methodology → Findings grouped by severity → Recommendations,
with an appendix of observed services.

## Quick start

```bash
python -m vulnscan scanme.org            # scan + ALL reports, automatically

# that single command writes:
#   out/vulnscan-report_<timestamp>.html   — styled assessment report
#   out/vulnscan-report_<timestamp>.json   — machine-readable findings
#   (your Downloads folder)/vulnscan-report_<timestamp>.pdf — rendered report

# only the summary in the terminal, no files:
python -m vulnscan scanme.org --no-html --no-json --no-pdf

# preview the generated report on this machine:
python3 tests/serve_report.py            # → http://127.0.0.1:8622/report.html
```

Targets can be hostnames, IPs or CIDR ranges.

## Usage

```bash
python -m vulnscan <target> [targets...] [options]

# Examples
python -m vulnscan scanme.org                     # default "top" port set
python -m vulnscan 10.0.0.0/29 -p 1-1024          # CIDR + explicit range
python -m vulnscan example.com -p 22,80,8000-8100 --legacy-tls
python -m vulnscan --version
```

Options:

| Flag | Meaning |
|---|---|
| `-p, --ports` | port spec: `top` (default common-port set), `all` (1–65535), or `22,80,8000-8100` |
| `-t, --timeout` | per-probe timeout seconds (default 2.5) |
| `-c, --concurrency` | max simultaneous probes (default 256) |
| `--legacy-tls` | additionally test for TLS 1.0/1.1 support (slower) |
| *(default)* | HTML + JSON reports land in `out/`, PDF in Downloads — automatically |
| `-o, --output-dir DIR` | directory for the automatic HTML/JSON reports (default `out/`) |
| `--html PATH` / `--json PATH` / `--pdf PATH` | override the automatic report destination |
| `--no-html` / `--no-json` / `--no-pdf` | skip that report artifact |
| `-q, --quiet` | no progress output |
| `--no-color` | plain terminal output |

Exit code is `1` when findings exist, `0` when the target is clean — handy for
CI gates.

## What it does

For every open port it collects **evidence first**: TLS certificate (subject,
issuer, SAN, expiry, self-signed-ness, hostname match), service banner
(probe payloads for Redis INFO, memcached stats, SMTP EHLO), and an HTTP probe
(status, headers, server string, title, body snippet). The checks then reason
over that evidence:

* **Exposed services** — Docker API, Redis (auth vs. unauthenticated via the
  INFO probe), memcached, MongoDB, Elasticsearch (checked for open
  cluster access), RDP, SMB, VNC, Telnet, WinRM, kubelet, etcd, database
  listeners, NFS, rsync, RabbitMQ/Kibana consoles and more.
* **Anonymous access** — FTP anonymous logins (banner-aware, works on
  nonstandard FTP ports).
* **TLS** — expired / soon-expiring / not-yet-valid certificates, self-signed,
  hostname mismatch, legacy protocol versions (opt-in), weak ciphers.
* **HTTP configuration** — missing security headers (HSTS, CSP,
  X-Frame-Options, XCTO, Referrer-Policy), server/framework version
  disclosure, enabled directory listing, stack-trace leaks, cookie flags
  (Secure/HttpOnly), plaintext HTTP.
* **Version fingerprints** — known-CVE matching (vsftpd 2.3.4 backdoor,
  Apache 2.4.49/2.4.50 path traversal, OpenSSH regreSSHion range) and
  end-of-life software detection.

Nothing is exploited and no destructive probes are sent.

## Severity model

Severity and confidence are reported independently — a `tentative` finding is
never silently upgraded.

| Severity | Meaning in this report |
|---|---|
| Critical | Exploitable by unauthenticated attackers; often full control (open Redis, Docker API, vsftpd backdoor) |
| High | Meaningful exposure or access (anon FTP, exposed RDP/SMB/VNC, expired cert) |
| Medium | Weaknesses that aid a follow-up attack (missing security headers, legacy TLS, EOL software) |
| Low | Hardening items (version disclosure, self-signed cert, cookie flags) |
| Informational | Observations, not immediate risks |

Confidence: `certain` (the probe directly proved it), `firm` (strong
evidence), `tentative` (needs human verification). Every finding also carries
CWE IDs where applicable, CVE IDs for fingerprint matches, concrete
evidence, a specific remediation and references.

## Report format

The HTML report mirrors standard vulnerability assessment reports:

1. **Executive summary** — context prose + severity count table
2. **Scan results** — visual severity breakdown (clickable filter)
3. **Methodology** — phases, scope, non-goals
4. **Findings** — grouped by severity band with per-band framing, followed by
   detailed cards (asset, description, impact, evidence, remediation, CWE/CVE)
5. **Recommendations** — de-duplicated actions ranked by number of findings
   resolved and hosts affected
6. **Appendix** — all observed services with product/version and banners

The JSON uses the same content with a `report_version`, `metadata`, `scope`,
`summary`, `services[]` and `findings[]` schema. Each finding looks like:

```json
{
  "id": "VS-0001",
  "rule_id": "VS-CVE-2011-2523",
  "title": "vsftpd 2.3.4 backdoor (CVE-2011-2523)",
  "severity": "critical",
  "confidence": "certain",
  "status": "open",
  "cwe": ["CWE-912"],
  "cve": ["CVE-2011-2523"],
  "asset": { "host": "192.0.2.10", "ip": "192.0.2.10", "port": 21,
             "protocol": "tcp", "service": "ftp" },
  "description": "The banner identifies vsftpd 2.3.4 …",
  "impact": "Trivial remote code execution as the FTP server user.",
  "evidence": "Banner: '220 (vsFTPD 2.3.4)'",
  "remediation": "Reinstall a current vsftpd release immediately …",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
  "provenance": { "scanner": "vulnscan 0.1.0" }
}
```

Fields are omitted rather than invented: a finding without a CVE lists no
CVE content, and unknown certificate fields stay empty.

## Testing

`python3 tests/fake_services.py` starts a rig of deliberately vulnerable fake
services on loopback (open Redis, no-auth memcached, anonymous vsftpd 2.3.4,
plain HTTP, self-signed HTTPS, plain-HTTP Docker API). Then:

```bash
python -m vulnscan 127.0.0.1 -p 21,6379,11211,8080,8443,2375
```

Reports are automatic — this one command produces the HTML, JSON and the
Downloads-folder PDF with no extra flags.

## Layout

```
vulnscan/
  targets.py   # target + port spec parsing
  scanner.py   # async connect scan, banner/TLS/HTTP probes
  checks.py    # rule engine → Finding objects
  report.py    # JSON / HTML / terminal rendering
  pdf.py       # headless-browser PDF rendering (auto-download)
  cli.py       # argparse front end
tests/
  fake_services.py     # vulnerable mock services for verification
  serve_report.py      # static preview server for out/report.html
```

## Limits

Banner-based detection can mislabel services; confidence is tracked per rule
and `tentative` findings say so explicitly. Version fingerprinting only fires
when the service discloses a version. This is a surface scanner, not a
replacement for an authenticated patch audit.
