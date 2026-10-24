# PHP App CVE Scanner

**Crawl · fingerprint · prove** recent PHP core vulnerabilities on a target web application — with primary focus on the **2026 php2shell** family.

| | |
|---|---|
| **Script** | `php_app_cve_scanner.py` |
| **Language** | Python 3.9+ (stdlib only — no pip deps) |
| **Posture** | Proof-oriented. Safe markers only. No reverse shells, no destructive commands. |
| **License** | Use only on systems you are authorized to test. |

---

## What it does

1. **Crawls** the target site (BFS, configurable depth/page cap)
2. **Fingerprints** PHP version, SAPI, server stack (`X-Powered-By`, banners, phpinfo, cookies, tech hints)
3. **Evaluates** recent PHP core CVEs against live evidence
4. **Probes** `session.upload_progress` surfaces used by the 2026 RCE chain (multipart + `PHP_SESSION_UPLOAD_PROGRESS`)
5. **Reports** findings to the terminal and a JSON file

---

## 2026 primary CVEs (php2shell)

| CVE | Severity | Summary |
|-----|----------|---------|
| **CVE-2026-109618** | Critical (CVSS 9.2) | OOM / `zend_bailout` longjmp corruption → unauthenticated RCE |
| **CVE-2026-109619** | Critical (CVSS 9.2) | `session.upload_progress` stale global state UAF → unauthenticated RCE (worst on **mod_php + Apache prefork**) |
| **CVE-2026-115560** | High | `serialize_handler` confusion via upload_progress → attacker-controlled unserialize |

**Fixed floors** (php.net 2026-10-21 security release):

| Branch | Minimum safe |
|--------|----------------|
| 8.2 | **8.2.35** |
| 8.3 | **8.3.36** |
| 8.4 | **8.4.27** |
| 8.5 | **8.5.12** |
| ≤ 8.1 | **EOL** — treat as permanently vulnerable for 109618 / 109619 |

**Immediate mitigation (before patching):**

```ini
; must apply BEFORE request parsing (php.ini / FPM pool / Apache)
; do NOT rely on ini_set() alone
session.upload_progress.enabled = 0
```

Restart all workers after changing this.

Also for CVE-2026-109618 interim hardening:

```apache
# Apache / FPM: apps must not override
php_admin_value memory_limit -1
```

Patching to the fix floors above is the only complete fix.

---

## Secondary coverage (2024–2025)

When version / SAPI evidence allows, the scanner also maps:

- **CVE-2024-4577** / **CVE-2024-8926** / **CVE-2024-8927** — CGI / Windows argument-injection family  
- **CVE-2024-1874** — `proc_open` array-syntax (Windows)  
- **CVE-2024-5458**, **CVE-2024-11233**, **CVE-2024-11234**  
- **CVE-2025-1217**, **CVE-2025-1734**, **CVE-2025-1736**, **CVE-2025-1861**, **CVE-2025-1220**, **CVE-2025-6491**

Use `--only-2026` to skip secondary checks.

---

## Requirements

- Python **3.9+**
- No third-party packages (uses only the standard library)
- Network reachability to the target
- **Written authorization** to test the target

```bash
# optional sanity check
python3 --version
python3 php_app_cve_scanner.py --help
```

---

## Install

```bash
git clone https://github.com/<you>/php-app-cve-scanner.git
cd php-app-cve-scanner
# single file — nothing to install
chmod +x php_app_cve_scanner.py
```

Or drop `php_app_cve_scanner.py` anywhere on your PATH.

---

## Usage

```text
python3 php_app_cve_scanner.py <URL> [options]
```

### Quick start

```bash
# Basic scan
python3 php_app_cve_scanner.py https://app.example/

# 2026 CVEs only + JSON out
python3 php_app_cve_scanner.py https://app.example/ --only-2026 -o report.json

# Deeper crawl
python3 php_app_cve_scanner.py https://app.example/ -d 3 -m 150 -o report.json

# Authenticated / custom headers
python3 php_app_cve_scanner.py https://app.example/ \
  --cookie "PHPSESSID=abc; session=xyz" \
  -H "Authorization: Bearer TOKEN"

# Heavier upload_progress / OOM-adjacent probes
python3 php_app_cve_scanner.py https://app.example/ --aggressive --only-2026
```

### CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `target` | *(required)* | Root URL (`https://…`) |
| `-d`, `--depth` | `3` | Crawl depth |
| `-m`, `--max-pages` | `100` | Max pages to fetch |
| `-o`, `--output` | auto | JSON report path |
| `-t`, `--timeout` | `12.0` | Per-request timeout (seconds) |
| `--cookie` | | Cookie header value |
| `-H`, `--header` | | Extra header (`Name: value`); repeatable |
| `--ua` | `PHP-App-CVE-Scanner/2.0` | User-Agent |
| `--delay` | `0` | Delay between requests (seconds) |
| `--secure` | off | Verify TLS certificates |
| `--subdomains` | off | Follow links to sibling subdomains |
| `--robots` | off | Respect `robots.txt` |
| `--aggressive` | off | Heavier multipart / upload_progress probes |
| `--only-2026` | off | Only CVE-2026-109618 / 109619 / 115560 |
| `-q`, `--quiet` | off | Less crawl chatter |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No `CONFIRMED` / `LIKELY` findings |
| `1` | At least one `CONFIRMED` or `LIKELY` finding |
| `2` | Bad args / target unreachable |

Useful in CI:

```bash
python3 php_app_cve_scanner.py https://staging.example/ --only-2026 -o out.json
echo $?   # 1 → triage required
```

---

## How confidence is decided

The scanner **does not claim RCE** unless evidence supports it. Status values:

| Status | Meaning |
|--------|---------|
| **CONFIRMED** | Strong multi-signal proof (e.g. live version below fix floor **and** `session.upload_progress.enabled=On` via phpinfo, plus SAPI context) |
| **LIKELY** | Version in vulnerable range with supporting stack signals (Apache/mod_php, multipart acceptance, etc.) |
| **POSSIBLE** | Partial signals; version unknown or incomplete config evidence |
| **NOT_VULNERABLE** | Version at/above fix floor (or rule does not apply) |
| **NOT_APPLICABLE** | Wrong platform/SAPI for that CVE |
| **ERROR** | Probe failed |

### Evidence sources

- Response headers: `X-Powered-By`, `Server`
- Discovered `/phpinfo.php`, `/info.php`, and similar
- HTML / error body version leaks
- Multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` (first field) — HTTP status, body reflection, session side-effects
- SAPI hints: Apache vs nginx, mod_php vs PHP-FPM, Windows/CGI

> **Note:** Black-box proof of UAF/RCE without a full exploit chain is intentionally limited. Version + `upload_progress=On` + Apache/mod_php is treated as the high-confidence **trigger surface**, not a demonstrated shell.

---

## Sample console output

```text
[+] Target: https://app.example/
[+] Mode: 2026 PHP CVEs only (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560)
[+] Reachable (status=200)
...
[PROBE] session.upload_progress / php2shell primitives…
...
════════════════════════════════════════════════════════
 PHP App CVE Scanner — Results
════════════════════════════════════════════════════════
 PHP version : 8.2.3  (phpinfo-body)
 Server      : Apache/2.4.41 (Ubuntu)
 ...
 [CONFIRMED] CVE-2026-109619  CRITICAL
   session.upload_progress stale global state UAF → RCE
   evidence:
     - PHP 8.2.3 < 8.2.35 fix floor
     - phpinfo: session.upload_progress.enabled=On
     - Apache / mod_php likely
 ...
[+] JSON report → /path/php_cve_report_app.example_....json
```

---

## JSON report shape

```json
{
  "target": "https://app.example/",
  "scanned_at": "2026-10-24T12:00:00+00:00",
  "elapsed_seconds": 12.3,
  "fingerprint": {
    "php_version": "8.2.3",
    "php_version_source": "phpinfo-body",
    "server": "Apache/2.4.41 (Ubuntu)",
    "powered_by": "PHP/8.2.3",
    "is_apache": true,
    "is_mod_php_likely": true,
    "upload_progress_signal": true
  },
  "crawl": { "pages": 42, "forms": 5 },
  "findings": [
    {
      "cve": "CVE-2026-109619",
      "title": "...",
      "severity": "CRITICAL",
      "status": "CONFIRMED",
      "confidence": "high",
      "evidence": ["..."],
      "affected_urls": ["https://app.example/info.php"],
      "remediation": "Upgrade immediately to PHP ≥ 8.2.35 / ..."
    }
  ]
}
```

---

## Remediation checklist

1. **Patch PHP** to ≥ `8.2.35` / `8.3.36` / `8.4.27` / `8.5.12` (or current branch equivalent).
2. **Disable upload progress now** (all SAPIs — FPM pool ≠ CLI):

   ```ini
   session.upload_progress.enabled = 0
   ```

3. **Restart** php-fpm / Apache / workers.
4. Prefer **PHP-FPM + nginx** over legacy **mod_php prefork** where possible (reduces 109619 blast radius; still patch).
5. Do not flip `session.serialize_handler` with `ini_set()` at runtime (115560 combo).
6. Re-scan with this tool after changes; expect `NOT_VULNERABLE` / mitigated signals.
7. Remove public `phpinfo` / `info.php` and version banners in production.

---

## Safety & ethics

- **Authorized testing only.** Running this against systems without permission may be illegal.
- Probes use **non-destructive markers** (no reverse shells, no `rm`, no credential stuffing).
- `--aggressive` increases request size/count for stronger signals — still proof-oriented, not exploit delivery.
- Default TLS verification is **off** (common in lab/pentest); use `--secure` when you need cert checks.
- Rate politely on production: `--delay 0.2` (or higher) and modest `-m`.

---

## Project layout

```text
.
├── README.md                 # this file
├── php_app_cve_scanner.py    # main scanner (single file)
└── (optional lab / PoC dirs if you vendor them)
```

---

## Limitations

- No JavaScript rendering — pure HTTP crawl (misses SPA-only routes).
- Version must be observable (headers, phpinfo, errors) or findings stay `POSSIBLE`.
- Full RCE exploitation is **out of scope** by design.
- WAF/CDN soft-200 pages can spoof content; treat body validation as part of human review.
- Fix floors are encoded from the 2026-10-21 advisory — update `PHP2SHELL_FIXED` in the script if newer releases ship.

---

## Updating fix floors

In `php_app_cve_scanner.py`:

```python
PHP2SHELL_FIXED = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}
```

Bump patch numbers when php.net publishes newer security releases for the same branches.

---

## Disclaimer

This tool is provided for **defensive security assessment**, vulnerability management, and authorized penetration testing. Authors and distributors assume no liability for misuse. Always obtain explicit written authorization before scanning.

---

## Credits

- PHP security advisories / GHSA entries for CVE-2026-109618 (`GHSA-w8hw-w9fx-j79w`) and CVE-2026-109619 (`GHSA-6wmf-4rv5-p3rp`)
- php.net 2026-10-21 security release fix floors

---

## Quick copy-paste

```bash
python3 php_app_cve_scanner.py https://TARGET/ --only-2026 -d 2 -m 80 -o php2026_report.json
```
