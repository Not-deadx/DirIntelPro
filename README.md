# DirIntel Pro

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Kali%20Linux-blue?style=for-the-badge&logo=linux" />
  <img src="https://img.shields.io/badge/language-Bash-green?style=for-the-badge&logo=gnu-bash" />
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge" />
  <img src="https://img.shields.io/badge/use-Authorized%20Only-critical?style=for-the-badge" />
</p>

<p align="center">
  <b>Advanced Directory Intelligence & Risk Analysis Framework</b><br/>
  Authorized security testing — directory enumeration, fingerprinting, risk scoring & subdomain discovery
</p>

---

## Overview

DirIntel Pro is a professional-grade Bash framework for authorized directory intelligence, response fingerprinting, and security risk analysis. It transforms raw directory enumeration into structured, scored, and categorized security intelligence — helping security professionals and developers understand exposure risk across web targets.

This tool is designed for **analysis and classification**, not exploitation.

---

## Legal Warning

> **This tool must only be used on systems you own or have explicit written permission to test.**
> Unauthorized use is illegal under computer fraud laws including the CFAA (US), Computer Misuse Act (UK), and equivalent legislation worldwide.
> The author assumes no liability for misuse.

---

## Features

| Module | Capability |
|--------|-----------|
| **Smart Host Detection** | HEAD request, status classification (LIVE / REDIRECTING / FORBIDDEN / DEAD), server header capture, response time |
| **Intelligent Enumeration** | Wordlist + extension expansion, Content-Type capture, page title extraction, rate-limited, threaded |
| **Response Fingerprinting** | SHA256 body hash, content length, word count, line count, wildcard/custom-404 detection |
| **Sensitive Pattern Detector** | High-risk keyword scanning in body, sensitive path keywords, sensitive file extensions |
| **Risk Scoring System** | Per-path score (0–30+), four severity levels: LOW / MEDIUM / HIGH / CRITICAL |
| **Advanced Analysis** | Directory listing detection, Git repository exposure, misconfigured backup file detection |
| **Clean Output Structure** | Categorized by status code, severity, and type — all in organized per-domain directories |
| **Markdown Report** | Full scan report with risk distribution chart, findings, and developer recommendations |
| **Professional UX** | Colored output, real-time progress bar, Ctrl+C trap, timestamped logs, dependency check |

---

## Requirements

| Dependency | Purpose |
|------------|---------|
| `curl` | HTTP requests |
| `awk` | Text processing |
| `sed` | Stream editing |
| `grep` | Pattern matching |
| `date` | Timestamps |
| `wc` | Counting |
| `sha256sum` | Body hashing |

Most are available by default on Linux/macOS. On Windows, use WSL or Git Bash.

---

## Installation

```bash
git clone https://github.com/youruser/dirintel-pro.git
cd dirintel-pro
chmod +x DirIntelPro.sh
```

---

## Usage

```
./DirIntelPro.sh --authorized [OPTIONS]
```

### Required Flags

| Flag | Description |
|------|-------------|
| `--authorized` | Confirms you have written permission to test the target |
| `--wordlist <file>` | Path to directory wordlist |

### Target (one required)

| Flag | Description |
|------|-------------|
| `--url <url>` | Single target URL |
| `--domain-list <file>` | File with one domain/URL per line |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--extensions <ext,...>` | none | Comma-separated extensions to append (e.g. `php,html,txt`) |
| `--delay <seconds>` | `1` | Delay between requests (minimum: 0.5s) |
| `--threads <n>` | `5` | Parallel threads (maximum: 10) |
| `--verbose` | off | Enable verbose output |
| `--help` | — | Show help |

### Examples

```bash
# Single target
./DirIntelPro.sh --authorized --url https://example.com --wordlist common.txt

# With extensions
./DirIntelPro.sh --authorized --url https://example.com --wordlist dirs.txt --extensions php,html,txt

# Multiple targets
./DirIntelPro.sh --authorized --domain-list targets.txt --wordlist dirs.txt --delay 2 --threads 3

# Verbose mode
./DirIntelPro.sh --authorized --url https://example.com --wordlist dirs.txt --verbose
```

---

## Output Structure

```
results/
├── live_hosts.txt                   # All live targets with server info
├── dead_hosts.txt                   # Unreachable targets
├── subdomains/                      # Subdomain scan results (if --subdomain-scan used)
│   └── <domain>/
│       ├── live_subdomains.txt
│       ├── dead_subdomains.txt
│       ├── redirecting_subdomains.txt
│       ├── forbidden_subdomains.txt
│       ├── all_subdomains.txt
│       └── subdomain_report.md
└── <domain>/
    ├── categorized/
    │   ├── 200.txt                  # Accessible paths
    │   ├── 403.txt                  # Forbidden paths
    │   ├── redirects.txt            # Redirect paths
    │   └── other.txt                # Other status codes
    ├── severity/                    # ← Bug findings sorted by severity
    │   ├── critical/
    │   │   └── findings.txt         # Score 21+  (CRITICAL bugs)
    │   ├── high/
    │   │   └── findings.txt         # Score 13–20 (HIGH bugs)
    │   ├── medium/
    │   │   └── findings.txt         # Score 6–12  (MEDIUM bugs)
    │   └── low/
    │       └── findings.txt         # Score 0–5   (LOW bugs)
    ├── fingerprint_analysis.txt     # SHA256, size, word/line count per 200 response
    ├── sensitive_files.txt          # Exposed sensitive file extensions
    ├── high_risk_paths.txt          # Paths matching sensitive keywords or body keywords
    ├── directory_listing_exposed.txt
    ├── git_exposure.txt
    ├── report.md                    # Full markdown intelligence report
    └── logs.txt                     # Timestamped request log
```

---

## Risk Scoring

Each discovered path receives a risk score based on:

| Condition | Score |
|-----------|-------|
| 200 OK response | +2 |
| 403 Forbidden response | +1 |
| Sensitive path keyword match | +5 |
| Admin/panel/console/dashboard path | +7 |
| Sensitive file extension (`.env`, `.sql`, `.bak`, etc.) | +10 |
| High-risk keyword found in response body | +15 |

### Severity Levels

| Score | Level | Color |
|-------|-------|-------|
| 0–5 | LOW | Green |
| 6–12 | MEDIUM | Yellow |
| 13–20 | HIGH | Red |
| 21+ | CRITICAL | Magenta/Bold |

---

## Sensitive Patterns Detected

### High-Risk Body Keywords
`password`, `token`, `secret`, `api_key`, `db_host`, `private_key`, `authorization`, `bearer`, `passwd`, `credentials`, `access_key`, `auth_token`, `session`

### Sensitive Path Keywords
`admin`, `backup`, `config`, `.git`, `.env`, `debug`, `database`, `private`, `internal`, `secret`, `uploads`, `test`, `dev`, `staging`, `api`, `console`, `panel`

### Sensitive Extensions
`.env`, `.zip`, `.sql`, `.bak`, `.tar`, `.gz`, `.log`, `.key`, `.pem`, `.conf`, `.cfg`, `.ini`, `.xml`, `.json`, `.yaml`, `.yml`

---

## Advanced Checks

### Directory Listing Detection
Scans 200 responses for `"Index of /"` — a common misconfiguration that exposes directory contents.

### Git Repository Exposure
Probes `/.git/HEAD` for accessibility. If accessible and contains a `ref:` pointer, your source code history may be fully downloadable.

### Backup File Detection
Probes common backup file names (`backup.zip`, `db.sql`, `.env.bak`, `wp-config.php.bak`, etc.) before enumeration begins.

### Wildcard Response Detection
If 3 or more paths return identical SHA256 hashes and content lengths, the tool flags possible wildcard/custom-404 behavior to reduce false positives.

---

## How Developers Can Prevent Exposure

1. **Restrict admin panels** with MFA and IP allowlisting
2. **Move config/backup files** outside the web root
3. **Block `.git` access** via server config (`deny all` for `/.git`)
4. **Disable directory listing** (`Options -Indexes` / `autoindex off`)
5. **Never return credentials** in HTTP responses
6. **Restrict upload directories** and validate file types server-side
7. **Remove debug/test endpoints** from production
8. **Enforce HTTPS** with HSTS headers
9. **Return 404** instead of 403 for sensitive paths to avoid path confirmation
10. **Add security headers**: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`

---

## False Positive Disclaimer

This tool performs automated analysis and may produce false positives. All findings should be manually verified before taking action. A 200 response does not necessarily indicate a security vulnerability — context and content must be evaluated. Risk scores are indicative only and should be interpreted by a qualified security professional.

---

## Ethical Use

DirIntel Pro is built for:
- **Penetration testers** conducting authorized engagements
- **Security researchers** analyzing their own infrastructure
- **Developers** auditing their own web applications for misconfigurations
- **Bug bounty hunters** working within defined scope

It is **not** designed for:
- Unauthorized scanning of third-party systems
- Aggressive or denial-of-service style attacks
- WAF bypass or evasion techniques

---

## License

MIT License — Use responsibly. See [LICENSE](LICENSE).

---

*DirIntel Pro v2.0.0 — Advanced Directory Intelligence & Risk Analysis Framework*
