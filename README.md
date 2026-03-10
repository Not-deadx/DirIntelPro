# DirIntel Pro


## Overview

DirIntel Pro is a professional Bash framework for authorized directory intelligence, response fingerprinting, and security risk analysis. It turns directory enumeration into structured, scored, and categorized findings so security teams and developers can see exposure risk across web targets.

The tool focuses on **analysis and classification**, not exploitation.

---

## Legal Warning

> **Use this tool only on systems you own or have explicit written permission to test.**  
> Unauthorized use may violate computer misuse laws (e.g. CFAA, Computer Misuse Act) and similar legislation. The author is not liable for misuse.

---

## Features

| Module | Description |
|--------|-------------|
| **Smart Host Detection** | HEAD checks with status (LIVE / REDIRECTING / FORBIDDEN / DEAD), Server header, response time |
| **Intelligent Enumeration** | Wordlist + extensions, Content-Type, page title, rate-limited, multi-threaded |
| **Response Fingerprinting** | SHA256 body hash, size, word/line count, wildcard and custom-404 detection |
| **Sensitive Pattern Detector** | High-risk keywords in body, sensitive path keywords, sensitive file extensions |
| **Risk Scoring** | Per-path score (0–30+), severity: LOW / MEDIUM / HIGH / CRITICAL |
| **Advanced Analysis** | Directory listing, Git exposure, backup file checks, robots.txt & sitemap.xml fetch |
| **Output Structure** | Results grouped by status code and severity in per-domain folders |
| **Reports** | Markdown report with risk chart, findings, and recommendations |
| **UX** | Colored output, progress bar, Ctrl+C handling, timestamped logs, dependency check |

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
| `sha256sum` | Body hashing (fallback: openssl/python if missing) |

On Debian/Ubuntu/Kali the script can attempt to install missing tools via `apt-get`. On Windows use WSL or Git Bash.

---

## Installation

```bash
git clone https://github.com/Not-deadx/DirIntelPro.git
cd DirIntelPro
chmod +x DirIntelPro.sh
```

---

## Usage

```text
./DirIntelPro.sh --authorized [OPTIONS]
```

### Required

| Flag | Description |
|------|-------------|
| `--authorized` | Confirm you have permission to test the target |
| `--wordlist <file>` | Path to directory wordlist |

### Target (one required)

| Flag | Description |
|------|-------------|
| `--url <url>` | Single target URL |
| `--domain-list <file>` | File with one domain or URL per line |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--extensions <ext,...>` | none | Extensions to try (e.g. `php,html,txt`) |
| `--subdomain-scan <file>` | — | Subdomain wordlist for subdomain enumeration |
| `--delay <seconds>` | `1` | Delay between requests (min 0.5) |
| `--threads <n>` | `5` | Parallel threads (max 10) |
| `--verbose` | off | Verbose output |
| `--help` | — | Show help |

### Examples

```bash
# Single target
./DirIntelPro.sh --authorized --url https://example.com --wordlist wordlist.txt

# With extensions
./DirIntelPro.sh --authorized --url https://example.com --wordlist wordlist.txt --extensions php,html,txt

# With subdomain scan
./DirIntelPro.sh --authorized --url https://example.com --wordlist wordlist.txt --subdomain-scan subdomains.txt

# Multiple targets
./DirIntelPro.sh --authorized --domain-list domains.txt --wordlist wordlist.txt --delay 2 --threads 3
```

---

## Output Structure

```text
results/
├── live_hosts.txt
├── dead_hosts.txt
├── subdomains/                    # if --subdomain-scan used
│   └── <domain>/
│       ├── live_subdomains.txt
│       ├── dead_subdomains.txt
│       ├── redirecting_subdomains.txt
│       ├── forbidden_subdomains.txt
│       ├── all_subdomains.txt
│       └── subdomain_report.md
└── <domain>/
    ├── categorized/
    │   ├── 200.txt
    │   ├── 403.txt
    │   ├── redirects.txt
    │   └── other.txt
    ├── severity/
    │   ├── critical/findings.txt   # score 21+
    │   ├── high/findings.txt       # score 13–20
    │   ├── medium/findings.txt    # score 6–12
    │   └── low/findings.txt       # score 0–5
    ├── fingerprint_analysis.txt
    ├── sensitive_files.txt
    ├── high_risk_paths.txt
    ├── directory_listing_exposed.txt
    ├── git_exposure.txt
    ├── robots.txt
    ├── sitemap.xml
    ├── report.md
    └── logs.txt
```

---

## Risk Scoring

| Condition | Score |
|-----------|-------|
| 200 OK | +2 |
| 403 Forbidden | +1 |
| Sensitive path keyword | +5 |
| Admin/panel/console/dashboard path | +7 |
| Sensitive file extension | +10 |
| High-risk keyword in response body | +15 |

### Severity

| Score | Level |
|-------|--------|
| 0–5 | LOW |
| 6–12 | MEDIUM |
| 13–20 | HIGH |
| 21+ | CRITICAL |

---

## Sensitive Patterns

**Body keywords:** `password`, `token`, `secret`, `api_key`, `db_host`, `private_key`, `authorization`, `bearer`, `credentials`, `access_key`, `auth_token`, `session`

**Path keywords:** `admin`, `backup`, `config`, `.git`, `.env`, `debug`, `database`, `private`, `internal`, `uploads`, `test`, `dev`, `staging`, `api`, `console`, `panel`

**Extensions:** `.env`, `.zip`, `.sql`, `.bak`, `.tar`, `.gz`, `.log`, `.key`, `.pem`, `.conf`, `.cfg`, `.ini`, `.xml`, `.json`, `.yaml`, `.yml`

---

## Advanced Checks

- **Directory listing:** Looks for `Index of /` in 200 responses.
- **Git exposure:** Checks `/.git/HEAD`; if 200 and contains `ref:`, source may be exposed.
- **Backup files:** Probes common names (`backup.zip`, `db.sql`, `.env.bak`, etc.).
- **robots.txt & sitemap.xml:** Fetched and saved; Disallow paths are noted.
- **Wildcard detection:** Flags when many paths share the same hash/size (possible wildcard/custom 404).

---

## How Developers Can Prevent Exposure

1. Restrict admin/panel/console with strong auth and IP allowlisting.
2. Keep config and backup files outside the web root.
3. Block `/.git` in server config (e.g. `deny all` or return 404).
4. Disable directory listing (`Options -Indexes` / `autoindex off`).
5. Do not return credentials or secrets in HTTP responses.
6. Restrict upload dirs and validate file types server-side.
7. Remove or protect debug/test endpoints in production.
8. Enforce HTTPS and use HSTS.
9. Prefer 404 over 403 for sensitive paths to avoid confirming existence.
10. Add security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`.

---

## False Positive Disclaimer

Results are automated and may include false positives. Verify findings before acting. A 200 response does not by itself mean a vulnerability; interpret risk scores with context and professional judgment.

---

## Ethical Use

**Intended for:** authorized pentests, security research on your own systems, developers auditing their apps, bug bounty within scope.

**Not for:** unauthorized scanning, DoS-style activity, or WAF bypass/evasion.

---

## License

MIT License. Use responsibly. See [LICENSE](LICENSE).

---

*DirIntel Pro v2.0.0 — Advanced Directory Intelligence & Risk Analysis Framework*
