# Web Application Vulnerability Scanner

A lightweight Python scanner that crawls a web application and checks for common vulnerability classes using `requests` and `BeautifulSoup`. Built for learning and for testing applications **you own or are authorised to assess**.

> Built as Task 2 of the Elite Tech Intern cybersecurity internship, then hardened with scope controls, soft-404 handling, and non-destructive form testing.

## ⚠️ Authorised use only

Scanning a system you do not own or have **explicit written permission** to test may be illegal (for example, under the UK Computer Misuse Act 1990 or India's IT Act 2000). This tool:

- refuses to run without an authorisation confirmation (`-y` to skip in your own lab),
- **stays strictly within the target host** — it never follows links off-domain,
- sends only benign, non-destructive probes,
- does **not** auto-submit POST forms (it flags them for manual review instead).

You are responsible for how you use it. Safe practice targets include [testphp.vulnweb.com](http://testphp.vulnweb.com), OWASP Juice Shop, and DVWA running locally.

## What it checks

| Check | Severity | How |
|-------|----------|-----|
| Reflected XSS | HIGH | Injects a uniquely-marked `<script>` payload into query params and forms; flags it if reflected unescaped |
| SQL Injection (error-based) | HIGH | Sends classic quote payloads; flags known database error signatures in the response |
| Sensitive file exposure | HIGH | Probes for `.git/config`, `.env`, backups, `phpinfo.php`, etc. |
| Missing security headers | LOW | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy |
| Insecure cookie flags | MEDIUM | Flags cookies missing `Secure` / `HttpOnly` |

The scanner **baselines a random non-existent path first**. If the server returns `200` for it (a soft-404 / catch-all), sensitive-path probing is skipped to avoid false positives — a common failure mode in naive scanners.

## Installation

```bash
git clone https://github.com/<your-username>/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan (prompts for authorisation confirmation)
python3 scanner.py http://testphp.vulnweb.com

# Give a URL with parameters so injection checks have something to test
python3 scanner.py "http://testphp.vulnweb.com/listproducts.php?cat=1"

# Tune the crawl and save a JSON report
python3 scanner.py http://localhost:5000 --max-pages 20 --delay 0.2 --json report.json -y
```

### Options

| Flag | Description |
|------|-------------|
| `--max-pages N` | Maximum pages to crawl (default 30) |
| `--delay S` | Seconds between requests — be polite (default 0.3) |
| `--timeout S` | Per-request timeout |
| `--json FILE` | Write findings as JSON |
| `--insecure` | Skip TLS verification (lab use only) |
| `-y, --yes` | Skip the authorisation prompt |

Exit code is `1` if any HIGH/MEDIUM issue is found, `0` otherwise — so it slots into CI pipelines.

## Sample output

```
 Summary:  HIGH: 3  MEDIUM: 0  LOW: 1  INFO: 0

 [HIGH] Reflected XSS
       URL:    http://target/search?name=x
       Detail: Parameter 'name' reflects an unsanitised <script> payload.
       Proof:  marker 'xSsPr0be9137' found unescaped in response

 [HIGH] SQL Injection
       URL:    http://target/item?id=1
       Detail: Parameter 'id' triggers a database error string.
       Proof:  matched signature: 'You have an error in your SQL syntax'
```

## How the checks work

- **XSS** uses a random marker string inside the payload so a reflection is unambiguously *ours*, not a coincidental match.
- **SQLi** is detected via reflected DBMS error strings (error-based). This is the non-destructive approach: it never runs `OR 1=1 --` style logic that could alter data, and it doesn't attempt blind/time-based extraction.
- **Crawling** is breadth-first and scope-locked to the target's `netloc`.

## Limitations (by design)

This is an educational tool, not a replacement for Burp Suite, OWASP ZAP, or a professional assessment. It does **not** cover:

- Stored/DOM-based XSS, blind or time-based SQLi
- Authentication, CSRF, SSRF, IDOR, or business-logic flaws
- JavaScript-rendered single-page apps (it parses static HTML only)

Absence of findings is **not** proof of security.

## License

MIT — see [LICENSE](LICENSE).
