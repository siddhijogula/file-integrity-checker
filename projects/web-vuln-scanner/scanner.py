#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
=====================================

A lightweight, educational scanner that crawls a web application and checks
for common classes of vulnerability:

    * Reflected Cross-Site Scripting (XSS)
    * Error-based / reflected SQL Injection (SQLi)
    * Missing security headers
    * Insecure cookie flags
    * Exposure of sensitive paths (.git, .env, backups, etc.)

It uses `requests` for HTTP and `BeautifulSoup` for HTML/form parsing.

------------------------------------------------------------------------------
AUTHORISED USE ONLY
------------------------------------------------------------------------------
Only scan applications you own or have explicit written permission to test.
Unauthorised scanning may be illegal (e.g. the UK Computer Misuse Act 1990).
This tool sends only benign, non-destructive probes and honours a scope
restriction, but you remain responsible for how you use it.
------------------------------------------------------------------------------

Author: Siddhi Jogula
License: MIT
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    sys.exit(
        "Missing dependencies. Install them with:\n"
        "    pip install -r requirements.txt"
    )


# ---------------------------------------------------------------------------
# Payloads & signatures
# ---------------------------------------------------------------------------

# A unique marker so we can tell OUR reflected payload apart from coincidences.
XSS_MARKER = "xSsPr0be9137"
XSS_PAYLOAD = f"<script>{XSS_MARKER}</script>"

# Classic SQLi probes. We look for reflected DB error strings, which is the
# safe (non-blind, non-destructive) way to flag likely injection points.
SQLI_PAYLOADS = ["'", '"', "')", "' OR '1'='1"]

SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqlite3?::",
    r"sqlstate\[",
    r"ora-\d{5}",
    r"odbc sql server driver",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)

# Security headers we expect a hardened app to send.
SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS and data injection.",
    "X-Frame-Options": "Prevents clickjacking via framing.",
    "X-Content-Type-Options": "Stops MIME-type sniffing.",
    "Strict-Transport-Security": "Enforces HTTPS (HSTS).",
    "Referrer-Policy": "Controls referrer information leakage.",
}

# Sensitive paths that should not be publicly reachable.
SENSITIVE_PATHS = [
    ".git/config",
    ".env",
    "backup.zip",
    "backup.sql",
    "db.sql",
    ".htaccess",
    "wp-config.php.bak",
    "config.php.bak",
    "phpinfo.php",
]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    severity: str            # HIGH / MEDIUM / LOW / INFO
    category: str            # e.g. "Reflected XSS"
    url: str
    detail: str
    evidence: str = ""

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    base_url: str
    max_pages: int = 30
    delay: float = 0.3          # politeness delay between requests (seconds)
    timeout: float = 10.0
    user_agent: str = "WebVulnScanner/1.0 (+authorised-testing)"
    verify_tls: bool = True


class WebVulnScanner:
    def __init__(self, config: ScanConfig):
        self.cfg = config
        self.base = config.base_url.rstrip("/")
        parsed = urlparse(config.base_url)
        self.scope_host = parsed.netloc
        # Clean origin (scheme://host[:port]) for building absolute probe paths,
        # so we never accidentally graft a path onto an existing query string.
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.session = requests.Session()
        self.session.headers["User-Agent"] = config.user_agent
        self.visited: Set[str] = set()
        self.findings: List[Finding] = []
        self._seen_categories: Set[Tuple[str, str]] = set()

    # -- scope enforcement --------------------------------------------------

    def _in_scope(self, url: str) -> bool:
        """Never leave the target host. This is the core safety guardrail."""
        return urlparse(url).netloc == self.scope_host

    # -- HTTP helper --------------------------------------------------------

    def _get(self, url: str, params: Optional[dict] = None) -> Optional[requests.Response]:
        try:
            time.sleep(self.cfg.delay)
            return self.session.get(
                url,
                params=params,
                timeout=self.cfg.timeout,
                verify=self.cfg.verify_tls,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            print(f"  [warn] request failed for {url}: {exc}", file=sys.stderr)
            return None

    def _add(self, finding: Finding) -> None:
        # De-duplicate on (category, url) so one issue isn't reported twice.
        key = (finding.category, finding.url)
        if key in self._seen_categories:
            return
        self._seen_categories.add(key)
        self.findings.append(finding)

    # -- crawling -----------------------------------------------------------

    def crawl(self) -> List[str]:
        """Breadth-first crawl, staying strictly in scope."""
        queue: deque[str] = deque([self.base])
        pages: List[str] = []

        while queue and len(pages) < self.cfg.max_pages:
            url = queue.popleft()
            if url in self.visited or not self._in_scope(url):
                continue
            self.visited.add(url)

            resp = self._get(url)
            if resp is None or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            pages.append(url)

            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                link = urljoin(url, tag["href"].split("#")[0])
                if self._in_scope(link) and link not in self.visited:
                    queue.append(link)

        return pages

    # -- individual checks --------------------------------------------------

    def check_security_headers(self, url: str) -> None:
        resp = self._get(url)
        if resp is None:
            return

        for header, why in SECURITY_HEADERS.items():
            if header not in resp.headers:
                self._add(Finding(
                    severity="LOW",
                    category="Missing Security Header",
                    url=url,
                    detail=f"Missing '{header}'. {why}",
                ))

        # Cookie flags
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly")
            if issues:
                self._add(Finding(
                    severity="MEDIUM",
                    category="Insecure Cookie",
                    url=url,
                    detail=f"Cookie '{cookie.name}' missing flag(s): {', '.join(issues)}.",
                ))

    def check_sensitive_paths(self) -> None:
        # Baseline a random path first: if the server returns 200 for something
        # that shouldn't exist, it has a catch-all/soft-404 and path probing is
        # unreliable, so we skip it to avoid a flood of false positives.
        probe = self._get(f"{self.origin}/nonexistent_{XSS_MARKER}_404check")
        if probe is not None and probe.status_code == 200:
            self._add(Finding(
                severity="INFO",
                category="Sensitive File Exposure",
                url=self.origin,
                detail="Server returns 200 for non-existent paths (soft-404); "
                       "skipping sensitive-path checks to avoid false positives.",
            ))
            return

        for path in SENSITIVE_PATHS:
            target = f"{self.origin}/{path}"
            resp = self._get(target)
            if resp is not None and resp.status_code == 200 and resp.content:
                self._add(Finding(
                    severity="HIGH",
                    category="Sensitive File Exposure",
                    url=target,
                    detail=f"Sensitive path '{path}' is publicly reachable (HTTP 200).",
                    evidence=f"{len(resp.content)} bytes returned",
                ))

    def _query_params(self, url: str) -> Dict[str, List[str]]:
        return parse_qs(urlparse(url).query)

    def check_reflected_xss(self, url: str) -> None:
        params = self._query_params(url)
        if not params:
            return
        for param in params:
            test = {k: v[0] for k, v in params.items()}
            test[param] = XSS_PAYLOAD
            base = url.split("?")[0]
            resp = self._get(f"{base}?{urlencode(test)}")
            if resp is None:
                continue
            if XSS_PAYLOAD in resp.text:
                self._add(Finding(
                    severity="HIGH",
                    category="Reflected XSS",
                    url=url,
                    detail=f"Parameter '{param}' reflects an unsanitised <script> payload.",
                    evidence=f"marker '{XSS_MARKER}' found unescaped in response",
                ))

    def check_sql_injection(self, url: str) -> None:
        params = self._query_params(url)
        if not params:
            return
        for param in params:
            for payload in SQLI_PAYLOADS:
                test = {k: v[0] for k, v in params.items()}
                test[param] = payload
                base = url.split("?")[0]
                resp = self._get(f"{base}?{urlencode(test)}")
                if resp is None:
                    continue
                match = SQL_ERROR_RE.search(resp.text)
                if match:
                    self._add(Finding(
                        severity="HIGH",
                        category="SQL Injection",
                        url=url,
                        detail=f"Parameter '{param}' triggers a database error string.",
                        evidence=f"matched signature: '{match.group(0)[:60]}'",
                    ))
                    break  # one confirmation per param is enough

    def check_forms(self, url: str) -> None:
        """Fuzz GET forms with XSS/SQLi markers (non-destructive)."""
        resp = self._get(url)
        if resp is None:
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            action = urljoin(url, form.get("action") or url)
            if not self._in_scope(action):
                continue
            inputs = [i.get("name") for i in form.find_all(["input", "textarea"])
                      if i.get("name")]
            if not inputs:
                continue

            # Only auto-submit GET forms; POST forms are reported for manual review
            # to avoid changing state on the target.
            if method != "get":
                self._add(Finding(
                    severity="INFO",
                    category="Form (manual review)",
                    url=action,
                    detail=f"POST form with fields {inputs} — test manually to stay non-destructive.",
                ))
                continue

            data = {name: XSS_PAYLOAD for name in inputs}
            r = self._get(action, params=data)
            if r is not None and XSS_PAYLOAD in r.text:
                self._add(Finding(
                    severity="HIGH",
                    category="Reflected XSS (form)",
                    url=action,
                    detail=f"GET form fields {inputs} reflect an unsanitised payload.",
                ))

    # -- orchestration ------------------------------------------------------

    def run(self) -> List[Finding]:
        print(f"[*] Target: {self.base}  (scope host: {self.scope_host})")
        print("[*] Crawling...")
        pages = self.crawl()
        print(f"[*] Crawled {len(pages)} page(s). Running checks...")

        self.check_security_headers(self.base)
        self.check_sensitive_paths()

        for url in pages:
            self.check_reflected_xss(url)
            self.check_sql_injection(url)
            self.check_forms(url)

        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        return self.findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

class _C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


_SEV_COLOUR = {
    "HIGH": _C.RED, "MEDIUM": _C.YELLOW, "LOW": _C.BLUE, "INFO": _C.GREY,
}


def print_report(findings: List[Finding], target: str) -> None:
    use_colour = sys.stdout.isatty()

    def col(text: str, code: str) -> str:
        return f"{code}{text}{_C.RESET}" if use_colour else text

    print("\n" + "=" * 68)
    print(col(f" Scan report — {target}", _C.BOLD))
    print(f" {datetime.now(timezone.utc).isoformat()}")
    print("=" * 68)

    if not findings:
        print("\n No issues detected by the checks that were run.")
        print(" (Absence of findings is not proof of security.)\n")
        return

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(
        col(f"{sev}: {counts.get(sev, 0)}", _SEV_COLOUR[sev])
        for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
    )
    print(f"\n Summary:  {summary}\n")

    for f in findings:
        badge = col(f"[{f.severity}]", _SEV_COLOUR.get(f.severity, ""))
        print(f" {badge} {col(f.category, _C.BOLD)}")
        print(f"       URL:    {f.url}")
        print(f"       Detail: {f.detail}")
        if f.evidence:
            print(f"       Proof:  {f.evidence}")
        print()


def write_json(findings: List[Finding], target: str, path: str) -> None:
    import json
    payload = {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [f.as_dict() for f in findings],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner",
        description="Scan a web application for common vulnerabilities. "
                    "AUTHORISED TARGETS ONLY.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "example:\n"
            "  %(prog)s http://testphp.vulnweb.com --max-pages 20\n\n"
            "Only scan systems you own or are explicitly permitted to test."
        ),
    )
    p.add_argument("url", help="Base URL of the target (e.g. http://example.com).")
    p.add_argument("--max-pages", type=int, default=30,
                   help="Maximum pages to crawl (default 30).")
    p.add_argument("--delay", type=float, default=0.3,
                   help="Seconds to wait between requests (default 0.3).")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Per-request timeout in seconds.")
    p.add_argument("--json", metavar="FILE", help="Write findings to a JSON file.")
    p.add_argument("--insecure", action="store_true",
                   help="Do not verify TLS certificates (lab use).")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the authorisation confirmation prompt.")
    return p


def confirm_authorisation(target: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    print(f"\nYou are about to scan: {target}")
    print("Confirm you are AUTHORISED to test this target.")
    try:
        answer = input("Type 'yes' to continue: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("[error] Please supply a full URL, e.g. http://example.com",
              file=sys.stderr)
        return 2

    if not confirm_authorisation(args.url, args.yes):
        print("Aborted: authorisation not confirmed.")
        return 1

    if args.insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore

    cfg = ScanConfig(
        base_url=args.url,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        verify_tls=not args.insecure,
    )
    scanner = WebVulnScanner(cfg)
    findings = scanner.run()
    print_report(findings, args.url)

    if args.json:
        write_json(findings, args.url, args.json)
        print(f"JSON report written to {args.json}")

    # Exit non-zero if any HIGH/MEDIUM issue was found (CI-friendly).
    if any(f.severity in ("HIGH", "MEDIUM") for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
