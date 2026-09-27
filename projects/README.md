# Cybersecurity Internship Projects — Setup & Push Guide

Four self-contained Python security tools, each in its own folder, ready to become four separate GitHub repositories. Built for the Elite Tech Intern cybersecurity internship and extended into portfolio-quality projects.

| # | Folder | Project | Key libraries |
|---|--------|---------|---------------|
| 1 | `file-integrity-checker/` | File Integrity Checker | `hashlib` (stdlib) |
| 2 | `web-vuln-scanner/` | Web App Vulnerability Scanner | `requests`, `beautifulsoup4` |
| 3 | `pentest-toolkit/` | Penetration Testing Toolkit | `socket`, `requests` |
| 4 | `aes-encryption-tool/` | Advanced Encryption Tool | `cryptography` |

Each folder already contains its own `README.md`, `requirements.txt`, `LICENSE` (MIT), and `.gitignore`.

---

## How to put these on GitHub

You have two sensible options.

### Option A — four separate repos (recommended)

This looks best on your profile: four distinct, well-documented repositories, each with its own README shown on its page.

For **each** folder, from inside it:

```bash
cd file-integrity-checker

git init
git add .
git commit -m "Initial commit: File Integrity Checker"
git branch -M main
```

Then create an empty repo on GitHub named e.g. `file-integrity-checker` (no README/license — you already have them), and:

```bash
git remote add origin https://github.com/siddhijogula/file-integrity-checker.git
git push -u origin main
```

Repeat for the other three folders. Suggested repo names:

- `file-integrity-checker`
- `web-vuln-scanner`
- `pentest-toolkit`
- `aes-encryption-tool`

### Option B — one combined repo

Put all four under a single repository (e.g. `cybersecurity-projects`) with this guide as the top-level README:

```bash
cd <this-folder>
git init
git add .
git commit -m "Cybersecurity internship projects"
git branch -M main
git remote add origin https://github.com/siddhijogula/cybersecurity-projects.git
git push -u origin main
```

---

## Before you push — a checklist

1. **Update the placeholders.** Each README has `siddhijogula` in the clone URL — replace it with your GitHub handle. The `LICENSE` files are already filled in with your name and the current year.
2. **Make them your own.** Read through the code so you can explain every design decision in an interview — *why* AES-GCM over CBC, *why* a TCP connect scan over SYN, *why* the scanner refuses off-domain links. That understanding is what the projects are really for.
3. **Pin the repos.** On your GitHub profile, pin these four so they appear at the top.
4. **Add topics/tags** on each repo (e.g. `python`, `cybersecurity`, `security-tools`, `pentesting`) so they're discoverable.

---

## What makes these portfolio-strong (talking points)

- **They run and were tested.** Each tool was verified end-to-end: the integrity checker detects modified/added/removed files; the scanner catches real reflected XSS and error-based SQLi; the toolkit's three modules all work against live targets; the encryption tool round-trips byte-perfectly and rejects tampered files.
- **They show security judgement, not just code.** The offensive tools (scanner, toolkit) enforce scope, confirm authorisation, and stay non-destructive. The encryption tool uses authenticated encryption and proper key derivation. This maturity is exactly what a SOC / security-analyst hiring manager looks for.
- **They're documented.** Every repo explains what it does, how it works, its limitations, and how to use it.

---

## A note on responsible use

The scanner and toolkit are for systems you **own or are explicitly authorised to test**. Both include authorisation prompts and scope controls. Practise on intentionally vulnerable targets — OWASP Juice Shop, DVWA, `testphp.vulnweb.com`, or `scanme.nmap.org` — never on systems you don't have permission for.

---

*Author: Siddhi Jogula · Licensed MIT*
