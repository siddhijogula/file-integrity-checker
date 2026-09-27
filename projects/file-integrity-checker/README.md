# File Integrity Checker

A command-line tool that detects unauthorised changes to files by computing and comparing cryptographic hashes against a trusted baseline. Useful for tamper detection, configuration drift monitoring, and verifying that a set of files hasn't changed between two points in time.

> Built as Task 1 of the Elite Tech Intern cybersecurity internship, then extended into a portfolio-quality tool.

## Features

- **Baseline + verify workflow** — snapshot a directory you trust, then check it later
- **Recursive directory scanning** with configurable ignore globs (`.git`, `__pycache__`, etc. skipped by default)
- **Multiple hash algorithms** — `sha256` (default), `sha512`, `blake2b`, `sha1`, `md5`
- **Chunked reading** — hashes large files without loading them into memory
- **Three change types reported** — `MODIFIED`, `ADDED`, `REMOVED`
- **Script-friendly** — returns a non-zero exit code when changes are found, so it drops straight into cron or CI
- **JSON reports** for machine consumption
- **Resilient** — an unreadable/locked file is logged and skipped, not fatal

## Why hashing?

A cryptographic hash is a fixed-length fingerprint of a file's contents. Changing even a single byte produces a completely different hash, so comparing a file's current hash to a known-good one reliably tells you whether it changed — without storing the original file. `sha256` is the default because it's collision-resistant and fast enough for routine scanning; `md5`/`sha1` are offered only for compatibility with legacy checksums and shouldn't be trusted against a deliberate attacker.

## Installation

```bash
git clone https://github.com/<your-username>/file-integrity-checker.git
cd file-integrity-checker
# No third-party dependencies — standard library only.
python3 --version   # 3.8+
```

## Usage

### 1. Create a baseline

```bash
python3 integrity_checker.py baseline ./important_files -o baseline.json
```

### 2. Verify later

```bash
python3 integrity_checker.py verify ./important_files -b baseline.json
```

Example output when something changed:

```
[!] 3 change(s) detected:
  MODIFIED  a.txt
  ADDED     evil.txt
  REMOVED   sub/config.ini
```

### 3. Hash a single file

```bash
python3 integrity_checker.py hash ./config.ini
```

### Options

| Flag | Command | Description |
|------|---------|-------------|
| `-o, --output` | `baseline` | Output path for the baseline (default `baseline.json`) |
| `-a, --algorithm` | `baseline`, `hash` | `sha256` / `sha512` / `blake2b` / `sha1` / `md5` |
| `-b, --baseline` | `verify` | Baseline file to compare against |
| `--json FILE` | `verify` | Also write a JSON report |
| `--ignore GLOB...` | `baseline`, `verify` | Extra ignore patterns |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No changes / success |
| `1` | Changes detected |
| `2` | Error (missing path or baseline) |

This makes it easy to alert on drift:

```bash
python3 integrity_checker.py verify ./etc -b etc.json || mail -s "Integrity alert" admin@example.com
```

## Scheduling (example)

Run a check every hour and log any drift:

```cron
0 * * * * cd /opt/fic && python3 integrity_checker.py verify /etc -b /opt/fic/etc.json --json /var/log/fic-last.json >> /var/log/fic.log 2>&1
```

## Design notes

- The baseline stores the relative path, hash, size, and last-modified time per file. Only the hash is used for the integrity decision; size/mtime are kept for human context.
- `os.walk` prunes ignored directories in place, so it never descends into `node_modules` or `.git`.
- Comparison is a straightforward set diff between baseline and current scan.

## Limitations

- Detects *content* changes, not who made them or when in real time — it's a point-in-time comparison, not a live file-system monitor.
- The baseline file itself should be stored somewhere the monitored system can't tamper with (e.g. read-only media or a separate host) for the guarantee to hold.

## License

MIT — see [LICENSE](LICENSE).
