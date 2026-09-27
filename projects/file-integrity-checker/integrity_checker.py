#!/usr/bin/env python3
"""
File Integrity Checker
======================

Monitors files and directories for unauthorised changes by computing and
comparing cryptographic hashes against a trusted baseline.

Typical workflow:
    1. Create a baseline of a directory you trust:
        python integrity_checker.py baseline ./important_files -o baseline.json

    2. Later, check whether anything changed:
        python integrity_checker.py verify ./important_files -b baseline.json

The tool reports files that were MODIFIED, ADDED, or REMOVED since the
baseline was taken. It is intended for change detection / tamper monitoring,
not as a replacement for a full HIDS.

Author: Siddhi Jogula
License: MIT
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SUPPORTED_ALGORITHMS = ("sha256", "sha512", "sha1", "md5", "blake2b")
DEFAULT_ALGORITHM = "sha256"
CHUNK_SIZE = 65_536  # 64 KB - read large files without loading them into RAM

# Directories/files we almost never want to fingerprint.
DEFAULT_IGNORE = (
    ".git",
    "__pycache__",
    "*.pyc",
    ".DS_Store",
    "node_modules",
    ".venv",
    "venv",
)


# ---------------------------------------------------------------------------
# Core hashing
# ---------------------------------------------------------------------------

def hash_file(path: Path, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the hex digest of a single file, reading it in chunks.

    Raises FileNotFoundError / PermissionError to the caller so they can be
    handled and reported per-file instead of aborting the whole scan.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    digest = hashlib.new(algorithm)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_ignored(rel_path: str, patterns: Iterable[str]) -> bool:
    """True if any path component matches an ignore glob."""
    parts = Path(rel_path).parts
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


# ---------------------------------------------------------------------------
# Baseline model
# ---------------------------------------------------------------------------

@dataclass
class Baseline:
    """A snapshot of a directory tree: relative path -> hash + metadata."""

    algorithm: str
    root: str
    created_at: str
    files: Dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "root": self.root,
            "created_at": self.created_at,
            "file_count": len(self.files),
            "files": self.files,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        return cls(
            algorithm=data["algorithm"],
            root=data["root"],
            created_at=data["created_at"],
            files=data["files"],
        )

    def save(self, out_path: Path) -> None:
        out_path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, in_path: Path) -> "Baseline":
        return cls.from_dict(json.loads(in_path.read_text()))


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _iter_files(root: Path, ignore: Iterable[str]) -> Iterable[Path]:
    """Yield every file under root that is not ignored."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place so os.walk doesn't descend them.
        dirnames[:] = [
            d for d in dirnames
            if not _is_ignored(str(Path(dirpath, d).relative_to(root)), ignore)
        ]
        for name in filenames:
            full = Path(dirpath, name)
            rel = str(full.relative_to(root))
            if _is_ignored(rel, ignore):
                continue
            yield full


def scan_directory(
    root: Path,
    algorithm: str = DEFAULT_ALGORITHM,
    ignore: Iterable[str] = DEFAULT_IGNORE,
) -> Baseline:
    """Walk `root` and build a Baseline of every readable file."""
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    baseline = Baseline(
        algorithm=algorithm,
        root=str(root),
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    for full in _iter_files(root, ignore):
        rel = str(full.relative_to(root))
        try:
            stat = full.stat()
            baseline.files[rel] = {
                "hash": hash_file(full, algorithm),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc
                ).isoformat(),
            }
        except (PermissionError, FileNotFoundError, OSError) as exc:
            # Report but keep going - a locked file shouldn't kill the scan.
            print(f"  [warn] could not read {rel}: {exc}", file=sys.stderr)

    return baseline


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

@dataclass
class DiffResult:
    modified: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.modified or self.added or self.removed)

    @property
    def total_changes(self) -> int:
        return len(self.modified) + len(self.added) + len(self.removed)


def compare(baseline: Baseline, current: Baseline) -> DiffResult:
    """Diff a fresh scan against the trusted baseline."""
    result = DiffResult()
    base_files = baseline.files
    curr_files = current.files

    for rel, meta in curr_files.items():
        if rel not in base_files:
            result.added.append(rel)
        elif meta["hash"] != base_files[rel]["hash"]:
            result.modified.append(rel)

    for rel in base_files:
        if rel not in curr_files:
            result.removed.append(rel)

    result.modified.sort()
    result.added.sort()
    result.removed.sort()
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# ANSI colours (disabled automatically when output is not a TTY).
class _C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _colour(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_C.RESET}"


def cmd_baseline(args: argparse.Namespace) -> int:
    root = Path(args.path)
    print(f"Creating baseline for {root} using {args.algorithm}...")
    baseline = scan_directory(root, args.algorithm, _resolve_ignore(args))
    out = Path(args.output)
    baseline.save(out)
    print(
        _colour(
            f"[ok] Baseline saved to {out} ({len(baseline.files)} files).",
            _C.GREEN,
        )
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        print(_colour(f"[error] Baseline not found: {baseline_path}", _C.RED),
              file=sys.stderr)
        return 2

    baseline = Baseline.load(baseline_path)
    root = Path(args.path) if args.path else Path(baseline.root)
    print(f"Verifying {root} against {baseline_path}...")

    current = scan_directory(root, baseline.algorithm, _resolve_ignore(args))
    diff = compare(baseline, current)

    _print_diff(diff)

    if args.json:
        Path(args.json).write_text(json.dumps({
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "baseline": str(baseline_path),
            "modified": diff.modified,
            "added": diff.added,
            "removed": diff.removed,
        }, indent=2))
        print(f"\nJSON report written to {args.json}")

    if diff.clean:
        return 0
    return 1  # non-zero so this is usable in scripts / CI / cron


def _print_diff(diff: DiffResult) -> None:
    print()
    if diff.clean:
        print(_colour("[✓] No changes detected. Integrity verified.", _C.GREEN))
        return

    print(_colour(f"[!] {diff.total_changes} change(s) detected:", _C.BOLD))
    for rel in diff.modified:
        print(_colour(f"  MODIFIED  {rel}", _C.YELLOW))
    for rel in diff.added:
        print(_colour(f"  ADDED     {rel}", _C.GREEN))
    for rel in diff.removed:
        print(_colour(f"  REMOVED   {rel}", _C.RED))


def cmd_hash(args: argparse.Namespace) -> int:
    """Convenience: print the hash of a single file."""
    path = Path(args.file)
    try:
        print(f"{hash_file(path, args.algorithm)}  {path}")
        return 0
    except (FileNotFoundError, PermissionError) as exc:
        print(_colour(f"[error] {exc}", _C.RED), file=sys.stderr)
        return 2


def _resolve_ignore(args: argparse.Namespace) -> List[str]:
    patterns = list(DEFAULT_IGNORE)
    if getattr(args, "ignore", None):
        patterns.extend(args.ignore)
    return patterns


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="integrity_checker",
        description="Monitor files for unauthorised changes via hashing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s baseline ./data -o data.json\n"
            "  %(prog)s verify ./data -b data.json\n"
            "  %(prog)s hash ./data/config.ini\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_base = sub.add_parser("baseline", help="Create a baseline snapshot.")
    p_base.add_argument("path", help="Directory to fingerprint.")
    p_base.add_argument("-o", "--output", default="baseline.json",
                        help="Where to write the baseline (default: baseline.json).")
    p_base.add_argument("-a", "--algorithm", default=DEFAULT_ALGORITHM,
                        choices=SUPPORTED_ALGORITHMS,
                        help=f"Hash algorithm (default: {DEFAULT_ALGORITHM}).")
    p_base.add_argument("--ignore", nargs="*", metavar="GLOB",
                        help="Extra glob patterns to ignore.")
    p_base.set_defaults(func=cmd_baseline)

    p_ver = sub.add_parser("verify", help="Verify a directory against a baseline.")
    p_ver.add_argument("path", nargs="?",
                       help="Directory to check (defaults to baseline root).")
    p_ver.add_argument("-b", "--baseline", default="baseline.json",
                       help="Baseline file to compare against.")
    p_ver.add_argument("--json", metavar="FILE",
                       help="Also write a machine-readable JSON report.")
    p_ver.add_argument("--ignore", nargs="*", metavar="GLOB",
                       help="Extra glob patterns to ignore.")
    p_ver.set_defaults(func=cmd_verify)

    p_hash = sub.add_parser("hash", help="Print the hash of one file.")
    p_hash.add_argument("file", help="File to hash.")
    p_hash.add_argument("-a", "--algorithm", default=DEFAULT_ALGORITHM,
                        choices=SUPPORTED_ALGORITHMS)
    p_hash.set_defaults(func=cmd_hash)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(_colour(f"[error] {exc}", _C.RED), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
