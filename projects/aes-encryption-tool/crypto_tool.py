#!/usr/bin/env python3
"""
Advanced Encryption Tool (AES-256-GCM)
======================================

Encrypts and decrypts files using authenticated AES-256 in GCM mode, with the
key derived from a password via scrypt. Authenticated encryption means a file
that has been tampered with will FAIL to decrypt rather than silently
returning corrupt data.

File format (all binary, concatenated):
    magic    : 4 bytes   b"AET1"          (format identifier + version)
    salt     : 16 bytes  (scrypt salt)
    nonce    : 12 bytes  (GCM nonce)
    ciphertext + GCM tag : remainder

Usage:
    python crypto_tool.py encrypt secret.pdf
    python crypto_tool.py decrypt secret.pdf.enc

Author: Siddhi Jogula
License: MIT
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:  # pragma: no cover
    sys.exit(
        "Missing dependency 'cryptography'. Install it with:\n"
        "    pip install -r requirements.txt"
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC = b"AET1"        # format magic + version
SALT_LEN = 16
NONCE_LEN = 12         # 96-bit nonce is the recommended size for GCM
KEY_LEN = 32           # 32 bytes = AES-256

# scrypt parameters. N is the CPU/memory cost; 2**15 is a reasonable
# interactive default (tune upward for higher-value secrets).
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

CHUNK_NOTE_THRESHOLD = 100 * 1024 * 1024  # warn above ~100 MB (in-memory)


# ---------------------------------------------------------------------------
# Core crypto
# ---------------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Encrypt plaintext and return the full on-disk container."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt a container produced by encrypt_bytes.

    Raises ValueError on a bad format or a failed authentication (wrong
    password or tampered file).
    """
    if blob[:4] != MAGIC:
        raise ValueError("Not a recognised AET file (bad magic bytes).")

    offset = 4
    salt = blob[offset:offset + SALT_LEN]; offset += SALT_LEN
    nonce = blob[offset:offset + NONCE_LEN]; offset += NONCE_LEN
    ciphertext = blob[offset:]

    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN or not ciphertext:
        raise ValueError("File is truncated or corrupt.")

    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:  # InvalidTag etc.
        raise ValueError(
            "Decryption failed — wrong password or the file has been modified."
        ) from exc


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------

@dataclass
class Result:
    in_path: Path
    out_path: Path
    size_in: int
    size_out: int


def _confirm_overwrite(path: Path, force: bool) -> bool:
    if not path.exists() or force:
        return True
    try:
        return input(f"{path} exists. Overwrite? [y/N] ").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def encrypt_file(in_path: Path, password: str,
                 out_path: Optional[Path] = None, force: bool = False) -> Result:
    if not in_path.is_file():
        raise FileNotFoundError(f"No such file: {in_path}")

    out_path = out_path or in_path.with_suffix(in_path.suffix + ".enc")
    if not _confirm_overwrite(out_path, force):
        raise FileExistsError(f"Refusing to overwrite {out_path}")

    data = in_path.read_bytes()
    if len(data) > CHUNK_NOTE_THRESHOLD:
        print(f"  [note] {in_path.name} is large; encrypting in memory.",
              file=sys.stderr)

    blob = encrypt_bytes(data, password)
    out_path.write_bytes(blob)
    return Result(in_path, out_path, len(data), len(blob))


def decrypt_file(in_path: Path, password: str,
                 out_path: Optional[Path] = None, force: bool = False) -> Result:
    if not in_path.is_file():
        raise FileNotFoundError(f"No such file: {in_path}")

    if out_path is None:
        # Strip a trailing .enc if present, else append .dec
        if in_path.suffix == ".enc":
            out_path = in_path.with_suffix("")
        else:
            out_path = in_path.with_suffix(in_path.suffix + ".dec")

    if not _confirm_overwrite(out_path, force):
        raise FileExistsError(f"Refusing to overwrite {out_path}")

    blob = in_path.read_bytes()
    plaintext = decrypt_bytes(blob, password)  # raises on failure
    out_path.write_bytes(plaintext)
    return Result(in_path, out_path, len(blob), len(plaintext))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class _C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _col(text: str, code: str) -> str:
    return f"{code}{text}{_C.RESET}" if sys.stdout.isatty() else text


def _get_password(confirm: bool) -> str:
    """Prompt for a password without echoing it. Optionally confirm."""
    pw = os.environ.get("AET_PASSWORD")
    if pw:
        return pw  # allow non-interactive use in scripts/CI
    pw = getpass.getpass("Password: ")
    if not pw:
        raise ValueError("Empty password.")
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if pw != again:
            raise ValueError("Passwords do not match.")
    return pw


def cmd_encrypt(args: argparse.Namespace) -> int:
    try:
        password = _get_password(confirm=True)
        res = encrypt_file(Path(args.file), password,
                           Path(args.output) if args.output else None,
                           force=args.force)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(_col(f"[error] {exc}", _C.RED), file=sys.stderr)
        return 2

    print(_col(f"[ok] Encrypted {res.in_path.name} -> {res.out_path.name} "
               f"({res.size_in} -> {res.size_out} bytes)", _C.GREEN))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    try:
        password = _get_password(confirm=False)
        res = decrypt_file(Path(args.file), password,
                           Path(args.output) if args.output else None,
                           force=args.force)
    except (FileNotFoundError, FileExistsError) as exc:
        print(_col(f"[error] {exc}", _C.RED), file=sys.stderr)
        return 2
    except ValueError as exc:
        # Authentication failure lands here — most common real-world case.
        print(_col(f"[error] {exc}", _C.RED), file=sys.stderr)
        return 3

    print(_col(f"[ok] Decrypted {res.in_path.name} -> {res.out_path.name} "
               f"({res.size_out} bytes recovered)", _C.GREEN))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crypto_tool",
        description="Encrypt/decrypt files with AES-256-GCM (password-based).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s encrypt report.pdf\n"
            "  %(prog)s decrypt report.pdf.enc\n"
            "  %(prog)s encrypt data.csv -o data.locked\n\n"
            "Set AET_PASSWORD in the environment for non-interactive use."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    e = sub.add_parser("encrypt", help="Encrypt a file.")
    e.add_argument("file", help="File to encrypt.")
    e.add_argument("-o", "--output", help="Output path (default: <file>.enc).")
    e.add_argument("-f", "--force", action="store_true",
                   help="Overwrite output without prompting.")
    e.set_defaults(func=cmd_encrypt)

    d = sub.add_parser("decrypt", help="Decrypt a file.")
    d.add_argument("file", help="File to decrypt (a .enc container).")
    d.add_argument("-o", "--output", help="Output path (default: strip .enc).")
    d.add_argument("-f", "--force", action="store_true",
                   help="Overwrite output without prompting.")
    d.set_defaults(func=cmd_decrypt)

    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
