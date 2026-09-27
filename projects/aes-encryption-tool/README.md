# Advanced Encryption Tool (AES-256-GCM)

A command-line tool that encrypts and decrypts files using **authenticated AES-256 encryption**, with the key derived from a password. Tamper-evident by design: a file that has been modified — even by a single byte — will refuse to decrypt rather than returning corrupt data.

> Built as Task 4 of the Elite Tech Intern cybersecurity internship, implemented with correct, modern cryptographic practice.

## Why this is done "the right way"

Many beginner AES tools quietly use ECB mode or unauthenticated CBC, which leak patterns and can't detect tampering. This tool avoids those traps:

| Choice | Why it matters |
|--------|----------------|
| **AES-256-GCM** | Authenticated encryption (AEAD) — provides both confidentiality *and* integrity. Wrong password or a tampered file → decryption fails loudly. |
| **scrypt key derivation** | Passwords aren't used as keys directly. scrypt is memory-hard, making brute-forcing the password expensive. |
| **Random salt per file** | The same password produces a different key every time, so identical files don't yield identical ciphertext. |
| **Random 96-bit nonce per file** | Never reuses a nonce with the same key — a critical GCM requirement. |
| **Uses the `cryptography` library** | Battle-tested primitives instead of hand-rolled crypto (the golden rule: *don't roll your own crypto*). |

## File format

Every encrypted file is a self-describing binary container:

```
+--------+----------+-----------+------------------------------+
| "AET1" |  salt    |  nonce    | ciphertext + GCM auth tag    |
| 4 bytes| 16 bytes | 12 bytes  | remainder                    |
+--------+----------+-----------+------------------------------+
```

The salt and nonce are stored alongside the ciphertext (they're not secret — only the password is), so decryption needs nothing but the file and the password.

## Installation

```bash
git clone https://github.com/<your-username>/aes-encryption-tool.git
cd aes-encryption-tool
pip install -r requirements.txt
```

## Usage

### Encrypt

```bash
python3 crypto_tool.py encrypt report.pdf
# prompts for a password (twice), writes report.pdf.enc
```

### Decrypt

```bash
python3 crypto_tool.py decrypt report.pdf.enc
# prompts for the password, writes report.pdf
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output PATH` | Custom output path |
| `-f, --force` | Overwrite the output file without prompting |

### Non-interactive / scripting

Set the password in the environment (useful for automation, avoids it appearing in shell history):

```bash
AET_PASSWORD="your-passphrase" python3 crypto_tool.py encrypt data.csv -f
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | File/usage error (missing file, refused overwrite) |
| `3` | Decryption failed — wrong password or tampered file |

## Verified behaviour

The tool has been tested for:

- **Round-trip integrity** — decrypted output is byte-identical to the original.
- **Wrong-password handling** — fails cleanly with a clear message, never emits garbage.
- **Tamper detection** — flipping any byte of the ciphertext or auth tag causes decryption to fail.

## Security notes & limitations

- The whole file is read into memory, so extremely large files (multi-GB) aren't ideal — a streaming/chunked mode would be the next enhancement.
- Password strength is on you: AES-256 is irrelevant if the passphrase is `password123`. Use a long, unique passphrase.
- There is no password recovery. If you lose the password, the data is gone — that's the point.
- scrypt cost parameter `N` is set for interactive use (`2**15`); raise it for higher-value secrets.

## License

MIT — see [LICENSE](LICENSE).
