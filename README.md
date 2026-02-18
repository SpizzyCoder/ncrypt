# ncrypt

`ncrypt` is a CLI tool for file encryption/decryption and detached signatures.

It supports:
- Password-based encryption (Argon2-derived key)
- Raw keyfile-based encryption
- Optional Snappy compression before encryption
- Ed25519 keypair generation, signing, and verification
- Header inspection for encrypted files

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Formats and Algorithms](#formats-and-algorithms)
- [Build and Development](#build-and-development)
- [Security Notes](#security-notes)

## Installation

### Build from source
Requires Rust (edition 2021) and Cargo.

```bash
cargo build --release
```

Binary output:
- Linux/macOS: `target/release/ncrypt`
- Windows: `target/release/ncrypt.exe`

### Optional cross-target build helper
```bash
bash build-targets.sh
```

Artifacts are written to `target_binaries/`.

## Quick Start

### 1. Encrypt with password
```bash
ncrypt encrypt -i secret.txt -o secret.txt.enc
```
You will be prompted for a password.

### 2. Decrypt with password
```bash
ncrypt decrypt -i secret.txt.enc -o secret.txt
```

### 3. Encrypt with a generated keyfile
```bash
ncrypt gen-keyfile -o keyfile.pem
ncrypt encrypt -k keyfile.pem -i secret.txt -o secret.txt.enc
ncrypt decrypt -k keyfile.pem -i secret.txt.enc -o secret.txt
```

### 4. Sign and verify a file
```bash
ncrypt gen-keypair -p main
ncrypt sign -p main_prvkey.pem -i document.txt -o document.txt.sig
ncrypt verify -p main_pubkey.pem -i document.txt -s document.txt.sig
```

On successful verification, `verify` prints `Match`.

## Command Reference

Global options:
- `-v`, `--verbose`: enable verbose logs

### `encrypt`
Encrypt a file with password (default) or keyfile.

```bash
ncrypt encrypt [OPTIONS] -i <INPUTFILE> -o <OUTPUTFILE>
```

Options:
- `-c`: enable Snappy compression before encryption
- `-k <KEYFILE>`: use key from custom keyfile PEM
- `-i <INPUTFILE>`: input file path
- `-o <OUTPUTFILE>`: output file path
- `-t <TIME_COST_ARGON2>`: Argon2 time cost (default `100`, supported range `1..=1000`)

Examples:
```bash
ncrypt encrypt -i notes.txt -o notes.txt.enc
ncrypt encrypt -c -i notes.txt -o notes.txt.enc
ncrypt encrypt -k keyfile.pem -i notes.txt -o notes.txt.enc
```

### `decrypt`
Decrypt a file with password (default) or keyfile.

```bash
ncrypt decrypt [OPTIONS] -i <INPUTFILE> -o <OUTPUTFILE>
```

Options:
- `-k <KEYFILE>`: keyfile PEM (required for keyfile-encrypted data)
- `-i <INPUTFILE>`: encrypted input file
- `-o <OUTPUTFILE>`: decrypted output file

### `gen-keyfile`
Generate a random 32-byte symmetric key and store it as PEM.

```bash
ncrypt gen-keyfile -o <OUTPUTFILE>
```

Options:
- `-o <OUTPUTFILE>`: destination keyfile path

### `gen-keypair`
Generate an Ed25519 keypair.

```bash
ncrypt gen-keypair [OPTIONS] -p <PREFIX>
```

Options:
- `-p <PREFIX>`: output prefix
- `-o <OUTPUTDIR>`: output directory (default `.`)

Outputs:
- `<PREFIX>_prvkey.pem`
- `<PREFIX>_pubkey.pem`

### `read-header`
Read and print the metadata header from an encrypted file.

```bash
ncrypt read-header -i <INPUTFILE>
```

Options:
- `-i <INPUTFILE>`: encrypted file to inspect

### `sign`
Create a detached signature for a file.

```bash
ncrypt sign -p <PRIVATE_KEY> -i <INPUTFILE> -o <OUTPUTFILE>
```

Options:
- `-p <PRIVATE_KEY>`: Ed25519 private key PEM
- `-i <INPUTFILE>`: file to sign
- `-o <OUTPUTFILE>`: signature output file

### `verify`
Verify a detached signature.

```bash
ncrypt verify -p <PUBLIC_KEY> -i <INPUTFILE> -s <SIGNATUREFILE>
```

Options:
- `-p <PUBLIC_KEY>`: Ed25519 public key PEM
- `-i <INPUTFILE>`: file to verify
- `-s <SIGNATUREFILE>`: detached signature file

## Formats and Algorithms

### Algorithms used
- Encryption: `XChaCha20-Poly1305`
- Password KDF: `Argon2`
- Signatures: `Ed25519`
- File hashing for signatures and header MAC derivation: `BLAKE3`
- Optional compression: `Snappy`

### Encrypted file structure (high level)
1. Header (`NCRYPT` signature, version, mode, compression, Argon2 time cost, nonce, optional password salt)
2. Header MAC (BLAKE3 keyed hash)
3. Encrypted stream chunks:
   - encrypted chunk length
   - encrypted chunk data
4. Authenticated end-of-stream marker

The decryptor rejects:
- Header MAC mismatch
- Truncated stream (missing end marker)
- Corrupted chunk length/chunk data
- Trailing bytes after end marker

### PEM formats
`ncrypt` uses custom PEM wrappers for symmetric keyfiles and signatures:
- Keyfile:
  - `----- BEGIN NCRYPT KEYFILE -----`
  - `----- END NCRYPT KEYFILE -----`
- Signature:
  - `----- BEGIN NCRYPT SIGNATURE -----`
  - `----- END NCRYPT SIGNATURE -----`

## Build and Development

Common commands:
```bash
cargo build
cargo build --release
cargo test
cargo fmt
cargo clippy -- -D warnings
```

Run directly with Cargo:
```bash
cargo run -- encrypt -i plain.txt -o plain.txt.enc
```

## Security Notes

- Keep private keys and keyfiles protected and out of version control.
- Password mode stores a random salt in the file header; this is expected.
- Use strong, unique passwords for password-based encryption.
- Prefer keyfiles for automated workflows where password prompting is not practical.
- Verification checks file content against the detached signature and public key; any content changes should fail verification.
