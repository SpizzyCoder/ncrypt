# Repository Guidelines

## Project Structure & Module Organization
- `src/main.rs`: CLI entrypoint and command routing (`clap` subcommands).
- `src/functions.rs`: core encryption, decryption, key generation, signing, and verification flows.
- `src/functions/crypt_file_header.rs`: binary header format and parsing logic.
- `src/functions/pem_files.rs`: PEM encoding/decoding helpers for keys and signatures.
- `README.md`: usage examples and algorithm notes.
- `build-targets.sh`: cross-target release build helper; outputs to `target_binaries/`.
- `target/`: Cargo build artifacts (generated, do not edit).

## Build, Test, and Development Commands
- `cargo build`: debug build for local iteration.
- `cargo build --release`: optimized binary in `target/release/`.
- `cargo run -- encrypt -i plain.txt -o plain.txt.enc`: run CLI without installing.
- `cargo test`: run unit/integration tests.
- `cargo fmt`: apply Rust formatting.
- `cargo clippy -- -D warnings`: lint and treat warnings as errors.
- `bash build-targets.sh`: build release binaries for configured Linux/Windows targets.

## Coding Style & Naming Conventions
- Rust edition is `2021`; follow standard Rust style and keep code `rustfmt`-clean.
- Use 4-space indentation.
- Use `snake_case` for functions, variables, and module files (for example, `print_log`, `pem_files.rs`).
- Use `PascalCase` for types/enums (for example, `NCryptFileHeader`, `Command`).
- Keep functions focused; move format-specific logic to module files under `src/functions/`.

## Testing Guidelines
- Primary framework: Rust built-in test harness (`#[test]`, `cargo test`).
- Prefer small unit tests near implementation (`#[cfg(test)] mod tests` in the same file).
- Add integration tests in `tests/` for end-to-end CLI paths when behavior crosses modules.
- Name tests by behavior, for example: `decrypt_rejects_truncated_stream`.
- For crypto changes, include round-trip and corruption-detection cases.

## Commit & Pull Request Guidelines
- Current history uses short, descriptive, sentence-style subjects (for example, `Updated PEM parsing to be newline-agnostic`).
- Keep commit titles concise and scoped to one logical change.
- For each PR, include a clear summary of behavior changes.
- Add test evidence (`cargo test`, manual CLI checks).
- Link issue(s) when applicable.
- Document migration or compatibility notes for file format/header changes.

## Security & Configuration Tips
- Never commit real secrets, passwords, or private key material.
- Use disposable test files for encryption/signing examples.
- Validate output file permissions and key handling when changing key-management code.
