# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`passmng` is a local-only CLI password manager written in Rust (edition 2024). The authoritative specification is `spec/spec.md` (English). Read it before implementing or changing any feature, and follow it over assumptions; if the spec is ambiguous or contradicts the request, ask the user instead of guessing.

## Commands

- Build: `cargo build`
- Run: `cargo run -- <subcommand> [args]` (e.g. `cargo run -- search github --url`)
- Test all: `cargo test`
- Single test: `cargo test <test_name>` (e.g. `cargo test search_rejects_multiple_field_flags`)
- Lint / format: `cargo clippy`, `cargo fmt`

## Architecture

Currently a single binary in `src/main.rs`; only argument parsing exists and every subcommand prints a "未実装" placeholder.

- CLI is defined with clap derive: `Cli` → `Command` enum (one variant per subcommand in the spec's Subcommands table).
- `Target` (service name + optional `--id`) is shared by `rm` / `show` / `edit`, implementing the spec's "Entry Selection" rule: one match → use it, several → interactive ID selection, `--id` → skip selection.
- `SearchArgs` uses a clap `ArgGroup` so `--name` / `--url` / `--note` are mutually exclusive; no flag means search by service name.

Key spec constraints that shape the design (see `spec/spec.md` for details):
- No network access. All entries live in one vault file encrypted with Argon2id (KDF) + XChaCha20-Poly1305; vault dir is stored in `~/.config/passmng/config.toml`.
- (service name, ID) is the unique key, compared case-insensitively but stored as typed.
- Plaintext passwords/keys must be zeroized after use; vault writes go to a temp file then rename.
- Clipboard copies (`add`, `show`) stay resident for 30 s, then clear the clipboard only if it still holds the copied password, and also clear on Ctrl+C.
- Planned crates: `clap`, `inquire`, `rpassword`, `serde`, `argon2`, `chacha20poly1305`, `rand`, `zeroize`, `arboard`, `dirs`.

## Conventions

- Write Rust tests alongside each feature as it is implemented (`#[cfg(test)] mod tests`). CLI parsing tests use `Cli::try_parse_from` via the `parse` helper so errors can be asserted.
- Source comments must be in English (spec requirement). Note: `///` doc comments on clap items become `--help` text.
- Do not install tools on your own; propose them and let the user install them.
