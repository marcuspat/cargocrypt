# Changelog

All notable changes to CargoCrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

Not published. A hardening release: most of it fixes things that did not do
what the documentation said. Upgrading from 0.2.3 needs attention; see
"Changed" and "Removed".

### Security

- Git filters encrypted under the constant password `"default-password"`
  when none was configured. They now fail.
- Team keys were wrapped under the constant password `"team_key_password"`
  and committed, so any clone could read them. They are now sealed to each
  member's X25519 public key and need that member's secret key to open.
- The team "signature" was an HMAC under a constant, and "access tokens"
  were encrypted under another constant. Both are removed.
- Security profiles had no effect: every profile derived the Balanced key
  (and ran Argon2 twice). The profile now sets the Argon2id cost, which is
  recorded in the file.
- Encrypted files and metadata are authenticated end to end: header and
  metadata are associated data; truncated, reordered or extended files are
  rejected.
- `encrypt` left a world-readable plaintext `.backup` beside every encrypted
  file by default. Backups are now opt-in and written `0600`.
- Output files are written to a private temporary file and renamed, so a
  failed decryption leaves no partial plaintext.
- Passwords were trimmed of whitespace, and could be read from clear text in
  `git config`. Neither happens now.
- Dependency advisories: 4 vulnerabilities and 11 warnings reported by
  `cargo audit` reduced to 1 warning (`bincode` 1.x unmaintained, kept to
  read old files).

### Added

- `cargocrypt scan`: secret scanning with text, JSON and SARIF output,
  `--staged`, `--baseline`, `.cargocryptignore` and inline `cargocrypt:allow`.
  Rules for current GitHub, Anthropic, OpenAI, Google, npm, Slack and Stripe
  token formats.
- `cargocrypt verify`: authenticate an encrypted file without writing
  plaintext.
- `cargocrypt rekey`: change password and/or profile in place, with plaintext
  held only in memory; upgrades files written by earlier versions.
- `cargocrypt completions <shell>`.
- `--password-file` and `CARGOCRYPT_PASSWORD_FILE`.
- Streaming encryption: memory use no longer grows with file size.
- `crypto::envelope`: sealing to an X25519 public key.
- Property tests, fuzz targets, known-answer tests, a labelled scanner
  corpus; CI jobs for all-target lints, minimum Rust version, cargo-deny,
  fuzz smoke runs and a scan of the repository itself.

### Changed

- **File format.** New files use container version 3 (files) or 2 (secrets)
  with XChaCha20-Poly1305. Files written by 0.2.3 are still read; convert
  them with `cargocrypt rekey`. 0.2.3 cannot read files written by 0.3.0.
- `.cargocrypt/config.toml` is now read. It was written by `init` and then
  ignored, so settings in existing files take effect for the first time.
- `backup_originals` defaults to `false`.
- `--password-stdin` no longer trims whitespace.
- `.gitattributes` entries are written as `filter=cargocrypt-encrypt`.
  Entries written by earlier versions never activated the filter; run
  `cargocrypt git configure-attributes` again.
- The pre-commit hook runs `cargocrypt scan --staged`. Reinstall it with
  `cargocrypt git install-hooks`: the earlier hook rejected every commit.
- The scanner reports far less: identifiers, hashes, lock files, public keys
  and plain URLs are no longer findings.
- Minimum supported Rust version is 1.88.
- `git2` 0.21, `ratatui` 0.30, `crossterm` 0.29.
- `TeamKeySharing::get_shared_key` takes the member's secret key;
  `add_member` rejects a malformed public key and no longer hands over
  existing keys (use `grant_key`).
- `EncryptedSecret::nonce()` returns `&[u8]`.

### Removed

- `EncryptedSecret::set_metadata` (metadata is authenticated).
- Reading the filter password from `git config cargocrypt.password`.
- `crypto::mock` (it was empty) and `From<reqwest::Error>`.
- The detection rule for SSH public keys, and the rule that treated any
  40-character hex string as a GitHub token.
- Unused dependencies: `reqwest`, `rustls`, `rustls-webpki`, `dialoguer`,
  `indicatif`, `console`.
- `benches/vs_rustyvault.rs`, which compared against a simulated competitor.

### Known limitations

- No independent security audit.
- Team member records and the audit log are not signed, and team operations
  have no command-line interface.
- The monitoring dashboard displays sample data.
- Git clean-filter output is randomised, so git may show a filtered file as
  modified.
- The terminal UI was not tested interactively after the `ratatui` upgrade.

## [0.2.0] to [0.2.3]

No changelog entries were written for these releases.

## [0.1.2] - 2025-01-12

### Fixed
- **Critical**: Fixed filename extension bug that caused double dots in encrypted filenames (e.g., `.env..enc` instead of `.env.enc`)
- **Security**: Replaced hardcoded temporary password with secure password prompting using rpassword
- **Feature**: Integrated TUI command that was previously inaccessible despite existing code

### Added
- Password prompting with confirmation for encryption operations
- Password prompting for decryption operations
- `cargocrypt tui` command to launch the interactive terminal interface

### Changed
- Improved filename handling logic for both regular files and dotfiles
- Enhanced security by ensuring all encryption operations require user-provided passwords

### Security
- Removed hardcoded "temporary_password" from encryption/decryption operations
- Added password confirmation step for encryption to prevent typos

## [0.1.1] - 2025-01-11

### Fixed
- Critical documentation error: corrected command from 'cargo crypt' to 'cargocrypt'

### Changed
- Updated README with correct usage instructions

## [0.1.0] - 2025-01-11

### Added
- Initial release of CargoCrypt
- Zero-config cryptographic operations for Rust projects
- ChaCha20-Poly1305 encryption with Argon2id key derivation
- Basic CLI commands: init, encrypt, decrypt, config
- Automatic backup creation before encryption
- Project detection (requires Cargo.toml)
- Comprehensive error handling with recovery suggestions

### Features
- Memory-safe secret handling with automatic zeroization
- Async-first architecture using Tokio
- Beautiful terminal output with color support
- Cross-platform support (Windows, macOS, Linux)