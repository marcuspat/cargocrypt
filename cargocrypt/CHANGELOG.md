# Changelog

All notable changes to CargoCrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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