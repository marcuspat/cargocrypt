# CargoCrypt 🔐

**Zero-config cryptographic operations for Rust projects**

[![Crates.io](https://img.shields.io/crates/v/cargocrypt.svg)](https://crates.io/crates/cargocrypt)
[![License](https://img.shields.io/crates/l/cargocrypt.svg)](LICENSE-MIT)

CargoCrypt brings enterprise-grade cryptography to your Rust workflow with zero configuration required. Inspired by the success of tools like `cargo-audit` and `ripgrep`, it emphasizes performance, security, and developer experience.

> ⚠️ **Current Status**: Early development (v0.1.2) - Core encryption/decryption works, but some features are still in progress.

## Recent Updates

### v0.1.2 (Current)
- Fixed critical filename extension handling
- Improved password security
- Enhanced TUI integration
- Published to crates.io

### v0.1.1
- Initial release with basic encryption/decryption
- Zero-config initialization
- ChaCha20-Poly1305 support

## Quick Start

```bash
# Install
cargo install cargocrypt

# Initialize in your project (zero config!)
cargocrypt init

# Encrypt sensitive files
cargocrypt encrypt src/secrets.rs

# Decrypt when needed
cargocrypt decrypt src/secrets.rs

# Generate secure keys
cargocrypt keygen --type ed25519

# Interactive TUI mode
cargocrypt tui
```

## Features

### ✅ Working Features
- **Zero Configuration** - Works out of the box, no config files needed
- **ChaCha20-Poly1305 encryption** - Fast, secure authenticated encryption
- **Argon2id key derivation** - Industry-standard password-based key derivation
- **Project initialization** - `cargocrypt init` sets up your project
- **Interactive TUI** - Beautiful terminal interface with `ratatui`
- **Secure defaults** - Balanced security/performance out of the box

### 🚧 In Development
- **Git integration** - Hooks and filters (partially implemented)
- **Multiple algorithms** - Currently only ChaCha20-Poly1305 is available
- **Key management** - Advanced key storage and rotation
- **Shell completion** - Command-line completion for shells
- **Audit trail** - Operation logging
- **CI/CD support** - Non-interactive password input for automation

### 🔧 Technical Details
- **Built with Ring** - Battle-tested crypto primitives
- **Cross-platform** - Linux, macOS, Windows support
- **Rust-first design** - Integrates with Cargo workflows
- **Memory-safe** - Secure secret handling with zeroization

## Philosophy

CargoCrypt follows the **zero-config philosophy** pioneered by successful Rust tools:

- **Convention over configuration** - Smart defaults that just work
- **Performance by default** - Optimized for speed and memory usage
- **Security by design** - Secure defaults, no foot-guns
- **Developer happiness** - Intuitive commands and helpful output

## Installation

### From crates.io
```bash
cargo install cargocrypt
```

### From source
```bash
git clone https://github.com/cargocrypt/cargocrypt
cd cargocrypt
cargo install --path .
```

### Binary releases
Download from [GitHub Releases](https://github.com/cargocrypt/cargocrypt/releases)

## Usage

### Basic Operations

```bash
# Initialize project (creates .cargocrypt/ directory)
cargocrypt init

# Encrypt a file (interactive password prompt)
cargocrypt encrypt src/api_keys.rs
# Creates: src/api_keys.rs.enc

# Decrypt a file (interactive password prompt)
cargocrypt decrypt src/api_keys.rs.enc
# Restores: src/api_keys.rs

# Show current configuration
cargocrypt config
```

### Advanced Usage (Planned)

```bash
# These features are planned for future releases:

# Encrypt directories
cargocrypt encrypt config/

# List encrypted files
cargocrypt list

# Key management
cargocrypt keygen --algorithm ed25519
cargocrypt key rotate
```

### Interactive Mode

```bash
# Launch TUI (Terminal User Interface)
cargocrypt tui
```

The TUI provides:
- **File browser** - Navigate and select files to encrypt/decrypt
- **Visual operations** - See encryption/decryption in progress
- **Password entry** - Secure password input with confirmation
- **Configuration view** - See current settings

> Note: Some TUI features like key management and git integration are still in development.

## Configuration (Optional)

While CargoCrypt works with zero configuration, you can customize behavior by creating `.cargocrypt/config.toml`:

```toml
# .cargocrypt/config.toml (optional)
[crypto]
# Performance profile: "fast", "balanced", "secure", "paranoid"
performance_profile = "balanced"

[security]
# Fail secure - abort on any security warnings
fail_secure = true

[file_ops]
# Keep backup of original files
backup_originals = true
```

> Note: Configuration file support is implemented but limited. More options will be added in future releases.

## Security

### Cryptographic Implementation

- **Ring** - Industry-standard cryptographic library
- **ChaCha20-Poly1305** - Fast, secure AEAD cipher
- **Argon2id** - Memory-hard key derivation function
- **Secure randomness** - Uses Ring's secure RNG
- **Constant-time operations** - Protection against timing attacks

### Key Derivation Parameters

CargoCrypt offers multiple security profiles:

| Profile  | Memory Cost | Time Cost | Parallelism | Use Case |
|----------|------------|-----------|-------------|----------|
| Fast     | 4 MB       | 1 iter    | 8 threads   | Testing  |
| Balanced | 64 MB      | 3 iter    | 4 threads   | Default  |
| Secure   | 256 MB     | 4 iter    | 4 threads   | Sensitive data |
| Paranoid | 1 GB       | 10 iter   | 4 threads   | Maximum security |

### Security Considerations

- **Password strength** - Use strong passwords; the tool doesn't enforce password policies yet
- **Memory protection** - Secrets are zeroized on drop using the `zeroize` crate
- **No key storage** - Keys are derived from passwords; no permanent key storage yet
- **File permissions** - Encrypted files maintain original permissions

## Performance

CargoCrypt delivers excellent performance with security:

### Benchmark Results

Run benchmarks with: `cargo run --example performance_test --release`

**Encryption/Decryption (with Argon2 key derivation):**
- 1 MB file: ~210ms encryption, ~105ms decryption
- 10 MB file: ~220ms encryption, ~110ms decryption
- Throughput: 4-45 MB/s (includes key derivation overhead)

**Raw ChaCha20-Poly1305 Performance (without key derivation):**
- Encryption: 1.0-1.2 GB/s
- Decryption: 1.0-1.3 GB/s
- Near-native performance for the cipher itself

**Key Derivation Times:**
- Fast profile: ~110ms (4 MB memory)
- Balanced profile: ~225ms (64 MB memory) - **Default**
- Secure profile: ~810ms (256 MB memory)
- Paranoid profile: ~6.8s (1 GB memory)

> Note: The key derivation is the primary performance bottleneck by design - it protects against brute-force attacks.

## Known Issues & Limitations

### Current Limitations
- **TTY required** - Password prompts require an interactive terminal (no piped passwords yet)
- **Single algorithm** - Only ChaCha20-Poly1305 is implemented (no AES-GCM yet)
- **No key files** - Passwords only; no support for key files or hardware tokens
- **Limited git integration** - Git hooks and filters are partially implemented
- **No directory encryption** - Only individual files are supported

### Platform Notes
- **Windows** - Tested on Windows 10/11, should work but less tested than Linux/macOS
- **CI/CD** - Non-interactive mode not yet supported (requires TTY for passwords)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development

```bash
# Clone and build
git clone https://github.com/cargocrypt/cargocrypt
cd cargocrypt
cargo build

# Run tests
cargo test

# Run benchmarks
cargo run --example performance_test --release

# Build release version
cargo build --release
```

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Roadmap

### Version 0.2.0 (Planned)
- [ ] Non-interactive mode for CI/CD
- [ ] AES-256-GCM support
- [ ] Directory encryption
- [ ] Key file support

### Version 0.3.0 (Planned)
- [ ] Full git integration (hooks, filters)
- [ ] Team key sharing
- [ ] Hardware token support
- [ ] Shell completions

### Version 1.0.0 (Future)
- [ ] Stable API
- [ ] Comprehensive key management
- [ ] Audit logging
- [ ] Plugin system

## Inspiration

CargoCrypt draws inspiration from excellent Rust tools:
- **cargo-audit** - Security-focused cargo subcommand
- **ripgrep** - Fast, user-friendly search
- **bat** - Modern take on cat
- **exa** - Modern ls replacement

The goal is to make cryptography as easy to use as these everyday tools.

---

**Zero config. Maximum security. Pure Rust.**