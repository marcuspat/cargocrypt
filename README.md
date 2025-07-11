# CargoCrypt 🔐

**Zero-config cryptographic operations for Rust projects**

CargoCrypt brings enterprise-grade cryptography to your Rust workflow with zero configuration required. Inspired by the success of tools like `cargo-audit` and `ripgrep`, it emphasizes performance, security, and developer experience.

## Quick Start

```bash
# Install
cargo install cargocrypt

# Initialize in your project (zero config!)
cargo crypt init

# Encrypt sensitive files
cargo crypt encrypt src/secrets.rs

# Decrypt when needed
cargo crypt decrypt src/secrets.rs

# Generate secure keys
cargo crypt keygen --type ed25519

# Interactive TUI mode
cargo crypt tui
```

## Features

### 🚀 Zero Configuration
- **Works out of the box** - No config files needed
- **Smart defaults** - Follows Rust ecosystem conventions
- **Git integration** - Respects `.gitignore` and hooks
- **Project detection** - Automatically finds Rust projects

### 🔒 Enterprise Security
- **Ring cryptography** - Battle-tested crypto primitives
- **Multiple algorithms** - AES-256-GCM, ChaCha20-Poly1305, Ed25519
- **Key management** - Secure key derivation and storage
- **Audit trail** - All operations are logged

### 💫 Developer Experience
- **Fast** - Rust performance with optimized release builds
- **Interactive TUI** - Beautiful terminal interface with `ratatui`
- **Progress indicators** - Visual feedback for long operations
- **Error messages** - Clear, actionable error reporting
- **Shell completion** - Bash, Zsh, Fish support

### 🔧 Rust-First Design
- **Cargo integration** - Works seamlessly with `cargo` workflows
- **Project-aware** - Understands Rust project structure
- **CI/CD friendly** - Perfect for automated workflows
- **Cross-platform** - Linux, macOS, Windows support

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
# Initialize project (creates .cargocrypt/ if needed)
cargo crypt init

# Encrypt files or directories
cargo crypt encrypt src/api_keys.rs
cargo crypt encrypt config/

# Decrypt files
cargo crypt decrypt src/api_keys.rs.enc

# List encrypted files
cargo crypt list

# Verify integrity
cargo crypt verify
```

### Key Management

```bash
# Generate new keys
cargo crypt keygen --algorithm ed25519
cargo crypt keygen --algorithm rsa4096

# Import existing keys
cargo crypt key import --file key.pem

# Export public keys
cargo crypt key export --public --format pem

# Rotate keys
cargo crypt key rotate --backup
```

### Interactive Mode

```bash
# Launch TUI
cargo crypt tui
```

The TUI provides:
- **File browser** - Navigate and select files to encrypt/decrypt
- **Key management** - Visual key generation and management
- **Progress tracking** - Real-time operation status
- **Git integration** - See which files are tracked/ignored

### Git Integration

```bash
# Setup git hooks (optional)
cargo crypt git setup

# Encrypt before commit
cargo crypt git pre-commit

# Decrypt after checkout
cargo crypt git post-checkout
```

## Configuration (Optional)

While CargoCrypt works with zero configuration, you can customize behavior:

```toml
# .cargocrypt/config.toml (optional)
[crypto]
default_algorithm = "chacha20poly1305"
key_derivation = "argon2id"

[files]
ignore_patterns = ["*.tmp", "target/"]
auto_encrypt = ["src/secrets/"]

[git]
pre_commit_hook = true
auto_decrypt = true
```

## Security

### Cryptographic Choices

- **Ring** - Industry-standard cryptographic library
- **ChaCha20-Poly1305** - Default AEAD cipher (fast, secure)
- **AES-256-GCM** - Alternative AEAD cipher (hardware accelerated)
- **Ed25519** - Default signature algorithm
- **Argon2id** - Key derivation function

### Key Storage

- **OS keychain integration** - Secure storage on macOS/Windows
- **Environment variables** - For CI/CD environments
- **File-based** - Encrypted key files with proper permissions
- **Hardware tokens** - YubiKey support (planned)

### Audit and Compliance

- **Operation logging** - All crypto operations are logged
- **Integrity verification** - Built-in file integrity checks
- **Key rotation** - Easy key rotation with backward compatibility
- **Compliance ready** - Supports SOC2, FIPS requirements

## Performance

CargoCrypt is optimized for speed:

```bash
# Benchmark on your machine
cargo crypt benchmark

# Typical performance (M1 MacBook Pro):
# Encryption: 1.2 GB/s (ChaCha20-Poly1305)
# Decryption: 1.4 GB/s (ChaCha20-Poly1305)
# Key generation: 15ms (Ed25519)
```

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

# Run integration tests
cargo test --test integration

# Benchmark
cargo bench
```

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Inspiration

CargoCrypt draws inspiration from excellent Rust tools:
- **cargo-audit** - Security-focused cargo subcommand
- **ripgrep** - Fast, user-friendly search
- **fd** - Simple, fast find alternative
- **bat** - Cat with syntax highlighting
- **exa** - Modern ls replacement

---

**Zero config. Maximum security. Pure Rust performance.**