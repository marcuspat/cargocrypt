# CargoCrypt Comprehensive Testing Guide

This document provides a complete testing procedure to validate all aspects of CargoCrypt functionality.

## Prerequisites

Ensure you have the following installed:
- Rust 1.70+ (`rustup update stable`)
- Git
- A test directory with sample files

## 1. Initial Setup & Installation

```bash
# Clone the repository
git clone https://github.com/marcuspat/cargocrypt.git
cd cargocrypt

# Build in release mode for optimal performance
cd cargocrypt
cargo build --release

# Run basic tests to ensure compilation
cargo test --lib -- --test-threads=1
```

## 2. Unit Test Execution

### Run All Tests (Small Batches to Avoid Timeouts)

```bash
# Core module tests
cargo test --lib core:: -- --test-threads=1

# Error handling tests
cargo test --lib error:: -- --test-threads=1

# Cryptography tests (excluding performance-heavy tests)
cargo test --lib crypto:: -- --test-threads=1 --skip performance_profiles

# Detection module tests
cargo test --lib detection:: -- --test-threads=1

# Git integration tests
cargo test --lib git:: -- --test-threads=1
```

### Run Specific Test Categories

```bash
# Basic encryption/decryption tests
cargo test --lib test_crypto_engine_basic_operations -- --nocapture

# Key derivation tests
cargo test --lib test_key_derivation -- --nocapture

# Secret detection tests
cargo test --lib test_pattern_matching -- --nocapture

# Error handling tests
cargo test --lib test_error_constructors -- --nocapture
```

## 3. Integration Testing

### Setup Test Environment

```bash
# Create a test project
mkdir -p ~/cargocrypt-test
cd ~/cargocrypt-test
cargo init --name test-project

# Create test files
echo "SECRET_API_KEY=fake_test_key_123456789" > .env
echo "password123" > secrets.txt
echo "normal content" > readme.txt
mkdir config
echo "database_password=sup3rs3cr3t" > config/database.yml
```

### Test Basic Functionality

```bash
# Initialize CargoCrypt in the project
cargocrypt init

# Test file encryption
cargocrypt encrypt .env
# Enter password when prompted

# Verify encrypted file exists
ls -la .env.enc

# Test file decryption
cargocrypt decrypt .env.enc
# Enter same password

# Compare original and decrypted
diff .env .env.decrypted
```

### Test Secret Detection

```bash
# Create a file with various secret patterns
cat > test_secrets.js << 'EOF'
const apiKey = "fake_live_key_987654321";
const password = "admin123";
const dbUrl = "postgresql://user:pass@localhost/db";
const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
EOF

# Run secret detection
cargocrypt detect test_secrets.js
```

### Test Git Integration

```bash
# Initialize git repo
git init
git add .
git commit -m "Initial commit"

# Setup CargoCrypt git integration
cargocrypt init --git

# Verify .gitignore was updated
cat .gitignore | grep cargocrypt

# Test encrypted file staging
cargocrypt encrypt secrets.txt
git status  # Should show .enc file, not original
```

## 4. Performance Testing

### Encryption Performance

```bash
# Create files of various sizes
dd if=/dev/urandom of=test_1mb.bin bs=1M count=1
dd if=/dev/urandom of=test_10mb.bin bs=1M count=10
dd if=/dev/urandom of=test_100mb.bin bs=1M count=100

# Time encryption operations
time cargocrypt encrypt test_1mb.bin
time cargocrypt encrypt test_10mb.bin
time cargocrypt encrypt test_100mb.bin
```

### Key Derivation Performance

```bash
# Test different performance profiles
cat > perf_test.sh << 'EOF'
#!/bin/bash
echo "Testing key derivation performance..."

# Create test config for each profile
for profile in fast balanced secure paranoid; do
    echo "Profile: $profile"
    time echo "test" | cargocrypt encrypt --profile $profile test.txt
    echo ""
done
EOF

chmod +x perf_test.sh
./perf_test.sh
```

## 5. Security Testing

### Password Strength Testing

```bash
# Test weak passwords (should warn or reject)
echo "test" | cargocrypt encrypt --password "123" sensitive.txt

# Test strong passwords
echo "test" | cargocrypt encrypt --password "Str0ng!P@ssw0rd#2024" sensitive.txt
```

### Tamper Detection

```bash
# Encrypt a file
echo "important data" > important.txt
cargocrypt encrypt important.txt

# Tamper with encrypted file
echo "corrupted" >> important.txt.enc

# Try to decrypt (should fail with authentication error)
cargocrypt decrypt important.txt.enc
```

## 6. CLI Feature Testing

### Help and Documentation

```bash
# Test help commands
cargocrypt --help
cargocrypt encrypt --help
cargocrypt detect --help
```

### Configuration

```bash
# Show current configuration
cargocrypt config

# Test configuration validation
cargocrypt config set performance_profile invalid_value
```

## 7. Error Handling Testing

### File Not Found

```bash
cargocrypt encrypt nonexistent.txt
```

### Invalid Encrypted Files

```bash
echo "not encrypted" > fake.enc
cargocrypt decrypt fake.enc
```

### Permission Errors

```bash
# Create read-only file
touch readonly.txt
chmod 444 readonly.txt
cargocrypt encrypt readonly.txt
```

## 8. Batch Operations Testing

```bash
# Create multiple files
for i in {1..10}; do
    echo "secret data $i" > secret_$i.txt
done

# Batch encrypt
cargocrypt encrypt secret_*.txt

# Verify all encrypted
ls -la secret_*.enc | wc -l  # Should be 10
```

## 9. Memory Safety Testing

Run with memory sanitizers (requires nightly Rust):

```bash
# Build with address sanitizer
RUSTFLAGS="-Z sanitizer=address" cargo +nightly build --target x86_64-unknown-linux-gnu

# Run tests with sanitizer
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu
```

## 10. Benchmarking

```bash
# Run built-in benchmarks
cargo bench --features benchmark

# Profile specific operations
cargo bench --bench crypto_operations
cargo bench --bench detection_performance
```

## Expected Results

### Successful Test Indicators
- ✅ All unit tests pass (except CPU-intensive ones on limited resources)
- ✅ Encryption/decryption produces identical files
- ✅ Secret detection finds all planted secrets
- ✅ Git integration properly ignores encrypted files
- ✅ Performance meets targets (<1ms for small file encryption)
- ✅ Tampered files fail authentication
- ✅ Error messages are clear and actionable

### Performance Targets
- Small files (<1MB): <10ms encryption/decryption
- Medium files (1-10MB): <100ms encryption/decryption  
- Large files (>100MB): <1s encryption/decryption
- Key derivation: <100ms for balanced profile

## Troubleshooting

### Test Timeouts
If tests timeout, try:
- Run with `--release` flag for better performance
- Use `--test-threads=1` to reduce CPU load
- Skip performance-heavy tests with `--skip performance`

### Build Failures
- Ensure Rust 1.70+ is installed
- Run `cargo clean` and rebuild
- Check all dependencies with `cargo tree`

### Platform-Specific Issues
- **macOS**: May need to allow terminal access in Security settings
- **Linux**: Ensure libssl-dev is installed
- **Windows**: Use PowerShell or Git Bash for best results

## Continuous Testing

For CI/CD integration:

```yaml
# Example GitHub Actions workflow
name: Test CargoCrypt
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
      - run: cargo test --lib -- --test-threads=2
      - run: cargo test --doc
      - run: cargo clippy -- -D warnings
```

## Report Issues

If you encounter any issues during testing:
1. Check the error message and suggestion
2. Review the troubleshooting section
3. File an issue at: https://github.com/marcuspat/cargocrypt/issues

Include:
- Error message
- Steps to reproduce
- System information (OS, Rust version)
- Test output logs