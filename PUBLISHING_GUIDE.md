# Publishing CargoCrypt to Crates.io

## Prerequisites

1. **Create a crates.io account**: https://crates.io/login
2. **Get your API token**: https://crates.io/me (click "API Tokens")
3. **Login to cargo**: 
   ```bash
   cargo login YOUR_API_TOKEN
   ```

## Pre-Publishing Checklist

- [x] Ensure all tests pass
- [x] Update version in Cargo.toml
- [x] Update repository and homepage URLs
- [x] Ensure README.md exists and is comprehensive
- [x] Check license is specified (MIT OR Apache-2.0)
- [x] Verify keywords and categories are appropriate
- [ ] Tag the release in git

## Publishing Steps

1. **Final verification**:
   ```bash
   cd cargocrypt
   cargo publish --dry-run
   ```

2. **Create git tag**:
   ```bash
   git tag -a v0.1.0 -m "Initial release of CargoCrypt"
   git push origin v0.1.0
   ```

3. **Publish to crates.io**:
   ```bash
   cargo publish
   ```

## Post-Publishing

1. **Verify on crates.io**: https://crates.io/crates/cargocrypt
2. **Update README with installation instructions**:
   ```
   cargo install cargocrypt
   ```
3. **Create GitHub release**: https://github.com/marcuspat/cargocrypt/releases/new

## If Publishing Fails

Common issues and solutions:

### Name Already Taken
If "cargocrypt" is taken, consider:
- `cargo-crypt`
- `cargocrypt-cli`
- `rust-cargocrypt`

Update in Cargo.toml:
```toml
[package]
name = "your-chosen-name"
```

### Build Timeout
For large projects, you may need to:
```bash
# Exclude unnecessary files
echo "target/" >> .cargo-ok
echo "*.log" >> .cargo-ok
echo "tests/fixtures/large_files/*" >> .cargo-ok
```

### Missing Metadata
Ensure Cargo.toml has all required fields:
- name
- version  
- authors or publish
- license
- description
- repository or homepage

## Version Management

Follow semantic versioning:
- 0.1.0 - Initial release
- 0.1.1 - Patch fixes
- 0.2.0 - New features
- 1.0.0 - Stable API

Update version:
```bash
# In Cargo.toml
version = "0.1.1"

# Commit and tag
git add Cargo.toml
git commit -m "Bump version to 0.1.1"
git tag v0.1.1
```