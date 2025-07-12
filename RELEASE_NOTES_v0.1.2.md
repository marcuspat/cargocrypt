# CargoCrypt v0.1.2 Release Notes

## 🎉 Critical Bug Fixes Release

This release addresses critical issues discovered during testing that significantly impacted user experience and security.

### 🐛 Major Fixes

#### 1. **Filename Extension Bug Fixed** 🔧
- **Previous behavior**: Files like `.env` would encrypt to `.env..enc` (double dot)
- **Fixed behavior**: Files now correctly encrypt to `.env.enc`
- **Impact**: This fix ensures compatibility with documentation and user expectations

#### 2. **Security: Password Prompting Implemented** 🔐
- **Previous behavior**: All operations used hardcoded "temporary_password"
- **Fixed behavior**: 
  - Encryption now prompts for password with confirmation
  - Decryption prompts for password
  - Passwords are securely handled using `rpassword`
- **Impact**: Major security improvement - CargoCrypt is now safe for real-world use

#### 3. **TUI Command Now Accessible** 🖥️
- **Previous behavior**: TUI code existed but `cargocrypt tui` command was not available
- **Fixed behavior**: `cargocrypt tui` now launches the interactive terminal interface
- **Impact**: Users can now access the beautiful TUI dashboard as documented

### 📦 Installation

```bash
cargo install cargocrypt --version 0.1.2
```

### 🚀 Usage Examples

#### Secure Encryption with Password Prompt
```bash
$ cargocrypt encrypt .env
Enter password for encryption: ****
Confirm password: ****
✅ File encrypted: .env.enc
```

#### Interactive TUI Mode
```bash
$ cargocrypt tui
# Launches the interactive terminal interface
```

### 🙏 Acknowledgments

Thank you to the early adopters who reported these critical issues. Your feedback helps make CargoCrypt better for everyone!

### 📋 Full Changelog

See [CHANGELOG.md](./cargocrypt/CHANGELOG.md) for complete version history.

### 🔜 Coming Next

- Advanced Git integration for team secret sharing
- ML-powered secret detection to prevent accidental commits
- Performance optimizations for large repositories
- Enhanced TUI features and visualizations

---

**Note**: This is a critical update. All users of v0.1.0 and v0.1.1 should upgrade immediately to ensure proper security and functionality.