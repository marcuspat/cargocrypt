# CargoCrypt Bug Verification Tests

## Overview

This document provides specific test procedures to verify that the three critical bugs in CargoCrypt have been fixed.

## Bug #1: Double Extension Bug (`.env` → `..env.enc`)

### Description
When encrypting hidden files (dotfiles), the system incorrectly creates filenames with double dots.

### Test Procedure

```bash
# Create test files
echo "SECRET_KEY=123" > .env
echo "config data" > .config
echo "secret" > .secret

# Run encryption (once fixed)
cargocrypt encrypt .env
cargocrypt encrypt .config
cargocrypt encrypt .secret

# Verify CORRECT behavior
ls -la | grep -E "\.env\.enc|\.config\.enc|\.secret\.enc"
# Should show: .env.enc, .config.enc, .secret.enc

# Verify INCORRECT files don't exist
ls -la | grep -E "\.\.env\.enc|\.\.config\.enc|\.\.secret\.enc"
# Should show: No results (no double dots)
```

### Expected Fix Location
- File: `src/core.rs` or similar
- Function: `encrypt_file()` method
- Issue: Incorrect handling of `Path::file_stem()` for hidden files

### Code Fix Pattern
```rust
// WRONG (current):
let encrypted_name = format!("{}.enc", path.file_stem().unwrap().to_str().unwrap());

// CORRECT (fixed):
let file_name = path.file_name().unwrap().to_str().unwrap();
let encrypted_name = format!("{}.enc", file_name);
```

## Bug #2: Missing Password Prompts

### Description
The CLI hardcodes passwords instead of prompting the user.

### Test Procedure

```bash
# Test encryption password prompt
cargocrypt encrypt secret.txt
# Expected prompts:
# Enter password: [hidden input]
# Confirm password: [hidden input]

# Test with mismatched passwords
cargocrypt encrypt secret2.txt
# Enter password: pass123
# Confirm password: different
# Expected: Error: Passwords do not match

# Test decryption password prompt
cargocrypt decrypt secret.txt.enc
# Expected prompt:
# Enter password: [hidden input]
```

### Expected Fix Location
- File: `src/main.rs`
- Lines: ~39-47 (where TODOs are)
- Dependencies: Need to add `rpassword` crate

### Code Fix Pattern
```rust
// WRONG (current):
let password = "temporary_password"; // TODO: Prompt for password

// CORRECT (fixed):
use rpassword::prompt_password;

let password = prompt_password("Enter password: ")?;
let confirm = prompt_password("Confirm password: ")?;
if password != confirm {
    return Err("Passwords do not match".into());
}
```

## Bug #3: Missing TUI Command

### Description
The TUI subcommand is not implemented in the CLI.

### Test Procedure

```bash
# Test TUI command exists
cargocrypt tui --help
# Expected: Shows help for TUI command

# Test TUI launches
cargocrypt tui
# Expected: Terminal UI appears with file browser

# Test TUI key bindings
# In TUI:
# - Arrow keys: Navigate
# - Enter: Select file
# - 'e': Encrypt selected file
# - 'd': Decrypt selected file
# - 'q' or ESC: Quit
```

### Expected Fix Location
- File: `src/main.rs`
- Add to `Commands` enum
- File: `src/tui.rs` or `src/tui/mod.rs`
- Implement the TUI module

### Code Fix Pattern
```rust
// In main.rs Commands enum:
#[derive(Subcommand)]
enum Commands {
    Init,
    Encrypt { file: PathBuf },
    Decrypt { file: PathBuf },
    Config,
    /// Launch Terminal User Interface
    Tui,  // ADD THIS
}

// In main.rs match statement:
Commands::Tui => {
    let mut tui = cargocrypt::tui::Tui::new()?;
    tui.run().await?;
}
```

## Verification Script

Run this to verify all fixes:

```bash
#!/bin/bash
echo "=== Bug Fix Verification ==="

# Bug 1: Extension test
echo -e "\n[1] Testing filename extensions..."
echo "test" > .env
if cargocrypt encrypt .env && [ -f ".env.enc" ] && [ ! -f "..env.enc" ]; then
    echo "✅ Extension bug FIXED"
else
    echo "❌ Extension bug NOT FIXED"
fi

# Bug 2: Password prompt test
echo -e "\n[2] Testing password prompts..."
echo "test" > pwd_test.txt
if echo -e "\n\n" | cargocrypt encrypt pwd_test.txt 2>&1 | grep -q "empty\|Password"; then
    echo "✅ Password prompt FIXED"
else
    echo "❌ Password prompt NOT FIXED"
fi

# Bug 3: TUI test
echo -e "\n[3] Testing TUI command..."
if cargocrypt tui --help 2>&1 | grep -q "Terminal\|TUI\|tui"; then
    echo "✅ TUI command FIXED"
else
    echo "❌ TUI command NOT FIXED"
fi

# Cleanup
rm -f .env .env.enc pwd_test.txt pwd_test.txt.enc
```

## Memory Storage for Coordination

Store test results for swarm coordination:

```bash
# After running tests, store results
npx claude-flow hooks notification --message "QA Test Results: Extension[✓/✗] Password[✓/✗] TUI[✓/✗]"
npx claude-flow hooks post-edit --file "test-results.json" --memory-key "swarm/qa/verification"
```