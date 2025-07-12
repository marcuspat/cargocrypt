# CargoCrypt QA Test Cases

## Test Suite Overview

This document contains comprehensive test cases for validating all CargoCrypt fixes.

## 1. Filename Extension Bug Tests

### Test Case 1.1: Hidden Files (dotfiles)
**Objective**: Verify that hidden files are encrypted with correct extension
- **Input**: `.env` file
- **Expected Output**: `.env.enc` (NOT `..env.enc`)
- **Steps**:
  1. Create `.env` file with content
  2. Run `cargocrypt encrypt .env`
  3. Verify output file is named `.env.enc`
  4. Verify no file named `..env.enc` exists

### Test Case 1.2: Files with Multiple Extensions
**Objective**: Verify files with multiple dots are handled correctly
- **Input**: `config.prod.json`
- **Expected Output**: `config.prod.json.enc`
- **Steps**:
  1. Create `config.prod.json` file
  2. Run `cargocrypt encrypt config.prod.json`
  3. Verify output file is named `config.prod.json.enc`

### Test Case 1.3: Files without Extensions
**Objective**: Verify files without extensions are handled correctly
- **Input**: `README`
- **Expected Output**: `README.enc`
- **Steps**:
  1. Create `README` file
  2. Run `cargocrypt encrypt README`
  3. Verify output file is named `README.enc`

### Test Case 1.4: Decryption Filename Restoration
**Objective**: Verify original filenames are restored correctly
- **Test Files**: `.env.enc`, `config.json.enc`, `README.enc`
- **Expected**: Original filenames restored without extra dots
- **Steps**:
  1. For each encrypted file, run `cargocrypt decrypt [file]`
  2. Verify original filename is restored correctly

## 2. Password Prompting Tests

### Test Case 2.1: Password Prompt Display
**Objective**: Verify password prompt appears when no password provided
- **Command**: `cargocrypt encrypt file.txt`
- **Expected**: 
  - Prompt: "Enter password: "
  - Password input is hidden (not echoed)
  - Confirmation prompt: "Confirm password: "

### Test Case 2.2: Password Confirmation Matching
**Objective**: Verify password confirmation works correctly
- **Scenario A**: Matching passwords
  - Enter: "testpass123"
  - Confirm: "testpass123"
  - Expected: Encryption proceeds successfully
  
- **Scenario B**: Non-matching passwords
  - Enter: "testpass123"
  - Confirm: "different123"
  - Expected: Error message and re-prompt

### Test Case 2.3: Empty Password Handling
**Objective**: Verify empty passwords are rejected
- **Input**: Press Enter without typing password
- **Expected**: Error message: "Password cannot be empty"

### Test Case 2.4: Decryption Password Prompt
**Objective**: Verify decrypt prompts for password
- **Command**: `cargocrypt decrypt file.enc`
- **Expected**: Single prompt "Enter password: " (no confirmation)

### Test Case 2.5: Wrong Password Handling
**Objective**: Verify graceful handling of wrong passwords
- **Input**: Wrong password during decryption
- **Expected**: Clear error message: "Decryption failed: Invalid password"

## 3. TUI (Terminal User Interface) Tests

### Test Case 3.1: TUI Command Availability
**Objective**: Verify TUI command is recognized
- **Command**: `cargocrypt tui --help`
- **Expected**: Help text showing TUI command description

### Test Case 3.2: TUI Launch
**Objective**: Verify TUI launches without errors
- **Command**: `cargocrypt tui`
- **Expected**: 
  - TUI interface appears
  - No crash or panic
  - Basic navigation works (arrow keys, enter, escape)

### Test Case 3.3: TUI File Browser
**Objective**: Test file browsing in TUI
- **Expected Features**:
  - List files in current directory
  - Navigate with arrow keys
  - Select files with Enter
  - Show file status (encrypted/plain)

### Test Case 3.4: TUI Encrypt/Decrypt Operations
**Objective**: Test crypto operations from TUI
- **Expected**:
  - Select file and press 'e' to encrypt
  - Select encrypted file and press 'd' to decrypt
  - Password prompts appear in TUI

### Test Case 3.5: TUI Exit
**Objective**: Verify clean exit from TUI
- **Methods**:
  - Press 'q' to quit
  - Press Escape to exit
  - Ctrl+C should exit cleanly

## 4. Integration Tests

### Test Case 4.1: Full Workflow Test
**Objective**: Test complete encrypt/decrypt cycle
1. Create test file with known content
2. Calculate SHA256 hash of original
3. Encrypt file with password
4. Verify .enc file created
5. Verify original file removed/backed up
6. Decrypt file
7. Verify content matches original (same hash)

### Test Case 4.2: Batch Operations
**Objective**: Test encrypting multiple files
- **Input**: Multiple files in a directory
- **Command**: `cargocrypt encrypt *.txt`
- **Expected**: All files encrypted with correct extensions

### Test Case 4.3: Git Integration
**Objective**: Verify git-ignored files are handled
- **Setup**: Create .gitignore with `*.enc`
- **Expected**: Encrypted files automatically ignored by git

## 5. Error Handling Tests

### Test Case 5.1: File Not Found
**Objective**: Graceful handling of missing files
- **Command**: `cargocrypt encrypt nonexistent.txt`
- **Expected**: Clear error: "File not found: nonexistent.txt"

### Test Case 5.2: Permission Denied
**Objective**: Handle permission errors gracefully
- **Setup**: Create file with no read permissions
- **Expected**: Clear error: "Permission denied: cannot read file"

### Test Case 5.3: Corrupted Encrypted File
**Objective**: Handle corrupted files gracefully
- **Setup**: Create fake .enc file with random data
- **Expected**: Clear error: "File appears to be corrupted or is not a valid CargoCrypt file"

### Test Case 5.4: Disk Space
**Objective**: Handle out of disk space
- **Scenario**: Encrypt large file with limited space
- **Expected**: Clear error: "Insufficient disk space"

## 6. Performance Tests

### Test Case 6.1: Large File Handling
**Objective**: Test performance with large files
- **Sizes**: 100MB, 500MB, 1GB
- **Metrics**: Time taken, memory usage
- **Expected**: Linear performance scaling

### Test Case 6.2: Many Small Files
**Objective**: Test batch performance
- **Setup**: 1000 small files (1KB each)
- **Expected**: Efficient batch processing

## Test Execution Log Template

```
Test Case: [ID] - [Name]
Date: [YYYY-MM-DD HH:MM:SS]
Environment: [OS, CargoCrypt version]
Status: [PASS/FAIL]
Notes: [Any observations]
```

## Automated Test Script

An automated test script is available at `qa-test-plan.sh` that runs all basic tests and generates a summary report.