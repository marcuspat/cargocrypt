#!/bin/bash
# Comprehensive CargoCrypt Feature Testing Script
# Tests every documented feature and command
# Creates detailed test output report

# Script Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="/tmp/cargocrypt_test_$$"
OUTPUT_FILE="$SCRIPT_DIR/test_output_comprehensive.txt"
CARGOCRYPT_DIR="$SCRIPT_DIR/cargocrypt"
BINARY="cargocrypt"  # Will use installed version first, fallback to local build

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Initialize output file
init_output() {
    cat > "$OUTPUT_FILE" << EOF
================================================================================
                     CargoCrypt Comprehensive Feature Test Report
================================================================================
Date: $(date)
Host: $(hostname)
OS: $(uname -s) $(uname -r)
User: $(whoami)
Test Directory: $TEST_DIR
================================================================================

EOF
}

# Helper functions
log() {
    echo "$1" | tee -a "$OUTPUT_FILE"
}

log_test() {
    echo -e "\n--- Test: $1 ---" | tee -a "$OUTPUT_FILE"
}

log_success() {
    echo -e "${GREEN}✓ PASS:${NC} $1" | tee -a "$OUTPUT_FILE"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}✗ FAIL:${NC} $1" | tee -a "$OUTPUT_FILE"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${YELLOW}⚠ SKIP:${NC} $1" | tee -a "$OUTPUT_FILE"
    ((TESTS_SKIPPED++))
}

log_info() {
    echo -e "${BLUE}ℹ INFO:${NC} $1" | tee -a "$OUTPUT_FILE"
}

run_command() {
    local cmd="$1"
    local desc="$2"
    log_info "Running: $cmd"
    echo "Command: $cmd" >> "$OUTPUT_FILE"
    echo "Output:" >> "$OUTPUT_FILE"
    if eval "$cmd" >> "$OUTPUT_FILE" 2>&1; then
        return 0
    else
        return 1
    fi
}

# Setup test environment
setup_test_env() {
    log "\nSetting up test environment..."
    
    # Create test directory
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"
    
    # Check for cargocrypt binary
    if command -v cargocrypt >/dev/null 2>&1; then
        BINARY="cargocrypt"
        log_info "Using installed cargocrypt: $(which cargocrypt)"
    elif [ -f "$CARGOCRYPT_DIR/target/debug/cargocrypt" ]; then
        BINARY="$CARGOCRYPT_DIR/target/debug/cargocrypt"
        log_info "Using debug build: $BINARY"
    elif [ -f "$CARGOCRYPT_DIR/target/release/cargocrypt" ]; then
        BINARY="$CARGOCRYPT_DIR/target/release/cargocrypt"
        log_info "Using release build: $BINARY"
    else
        log_fail "CargoCrypt binary not found!"
        log_info "Please install with: cargo install cargocrypt"
        exit 1
    fi
    
    # Verify binary works
    if $BINARY --version >/dev/null 2>&1; then
        log_success "Binary verified: $($BINARY --version 2>&1 | head -1)"
    else
        log_fail "Binary verification failed"
        exit 1
    fi
}

# Test 1: Installation Verification
test_installation() {
    log_test "1. Installation Verification"
    
    # Check if installed via cargo
    if cargo install --list | grep -q "cargocrypt"; then
        log_success "CargoCrypt is installed via cargo"
        log_info "Installation details:"
        cargo install --list | grep -A2 "cargocrypt" >> "$OUTPUT_FILE"
    else
        log_info "CargoCrypt not installed globally, using local binary"
    fi
    
    # Test version command
    if run_command "$BINARY --version" "Version check"; then
        log_success "Version command works"
    else
        log_fail "Version command failed"
    fi
    
    # Test help command
    if run_command "$BINARY --help" "Help command"; then
        log_success "Help command works"
    else
        log_fail "Help command failed"
    fi
}

# Test 2: Init Command
test_init() {
    log_test "2. Init Command"
    
    # Test init in empty directory
    mkdir -p "$TEST_DIR/project1"
    cd "$TEST_DIR/project1"
    
    if run_command "$BINARY init" "Initialize in empty directory"; then
        if [ -d ".cargocrypt" ]; then
            log_success "Init created .cargocrypt directory"
            ls -la .cargocrypt >> "$OUTPUT_FILE"
        else
            log_fail ".cargocrypt directory not created"
        fi
    else
        log_fail "Init command failed"
    fi
    
    # Test reinit (should be idempotent)
    if run_command "$BINARY init" "Reinitialize"; then
        log_success "Reinit works (idempotent)"
    else
        log_fail "Reinit failed"
    fi
    
    cd "$TEST_DIR"
}

# Test 3: Encrypt Command
test_encrypt() {
    log_test "3. Encrypt Command"
    
    cd "$TEST_DIR"
    
    # Test 3.1: Basic file encryption
    echo "This is a test secret" > test_secret.txt
    
    # Use echo to provide password non-interactively
    if echo -e "testpass123\ntestpass123\n" | run_command "$BINARY encrypt test_secret.txt" "Basic encryption"; then
        if [ -f "test_secret.txt.enc" ]; then
            log_success "Encrypted file created: test_secret.txt.enc"
            ls -la test_secret.txt.enc >> "$OUTPUT_FILE"
        else
            log_fail "Encrypted file not found"
        fi
    else
        log_fail "Basic encryption failed"
    fi
    
    # Test 3.2: Hidden file encryption (.env)
    echo "API_KEY=secret123" > .env
    
    if echo -e "testpass123\ntestpass123\n" | run_command "$BINARY encrypt .env" "Hidden file encryption"; then
        if [ -f ".env.enc" ] && [ ! -f "..env.enc" ]; then
            log_success "Hidden file encrypted correctly: .env.enc"
        else
            log_fail "Hidden file encryption issue (double dot bug?)"
        fi
    else
        log_fail "Hidden file encryption failed"
    fi
    
    # Test 3.3: Multiple extension file
    echo '{"config": "test"}' > config.prod.json
    
    if echo -e "testpass123\ntestpass123\n" | run_command "$BINARY encrypt config.prod.json" "Multiple extension file"; then
        if [ -f "config.prod.json.enc" ]; then
            log_success "Multiple extension file encrypted: config.prod.json.enc"
        else
            log_fail "Multiple extension encryption failed"
        fi
    else
        log_fail "Multiple extension encryption command failed"
    fi
    
    # Test 3.4: File without extension
    echo "README content" > README
    
    if echo -e "testpass123\ntestpass123\n" | run_command "$BINARY encrypt README" "No extension file"; then
        if [ -f "README.enc" ]; then
            log_success "No extension file encrypted: README.enc"
        else
            log_fail "No extension encryption failed"
        fi
    else
        log_fail "No extension encryption command failed"
    fi
}

# Test 4: Decrypt Command
test_decrypt() {
    log_test "4. Decrypt Command"
    
    cd "$TEST_DIR"
    
    # Test 4.1: Basic decryption
    if [ -f "test_secret.txt.enc" ]; then
        # Remove original to test full cycle
        rm -f test_secret.txt
        
        if echo -e "testpass123\n" | run_command "$BINARY decrypt test_secret.txt.enc" "Basic decryption"; then
            if [ -f "test_secret.txt" ]; then
                content=$(cat test_secret.txt)
                if [ "$content" = "This is a test secret" ]; then
                    log_success "Decryption successful, content verified"
                else
                    log_fail "Decrypted content doesn't match original"
                fi
            else
                log_fail "Decrypted file not created"
            fi
        else
            log_fail "Decryption command failed"
        fi
    else
        log_skip "No encrypted file to decrypt"
    fi
    
    # Test 4.2: Wrong password handling
    if [ -f ".env.enc" ]; then
        if echo -e "wrongpassword\n" | run_command "$BINARY decrypt .env.enc 2>&1" "Wrong password test"; then
            log_fail "Decryption should have failed with wrong password"
        else
            log_success "Wrong password correctly rejected"
        fi
    fi
}

# Test 5: Config Command
test_config() {
    log_test "5. Config Command"
    
    cd "$TEST_DIR"
    
    # Initialize first
    $BINARY init >/dev/null 2>&1
    
    # Test config command
    if run_command "$BINARY config" "Config display"; then
        log_success "Config command works"
    else
        log_info "Config command may not be implemented"
    fi
    
    # Check for config file
    if [ -f ".cargocrypt/config.toml" ]; then
        log_info "Config file exists:"
        cat .cargocrypt/config.toml >> "$OUTPUT_FILE"
    else
        log_info "No config file found (zero-config mode)"
    fi
}

# Test 6: TUI Command
test_tui() {
    log_test "6. TUI (Terminal User Interface) Command"
    
    # Test TUI help
    if run_command "$BINARY tui --help" "TUI help"; then
        log_success "TUI command exists"
    else
        log_fail "TUI command not found"
        return
    fi
    
    # Can't fully test interactive TUI in script, but verify it starts
    if timeout 1s $BINARY tui </dev/null >/dev/null 2>&1; then
        log_info "TUI starts (killed after 1s for testing)"
    else
        log_info "TUI interactive test skipped (requires terminal)"
    fi
}

# Test 7: Help System
test_help() {
    log_test "7. Help System"
    
    # Test main help
    if run_command "$BINARY --help" "Main help"; then
        log_success "Main help accessible"
    else
        log_fail "Main help failed"
    fi
    
    # Test subcommand help
    local subcommands=("init" "encrypt" "decrypt" "config" "tui" "list" "verify" "keygen")
    
    for cmd in "${subcommands[@]}"; do
        if $BINARY $cmd --help >/dev/null 2>&1; then
            log_success "Help for '$cmd' command available"
        else
            log_info "Help for '$cmd' command not available"
        fi
    done
}

# Test 8: Advanced Features (if available)
test_advanced_features() {
    log_test "8. Advanced Features"
    
    cd "$TEST_DIR"
    
    # Test list command
    if run_command "$BINARY list" "List encrypted files"; then
        log_success "List command works"
    else
        log_info "List command not available"
    fi
    
    # Test verify command
    if run_command "$BINARY verify" "Verify integrity"; then
        log_success "Verify command works"
    else
        log_info "Verify command not available"
    fi
    
    # Test keygen command
    if run_command "$BINARY keygen --type ed25519" "Key generation"; then
        log_success "Keygen command works"
    else
        log_info "Keygen command not available"
    fi
    
    # Test benchmark command
    if run_command "$BINARY benchmark" "Benchmark"; then
        log_success "Benchmark command works"
    else
        log_info "Benchmark command not available"
    fi
}

# Test 9: Error Handling
test_error_handling() {
    log_test "9. Error Handling"
    
    cd "$TEST_DIR"
    
    # Test non-existent file
    if echo -e "testpass\n" | $BINARY encrypt nonexistent.txt >/dev/null 2>&1; then
        log_fail "Should fail on non-existent file"
    else
        log_success "Correctly handles non-existent file"
    fi
    
    # Test empty password
    if echo -e "\n\n" | $BINARY encrypt test.txt 2>&1 | grep -q -i "empty\|password"; then
        log_success "Empty password correctly rejected"
    else
        log_info "Empty password handling unclear"
    fi
    
    # Test permission denied (if not root)
    if [ "$EUID" -ne 0 ]; then
        touch readonly.txt
        chmod 000 readonly.txt
        if echo -e "testpass\n" | $BINARY encrypt readonly.txt >/dev/null 2>&1; then
            log_fail "Should fail on permission denied"
        else
            log_success "Correctly handles permission errors"
        fi
        rm -f readonly.txt
    fi
}

# Test 10: Performance Test
test_performance() {
    log_test "10. Performance Test"
    
    cd "$TEST_DIR"
    
    # Create test files of different sizes
    log_info "Creating test files..."
    dd if=/dev/urandom of=small.bin bs=1K count=10 >/dev/null 2>&1
    dd if=/dev/urandom of=medium.bin bs=1M count=10 >/dev/null 2>&1
    
    # Time small file encryption
    log_info "Testing small file (10KB) encryption..."
    start_time=$(date +%s.%N)
    if echo -e "testpass123\ntestpass123\n" | $BINARY encrypt small.bin >/dev/null 2>&1; then
        end_time=$(date +%s.%N)
        duration=$(echo "$end_time - $start_time" | bc)
        log_success "Small file encrypted in ${duration}s"
    else
        log_fail "Small file encryption failed"
    fi
    
    # Time medium file encryption
    log_info "Testing medium file (10MB) encryption..."
    start_time=$(date +%s.%N)
    if echo -e "testpass123\ntestpass123\n" | $BINARY encrypt medium.bin >/dev/null 2>&1; then
        end_time=$(date +%s.%N)
        duration=$(echo "$end_time - $start_time" | bc)
        log_success "Medium file encrypted in ${duration}s"
    else
        log_fail "Medium file encryption failed"
    fi
    
    # Clean up large files
    rm -f small.bin medium.bin small.bin.enc medium.bin.enc
}

# Generate final report
generate_report() {
    log "\n================================================================================"
    log "                              TEST SUMMARY"
    log "================================================================================"
    log "Total Tests: $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
    log "Passed:      $TESTS_PASSED"
    log "Failed:      $TESTS_FAILED"
    log "Skipped:     $TESTS_SKIPPED"
    log ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        log "Result: ALL TESTS PASSED! ✅"
    else
        log "Result: SOME TESTS FAILED ❌"
    fi
    
    log "================================================================================"
    log "Full test output saved to: $OUTPUT_FILE"
    log "Test directory: $TEST_DIR (not cleaned up for inspection)"
    log "================================================================================"
}

# Main test execution
main() {
    init_output
    
    log "Starting CargoCrypt Comprehensive Feature Testing"
    log "================================================"
    
    setup_test_env
    
    # Run all tests
    test_installation
    test_init
    test_encrypt
    test_decrypt
    test_config
    test_tui
    test_help
    test_advanced_features
    test_error_handling
    test_performance
    
    # Generate final report
    generate_report
    
    # Return appropriate exit code
    if [ $TESTS_FAILED -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"