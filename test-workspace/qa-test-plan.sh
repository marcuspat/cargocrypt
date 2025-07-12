#!/bin/bash
# CargoCrypt QA Test Plan
# This script tests all the expected fixes for CargoCrypt

set -e # Exit on error

echo "=== CargoCrypt QA Test Suite ==="
echo "Testing all fixes for the identified issues"
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    echo -n "Testing: $test_name... "
    
    if eval "$test_command"; then
        if [ "$expected_result" = "pass" ]; then
            echo -e "${GREEN}PASSED${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}FAILED (expected to fail)${NC}"
            ((TESTS_FAILED++))
        fi
    else
        if [ "$expected_result" = "fail" ]; then
            echo -e "${GREEN}PASSED (correctly failed)${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}FAILED${NC}"
            ((TESTS_FAILED++))
        fi
    fi
}

# Navigate to test workspace
cd /workspaces/cargocrypt/test-workspace

echo "=== Test 1: Filename Extension Fix ==="
echo "Creating test files..."

# Create test files with various extensions
echo "secret data" > .env
echo "config data" > config.json
echo "secret key" > secrets.txt
echo "no extension data" > noext

# Test 1.1: Encrypt files and check extensions
echo
echo "Test 1.1: Testing encryption filename extensions"

# These tests will fail until the double extension bug is fixed
run_test "Encrypt .env file" "cargocrypt encrypt .env testpass123 2>/dev/null && [ -f '.env.enc' ] && [ ! -f '..env.enc' ]" "pass"
run_test "Encrypt config.json" "cargocrypt encrypt config.json testpass123 2>/dev/null && [ -f 'config.json.enc' ] && [ ! -f 'config..json.enc' ]" "pass"
run_test "Encrypt secrets.txt" "cargocrypt encrypt secrets.txt testpass123 2>/dev/null && [ -f 'secrets.txt.enc' ] && [ ! -f 'secrets..txt.enc' ]" "pass"
run_test "Encrypt file without extension" "cargocrypt encrypt noext testpass123 2>/dev/null && [ -f 'noext.enc' ] && [ ! -f '.noext.enc' ]" "pass"

# Test 1.2: Decrypt files and check original names restored
echo
echo "Test 1.2: Testing decryption filename restoration"

# Clean up encrypted files first
rm -f *.enc

# Re-encrypt for decryption tests
echo "secret data" > .env
cargocrypt encrypt .env testpass123 2>/dev/null || true
run_test "Decrypt .env.enc" "cargocrypt decrypt .env.enc testpass123 2>/dev/null && [ -f '.env' ]" "pass"

echo "config data" > config.json
cargocrypt encrypt config.json testpass123 2>/dev/null || true
run_test "Decrypt config.json.enc" "cargocrypt decrypt config.json.enc testpass123 2>/dev/null && [ -f 'config.json' ]" "pass"

echo
echo "=== Test 2: Password Prompting Fix ==="

# Test 2.1: Test password prompting (interactive test simulation)
echo
echo "Test 2.1: Testing password prompting"

# Create a test file
echo "test data" > test_prompt.txt

# Test with empty password (should fail)
run_test "Encrypt with empty password" "echo '' | cargocrypt encrypt test_prompt.txt 2>/dev/null" "fail"

# Test with password mismatch (should fail)
run_test "Encrypt with password mismatch" "printf 'pass123\ndifferent123\n' | cargocrypt encrypt test_prompt.txt 2>/dev/null" "fail"

# Test with matching passwords (should pass)
run_test "Encrypt with matching passwords" "printf 'testpass123\ntestpass123\n' | cargocrypt encrypt test_prompt.txt 2>/dev/null" "pass"

# Test decrypt with wrong password
echo "test data" > test_decrypt.txt
printf "testpass123\ntestpass123\n" | cargocrypt encrypt test_decrypt.txt 2>/dev/null || true
run_test "Decrypt with wrong password" "echo 'wrongpass' | cargocrypt decrypt test_decrypt.txt.enc 2>/dev/null" "fail"

# Test decrypt with correct password
run_test "Decrypt with correct password" "echo 'testpass123' | cargocrypt decrypt test_decrypt.txt.enc 2>/dev/null" "pass"

echo
echo "=== Test 3: TUI Launch Test ==="

# Test 3.1: Test TUI command exists
echo
echo "Test 3.1: Testing TUI command"

run_test "TUI command exists" "cargocrypt tui --help 2>&1 | grep -q 'Terminal User Interface'" "pass"

# Test 3.2: Test TUI launches (non-interactive test)
run_test "TUI launches without error" "timeout 1s cargocrypt tui 2>&1 || [ $? -eq 124 ]" "pass"

echo
echo "=== Test 4: Integration Tests ==="

# Test 4.1: Complete workflow test
echo
echo "Test 4.1: Testing complete encrypt/decrypt workflow"

# Clean workspace
rm -f workflow_test.txt workflow_test.txt.enc

# Create test file
echo "workflow test data" > workflow_test.txt
original_hash=$(sha256sum workflow_test.txt | cut -d' ' -f1)

# Encrypt
run_test "Workflow: Encrypt file" "printf 'workflowpass\nworkflowpass\n' | cargocrypt encrypt workflow_test.txt 2>/dev/null" "pass"

# Verify original is removed or backed up
run_test "Workflow: Original file handled" "[ ! -f 'workflow_test.txt' ] || [ -f 'workflow_test.txt.bak' ]" "pass"

# Decrypt
run_test "Workflow: Decrypt file" "echo 'workflowpass' | cargocrypt decrypt workflow_test.txt.enc 2>/dev/null" "pass"

# Verify content matches
if [ -f "workflow_test.txt" ]; then
    decrypted_hash=$(sha256sum workflow_test.txt | cut -d' ' -f1)
    run_test "Workflow: Content integrity" "[ '$original_hash' = '$decrypted_hash' ]" "pass"
else
    echo -e "${RED}FAILED${NC} - Decrypted file not found"
    ((TESTS_FAILED++))
fi

echo
echo "=== Test 5: Error Handling Tests ==="

# Test 5.1: Non-existent file
run_test "Encrypt non-existent file" "cargocrypt encrypt non_existent_file.txt testpass 2>/dev/null" "fail"

# Test 5.2: Invalid encrypted file
echo "not encrypted" > fake.enc
run_test "Decrypt invalid encrypted file" "echo 'testpass' | cargocrypt decrypt fake.enc 2>/dev/null" "fail"

# Test 5.3: Permission denied (if running as non-root)
if [ "$EUID" -ne 0 ]; then
    touch readonly.txt
    chmod 000 readonly.txt
    run_test "Encrypt file without read permission" "cargocrypt encrypt readonly.txt testpass 2>/dev/null" "fail"
    chmod 644 readonly.txt
    rm -f readonly.txt
fi

echo
echo "=== Test Summary ==="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo

# Store results for coordination
echo "{
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"tests_passed\": $TESTS_PASSED,
  \"tests_failed\": $TESTS_FAILED,
  \"test_categories\": {
    \"filename_extension\": \"tested\",
    \"password_prompting\": \"tested\",
    \"tui_launch\": \"tested\",
    \"integration\": \"tested\",
    \"error_handling\": \"tested\"
  }
}" > qa_test_results.json

# Clean up test files
echo "Cleaning up test files..."
rm -f *.enc *.txt *.json .env noext *.bak

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the results above.${NC}"
    exit 1
fi