#!/bin/bash
# Quick verification script for CargoCrypt fixes
# Run this after implementing fixes to verify they work

echo "🔍 CargoCrypt Quick Fix Verification"
echo "===================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Change to cargocrypt directory
cd /workspaces/cargocrypt/cargocrypt

# Check 1: Does it compile?
echo -n "1. Checking compilation... "
if cargo build 2>/dev/null; then
    echo -e "${GREEN}✓ Compiles${NC}"
    BINARY="./target/debug/cargocrypt"
else
    echo -e "${RED}✗ Compilation fails${NC}"
    exit 1
fi

# Check 2: Test filename fix
echo -n "2. Testing filename extension fix... "
cd /tmp
echo "test" > .env
if $BINARY encrypt .env 2>/dev/null; then
    if [ -f ".env.enc" ] && [ ! -f "..env.enc" ]; then
        echo -e "${GREEN}✓ Fixed${NC}"
        rm -f .env.enc
    else
        echo -e "${RED}✗ Still broken${NC}"
    fi
else
    echo -e "${RED}✗ Encrypt failed${NC}"
fi
rm -f .env

# Check 3: Test password prompt
echo -n "3. Testing password prompts... "
echo "test" > test.txt
if echo -e "\n\n" | $BINARY encrypt test.txt 2>&1 | grep -q "Password\|empty"; then
    echo -e "${GREEN}✓ Prompts for password${NC}"
else
    echo -e "${RED}✗ No password prompt${NC}"
fi
rm -f test.txt test.txt.enc

# Check 4: Test TUI
echo -n "4. Testing TUI command... "
if $BINARY tui --help 2>&1 | grep -q "tui\|TUI\|Terminal"; then
    echo -e "${GREEN}✓ TUI command exists${NC}"
else
    echo -e "${RED}✗ TUI command missing${NC}"
fi

echo
echo "Quick verification complete!"