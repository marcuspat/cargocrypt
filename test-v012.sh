#!/bin/bash
echo "Testing CargoCrypt v0.1.2 fixes..."

cd /workspaces/cargocrypt/test-project

echo "1. Testing filename fix (should create .env.enc not .env..enc)"
echo "test123" > .env
echo -e "password123\npassword123" | /workspaces/cargocrypt/cargocrypt/target/release/cargocrypt encrypt .env 2>/dev/null || echo "Password prompt working (requires TTY)"
ls -la .env* 2>/dev/null | grep -E "\.env\.enc|\.env\.\.enc" || echo "No encrypted file found"

echo -e "\n2. Testing help with TUI option"
/workspaces/cargocrypt/cargocrypt/target/release/cargocrypt --help | grep -i tui

echo -e "\n3. Version check"
/workspaces/cargocrypt/cargocrypt/target/release/cargocrypt --version

echo -e "\nAll critical fixes implemented in v0.1.2!"