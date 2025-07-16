#\!/bin/bash
echo "=== CargoCrypt Feature Test ==="
echo "Testing v0.1.2 features..."

# Test directory
mkdir -p feature-test && cd feature-test

# 1. Version test
echo -e "\n1. Version Test:"
/workspaces/cargocrypt/cargocrypt/target/release/cargocrypt --version

# 2. Help test
echo -e "\n2. Help Test:"
/workspaces/cargocrypt/cargocrypt/target/release/cargocrypt --help  < /dev/null |  grep -E "init|encrypt|decrypt|config|tui"

# 3. Init test
echo -e "\n3. Init Test:"
cargo init --name testproj && cd testproj
/workspaces/cargocrypt/cargocrypt/target/release/cargocrypt init
ls -la .cargocrypt/

# 4. Encrypt test
echo -e "\n4. Encrypt Test:"
echo "SECRET_KEY=test123" > .env
echo '{"api_key": "secret"}' > config.json
echo "password123" > secrets.txt
echo -e "test\ntest" | /workspaces/cargocrypt/cargocrypt/target/release/cargocrypt encrypt .env 2>&1 | grep -E "encrypted|password"
ls -la *.enc

# 5. Decrypt test
echo -e "\n5. Decrypt Test:"
rm -f .env config.json secrets.txt
echo "test" | /workspaces/cargocrypt/cargocrypt/target/release/cargocrypt decrypt .env.enc 2>&1 | grep -E "decrypted|password"
[ -f .env ] && echo "Decrypt successful" || echo "Decrypt failed"

# 6. Config test
echo -e "\n6. Config Test:"
/workspaces/cargocrypt/cargocrypt/target/release/cargocrypt config

# 7. TUI test
echo -e "\n7. TUI Test:"
/workspaces/cargocrypt/cargocrypt/target/release/cargocrypt --help | grep tui && echo "TUI command available"

echo -e "\n=== Test Complete ==="
