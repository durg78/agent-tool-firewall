#!/bin/bash
# ATF Test Script - Runs tests through the proxy

echo "=== ATF Proxy Test Suite ==="
echo "Proxy: http://localhost:3123"
echo "========================================"

# Test directory
TEST_DIR="test/malicious"

if [ ! -d "$TEST_DIR" ]; then
  echo "Error: Test directory $TEST_DIR not found!"
  echo "Please create it and add your malicious test files."
  exit 1
fi

for file in "$TEST_DIR"/*.html; do
  if [ ! -f "$file" ]; then
    continue
  fi

  filename=$(basename "$file")
  echo -e "\nTesting: $filename"

  # Run curl with proxy environment variables set for this command only
  http_proxy=http://localhost:3123 \
  https_proxy=http://localhost:3123 \
  curl -s -H "Host: example.com" \
       --max-time 10 \
       "http://localhost:8000/$filename" | head -c 300

  echo -e "\n----------------------------------------"
done

echo -e "\n=== Test completed ==="
