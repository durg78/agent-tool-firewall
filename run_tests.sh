#!/bin/bash
# ATF Test Script - Runs Go unit tests

echo "=== ATF Test Suite ==="
echo "========================================"

# Run all Go tests with verbose output
go test ./... -v

exit_code=$?

if [ $exit_code -eq 0 ]; then
  echo -e "\n=== All tests passed ==="
else
  echo -e "\n=== Tests failed ==="
  exit $exit_code
fi
