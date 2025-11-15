#!/usr/bin/env bash
# VDB API Test Runner
# Runs all HTTP test files using httpyac (VS Code REST Client compatible)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${TEST_DIR}/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Parse arguments
ENVIRONMENT="${1:-local}"
VERBOSE="${2:-false}"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}VDB API Integration Test Suite${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "${YELLOW}Environment:${NC} ${ENVIRONMENT}"
echo -e "${YELLOW}Test Directory:${NC} ${TEST_DIR}"
echo -e "${YELLOW}Timestamp:${NC} ${TIMESTAMP}"
echo ""

# Check if httpyac is installed
if ! command -v httpyac &> /dev/null; then
    echo -e "${RED}Error: httpyac is not installed${NC}"
    echo -e "${YELLOW}Install it with:${NC} npm install -g httpyac"
    echo ""
    echo -e "${YELLOW}Alternative:${NC} Use VS Code REST Client extension"
    exit 1
fi

# Create results directory
mkdir -p "${RESULTS_DIR}"

# Test files to run (in order)
TEST_FILES=(
    "oas/openapi.http"
    "v1/auth/token.http"
    "v1/info/cve-info.http"
    "v1/vuln/vulnerability.http"
    "v1/exploits/exploit-intel.http"
)

# Run tests
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

for test_file in "${TEST_FILES[@]}"; do
    TEST_PATH="${TEST_DIR}/${test_file}"

    if [ ! -f "${TEST_PATH}" ]; then
        echo -e "${RED}✗ Test file not found: ${test_file}${NC}"
        continue
    fi

    echo -e "${BLUE}Running:${NC} ${test_file}"

    # Run the test
    if httpyac send "${TEST_PATH}" --all --json > "${RESULTS_DIR}/${test_file//\//_}_${TIMESTAMP}.json" 2>&1; then
        echo -e "${GREEN}✓ Passed${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}✗ Failed${NC}"
        ((FAILED_TESTS++))
    fi

    ((TOTAL_TESTS++))
    echo ""
done

# Summary
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}======================================${NC}"
echo -e "Total Tests:  ${TOTAL_TESTS}"
echo -e "${GREEN}Passed:       ${PASSED_TESTS}${NC}"
echo -e "${RED}Failed:       ${FAILED_TESTS}${NC}"
echo ""

if [ ${FAILED_TESTS} -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check results in: ${RESULTS_DIR}${NC}"
    exit 1
fi
