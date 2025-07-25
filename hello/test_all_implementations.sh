#!/bin/bash

# Test script for all Hello World implementations
# This script tests each implementation and reports their status

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $message"
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}✗ FAIL${NC}: $message"
    elif [ "$status" = "INFO" ]; then
        echo -e "${BLUE}ℹ INFO${NC}: $message"
    elif [ "$status" = "WARN" ]; then
        echo -e "${YELLOW}⚠ WARN${NC}: $message"
    fi
}

# Initialize counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test results array
declare -A TEST_RESULTS

echo "========================================="
echo "Hello World Implementation Test Suite"
echo "========================================="
echo ""

# Test Python implementation
echo "Testing Python Implementation..."
echo "---------------------------------"
TOTAL_TESTS=$((TOTAL_TESTS + 1))

if [ -f "python/hello.py" ]; then
    # Test if Python is installed
    if command -v python3 &> /dev/null; then
        # Run the Python script and capture output
        PYTHON_OUTPUT=$(cd python && python3 hello.py 2>&1 | head -n 1)
        
        if [[ "$PYTHON_OUTPUT" == *"Hello, World!"* ]]; then
            print_status "PASS" "Python implementation outputs correct greeting"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            TEST_RESULTS["Python"]="PASS"
            
            # Run unit tests if they exist
            if [ -f "python/test_hello.py" ]; then
                print_status "INFO" "Running Python unit tests..."
                if (cd python && python3 test_hello.py -v 2>&1 | grep -q "OK"); then
                    print_status "PASS" "Python unit tests passed"
                else
                    print_status "WARN" "Python unit tests failed or incomplete"
                fi
            fi
        else
            print_status "FAIL" "Python implementation output incorrect: '$PYTHON_OUTPUT'"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            TEST_RESULTS["Python"]="FAIL"
        fi
    else
        print_status "WARN" "Python3 not installed, skipping Python tests"
        TEST_RESULTS["Python"]="SKIP"
    fi
else
    print_status "FAIL" "Python implementation not found"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    TEST_RESULTS["Python"]="FAIL"
fi
echo ""

# Test JavaScript implementation
echo "Testing JavaScript Implementation..."
echo "---------------------------------"
TOTAL_TESTS=$((TOTAL_TESTS + 1))

if [ -f "javascript/hello.js" ]; then
    # Test if Node.js is installed
    if command -v node &> /dev/null; then
        # Run the JavaScript file and capture output
        JS_OUTPUT=$(cd javascript && node hello.js 2>&1 | grep -m 1 "Hello, World!")
        
        if [[ "$JS_OUTPUT" == *"Hello, World!"* ]]; then
            print_status "PASS" "JavaScript implementation outputs correct greeting"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            TEST_RESULTS["JavaScript"]="PASS"
            
            # Check for package.json
            if [ -f "javascript/package.json" ]; then
                print_status "INFO" "package.json found"
                # Check if it has test scripts
                if grep -q '"test"' javascript/package.json; then
                    print_status "INFO" "Test script found in package.json"
                fi
            fi
        else
            print_status "FAIL" "JavaScript implementation output incorrect"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            TEST_RESULTS["JavaScript"]="FAIL"
        fi
    else
        print_status "WARN" "Node.js not installed, skipping JavaScript tests"
        TEST_RESULTS["JavaScript"]="SKIP"
    fi
else
    print_status "FAIL" "JavaScript implementation not found"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    TEST_RESULTS["JavaScript"]="FAIL"
fi
echo ""

# Test Go implementation
echo "Testing Go Implementation..."
echo "---------------------------------"
TOTAL_TESTS=$((TOTAL_TESTS + 1))

if [ -f "go/main.go" ]; then
    # Test if Go is installed
    if command -v go &> /dev/null; then
        # Run the Go program and capture output
        GO_OUTPUT=$(cd go && go run main.go 2>&1)
        
        if [[ "$GO_OUTPUT" == *"Hello, World!"* ]]; then
            print_status "PASS" "Go implementation outputs correct greeting"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            TEST_RESULTS["Go"]="PASS"
            
            # Check for go.mod
            if [ -f "go/go.mod" ]; then
                print_status "INFO" "go.mod found - project properly initialized"
            fi
        else
            print_status "FAIL" "Go implementation output incorrect: '$GO_OUTPUT'"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            TEST_RESULTS["Go"]="FAIL"
        fi
    else
        print_status "WARN" "Go not installed, skipping Go tests"
        TEST_RESULTS["Go"]="SKIP"
    fi
else
    print_status "FAIL" "Go implementation not found"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    TEST_RESULTS["Go"]="FAIL"
fi
echo ""

# Check for Rust implementation (currently empty)
echo "Testing Rust Implementation..."
echo "---------------------------------"
TOTAL_TESTS=$((TOTAL_TESTS + 1))

if [ -f "rust/main.rs" ] || [ -f "rust/src/main.rs" ]; then
    # Test if Rust is installed
    if command -v rustc &> /dev/null; then
        print_status "INFO" "Would test Rust implementation here"
        TEST_RESULTS["Rust"]="PENDING"
    else
        print_status "WARN" "Rust not installed, skipping Rust tests"
        TEST_RESULTS["Rust"]="SKIP"
    fi
else
    print_status "WARN" "Rust implementation not found (folder exists but is empty)"
    TEST_RESULTS["Rust"]="NOT_FOUND"
fi
echo ""

# Summary Report
echo "========================================="
echo "Test Summary Report"
echo "========================================="
echo ""
echo "Total Tests Run: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $FAILED_TESTS"
echo "Skipped: $((TOTAL_TESTS - PASSED_TESTS - FAILED_TESTS))"
echo ""

# Detailed Results Table
echo "Implementation Status:"
echo "---------------------"
for lang in "Python" "JavaScript" "Go" "Rust"; do
    if [ "${TEST_RESULTS[$lang]+isset}" ]; then
        status="${TEST_RESULTS[$lang]}"
        case $status in
            "PASS")
                echo -e "$lang: ${GREEN}✓ PASSED${NC}"
                ;;
            "FAIL")
                echo -e "$lang: ${RED}✗ FAILED${NC}"
                ;;
            "SKIP")
                echo -e "$lang: ${YELLOW}⚠ SKIPPED${NC} (runtime not installed)"
                ;;
            "NOT_FOUND")
                echo -e "$lang: ${YELLOW}⚠ NOT FOUND${NC}"
                ;;
            *)
                echo -e "$lang: ${BLUE}ℹ $status${NC}"
                ;;
        esac
    fi
done
echo ""

# Exit code based on test results
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All implemented tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please check the output above.${NC}"
    exit 1
fi