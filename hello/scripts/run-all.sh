#!/bin/bash

# Run all Hello World implementations
# This script executes each language implementation in sequence

echo "==================================="
echo "Multi-Language Hello World Runner"
echo "==================================="
echo

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
LANGUAGES_DIR="$PROJECT_ROOT/languages"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to run a language implementation
run_language() {
    local lang=$1
    local cmd=$2
    
    echo -e "${BLUE}Running $lang...${NC}"
    echo "-----------------------------------"
    
    if eval "$cmd"; then
        echo -e "${GREEN}✓ $lang completed successfully${NC}"
    else
        echo -e "${RED}✗ $lang failed${NC}"
    fi
    
    echo
}

# Check if languages directory exists
if [ ! -d "$LANGUAGES_DIR" ]; then
    echo -e "${RED}Error: Languages directory not found at $LANGUAGES_DIR${NC}"
    exit 1
fi

# Python
if [ -f "$LANGUAGES_DIR/python/hello.py" ]; then
    run_language "Python" "cd '$LANGUAGES_DIR/python' && python hello.py"
else
    echo -e "${RED}Python implementation not found${NC}"
fi

# JavaScript
if [ -f "$LANGUAGES_DIR/javascript/hello.js" ]; then
    run_language "JavaScript" "cd '$LANGUAGES_DIR/javascript' && node hello.js"
else
    echo -e "${RED}JavaScript implementation not found${NC}"
fi

# Go
if [ -f "$LANGUAGES_DIR/go/hello.go" ]; then
    # Try to run with go.mod first, fallback to simple go run
    if [ -f "$LANGUAGES_DIR/go/go.mod" ]; then
        run_language "Go" "cd '$LANGUAGES_DIR/go' && go run hello.go"
    else
        run_language "Go" "cd '$LANGUAGES_DIR/go' && go run main.go"
    fi
else
    echo -e "${RED}Go implementation not found${NC}"
fi

echo "==================================="
echo "All implementations completed!"
echo "===================================