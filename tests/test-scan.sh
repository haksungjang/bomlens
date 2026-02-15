#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ========================================================
# SBOM Tools - Integration Test 스크립트
# ========================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$SCRIPT_DIR/test-workspace"
SCAN_SCRIPT="$ROOT_DIR/scripts/scan-sbom.sh"
EXAMPLES_DIR="$ROOT_DIR/examples"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_test() { echo -e "${YELLOW}[TEST]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

PASSED=0
FAILED=0

cleanup() {
    echo ""
    echo "=========================================="
    echo " Cleaning up..."
    echo "=========================================="
    cd "$ROOT_DIR"
    rm -rf "$TEST_DIR"
}

# Function to find BOM file
find_bom_file() {
    local project=$1
    local version=$2
    
    # Single underscore
    if [ -f "${project}_${version}_bom.json" ]; then
        echo "${project}_${version}_bom.json"
        return 0
    fi
    
    # Double underscore
    if [ -f "${project}__${version}__bom.json" ]; then
        echo "${project}__${version}__bom.json"
        return 0
    fi
    
    # Pattern matching
    local pattern="${project}*${version}*bom.json"
    local found=$(ls $pattern 2>/dev/null | head -n1)
    if [ -n "$found" ]; then
        echo "$found"
        return 0
    fi
    
    return 1
}

echo "=========================================="
echo " SBOM Tools - Integration Test"
echo " Version: 1.0.0"
echo "=========================================="
echo ""

# ========================================================
# Prerequisites Validation
# ========================================================
print_header "Checking prerequisites..."

# Docker Check
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed."
    exit 1
fi

if ! docker info > /dev/null 2>&1; then
    print_error "Docker daemon is not running."
    exit 1
fi
print_success "Docker check passed"

# Script Check
if [ ! -f "$SCAN_SCRIPT" ]; then
    print_error "scan-sbom.sh not found at: $SCAN_SCRIPT"
    exit 1
fi
chmod +x "$SCAN_SCRIPT"
print_success "Scan script check passed"

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

trap cleanup EXIT

echo ""
print_header "Starting tests..."
echo ""

# ========================================================
# Test 1: Node.js project
# ========================================================
print_test "Test 1/10: Node.js project (npm)"

mkdir -p node-project
cd node-project

cat > package.json <<'EOF'
{
  "name": "test-nodejs-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}
EOF

npm install --package-lock-only > /dev/null 2>&1 || true

if "$SCAN_SCRIPT" --project "TestNodeApp" --version "1.0.0" --generate-only > /dev/null 2>&1; then
    if FOUND=$(find_bom_file "TestNodeApp" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Node.js project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Node.js project (SBOM이 비어있음)"
            ((FAILED++))
        fi
    else
        print_error "Node.js project (SBOM 파일 미생성)"
        ((FAILED++))
    fi
else
    print_error "Node.js project (스캔 실패)"
    ((FAILED++))
fi

cd "$TEST_DIR"

# ========================================================
# Test 2: Python project
# ========================================================
print_test "Test 2/10: Python project (pip)"

mkdir -p python-project
cd python-project

cat > requirements.txt <<'EOF'
flask==3.0.0
requests==2.31.0
pandas==2.1.0
EOF

if "$SCAN_SCRIPT" --project "TestPythonApp" --version "1.0.0" --generate-only > /dev/null 2>&1; then
    if FOUND=$(find_bom_file "TestPythonApp" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Python project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Python project (SBOM이 비어있음)"
            ((FAILED++))
        fi
    else
        print_error "Python project (SBOM 파일 미생성)"
        ((FAILED++))
    fi
else
    print_error "Python project (스캔 실패)"
    ((FAILED++))
fi

cd "$TEST_DIR"

# ========================================================
# Test 3: Java Maven project
# ========================================================
print_test "Test 3/10: Java Maven project"

mkdir -p java-maven-project
cd java-maven-project

cat > pom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0.0</version>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.2.0</version>
        </dependency>
    </dependencies>
</project>
EOF

if "$SCAN_SCRIPT" --project "TestJavaMaven" --version "1.0.0" --generate-only > /dev/null 2>&1; then
    if FOUND=$(find_bom_file "TestJavaMaven" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Java Maven project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Java Maven project (SBOM이 비어있음)"
            ((FAILED++))
        fi
    else
        print_error "Java Maven project (SBOM 파일 미생성)"
        ((FAILED++))
    fi
else
    print_error "Java Maven project (스캔 실패)"
    ((FAILED++))
fi

cd "$TEST_DIR"

# ========================================================
# Test 4: Ruby project
# ========================================================
print_test "Test 4/10: Ruby project (Bundler)"

mkdir -p ruby-project
cd ruby-project

cat > Gemfile <<'EOF'
source 'https://rubygems.org'

gem 'sinatra', '~> 3.0'
gem 'rack', '~> 2.2'
EOF

if "$SCAN_SCRIPT" --project "TestRuby" --version "1.0.0" --generate-only > /dev/null 2>&1; then
    if FOUND=$(find_bom_file "TestRuby" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Ruby project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Ruby project (SBOM이 비어있음)"
            ((FAILED++))
        fi
    else
        print_error "Ruby project (SBOM 파일 미생성)"
        ((FAILED++))
    fi
else
    print_error "Ruby project (스캔 실패)"
    ((FAILED++))
fi

cd "$TEST_DIR"

# ========================================================
# Test 5: PHP project
# ========================================================
print_test "Test 5/10: PHP project (Composer)"

mkdir -p php-project
cd php-project

cat > composer.json <<'EOF'
{
    "name": "test/php-app",
    "require": {
        "php": ">=7.4",
        "guzzlehttp/guzzle": "^7.0"
    }
}
EOF

if "$SCAN_SCRIPT" --project "TestPHP" --version "1.0.0" --generate-only > /dev/null 2>&1; then
    if FOUND=$(find_bom_file "TestPHP" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "PHP project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "PHP project (SBOM이 비어있음)"
            ((FAILED++))
        fi
    else
        print_error "PHP project (SBOM 파일 미생성)"
        ((FAILED++))
    fi
else
    print_error "PHP project (스캔 실패)"
    ((FAILED++))
fi

cd "$TEST_DIR"

# ========================================================
# Test 6: Rust project
# ========================================================
print_test "Test 6/10: Rust project (Cargo)"

mkdir -p rust-project
cd rust-project

cat > Cargo.toml <<'EOF'
[package]
name = "test-rust-app"
version = "1.0.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
EOF

mkdir -p src
cat > src/main.rs <<'EOF'
fn main() {
    println!("Rust application");
}
EOF

if "$SCAN_SCRIPT" --project "TestRust" --version "1.0.0" --generate-only > /dev/null 2>&1; then
    if FOUND=$(find_bom_file "TestRust" "1.0.0"); then
        COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
        if [ "$COMP_COUNT" -gt 0 ]; then
            print_success "Rust project ($COMP_COUNT components)"
            ((PASSED++))
        else
            print_error "Rust project (SBOM이 비어있음)"
            ((FAILED++))
        fi
    else
        print_error "Rust project (SBOM 파일 미생성)"
        ((FAILED++))
    fi
else
    print_error "Rust project (스캔 실패)"
    ((FAILED++))
fi

cd "$TEST_DIR"

# ========================================================
# Test 7: Docker Image
# ========================================================
print_test "Test 7/10: Docker image analysis"

if docker pull alpine:latest > /dev/null 2>&1; then
    if "$SCAN_SCRIPT" --target "alpine:latest" --project "TestAlpine" --version "latest" --generate-only > /dev/null 2>&1; then
        if FOUND=$(find_bom_file "TestAlpine" "latest"); then
            COMP_COUNT=$(cat "$FOUND" | jq '.components | length' 2>/dev/null || echo "0")
            if [ "$COMP_COUNT" -gt 0 ]; then
                print_success "Docker Image ($COMP_COUNT components)"
                ((PASSED++))
            else
                print_error "Docker Image (SBOM is empty)"
                ((FAILED++))
            fi
        else
            print_error "Docker Image (SBOM file not generated)"
            ((FAILED++))
        fi
    else
        print_error "Docker Image (Scan failed)"
        ((FAILED++))
    fi
else
    print_error "Docker Image (Alpine pull failed)"
    ((FAILED++))
fi

# ========================================================
# Test 8: Binary File
# ========================================================
print_test "Test 8/10: Binary file analysis"

cp /bin/echo test-binary

if "$SCAN_SCRIPT" --target "test-binary" --project "TestBinary" --version "1.0" --generate-only > /dev/null 2>&1; then
    if FOUND=$(find_bom_file "TestBinary" "1.0"); then
        print_success "Binary File"
        ((PASSED++))
    else
        print_error "Binary File (SBOM file not generated)"
        ((FAILED++))
    fi
else
    print_error "Binary File (Scan failed)"
    ((FAILED++))
fi

# ========================================================
# Test 9: RootFS Directory
# ========================================================
print_test "Test 9/10: RootFS directory analysis"

mkdir -p test-rootfs/{bin,lib,etc}
echo "config" > test-rootfs/etc/config

if "$SCAN_SCRIPT" --target "test-rootfs/" --project "TestRootFS" --version "1.0" --generate-only > /dev/null 2>&1; then
    if FOUND=$(find_bom_file "TestRootFS" "1.0"); then
        print_success "RootFS Directory"
        ((PASSED++))
    else
        print_error "RootFS Directory (SBOM file not generated)"
        ((FAILED++))
    fi
else
    print_error "RootFS Directory (Scan failed)"
    ((FAILED++))
fi

# ========================================================
# Test 10: Example Project Test
# ========================================================
print_test "Test 10/10: Example project validation"

# Return to root directory
cd "$ROOT_DIR"

EXAMPLE_TESTS=0
EXAMPLE_PASSED=0

# Node.js Example
if [ -f "examples/nodejs/package.json" ] && [ -f "examples/nodejs/index.js" ]; then
    ((EXAMPLE_TESTS++))
    ((EXAMPLE_PASSED++))
elif [ -f "examples/nodejs/package.json" ]; then
    ((EXAMPLE_TESTS++))
    echo "  [DEBUG] Node.js: package.json exists but index.js missing"
fi

# Python Example
if [ -f "examples/python/requirements.txt" ] && [ -f "examples/python/app.py" ]; then
    ((EXAMPLE_TESTS++))
    ((EXAMPLE_PASSED++))
elif [ -f "examples/python/requirements.txt" ]; then
    ((EXAMPLE_TESTS++))
    echo "  [DEBUG] Python: requirements.txt exists but app.py missing"
fi

# Java Example
if [ -f "examples/java-maven/pom.xml" ] && [ -f "examples/java-maven/src/main/java/com/example/Application.java" ]; then
    ((EXAMPLE_TESTS++))
    ((EXAMPLE_PASSED++))
elif [ -f "examples/java-maven/pom.xml" ]; then
    ((EXAMPLE_TESTS++))
    echo "  [DEBUG] Java: pom.xml exists but Application.java missing"
    echo "  [DEBUG] Checking: examples/java-maven/src/main/java/com/example/Application.java"
    ls -la examples/java-maven/src/main/java/com/example/ 2>&1 || echo "  [DEBUG] Directory not found"
fi

# Docker Example
if [ -f "examples/docker/Dockerfile" ] && [ -f "examples/docker/README.md" ]; then
    ((EXAMPLE_TESTS++))
    ((EXAMPLE_PASSED++))
elif [ -f "examples/docker/Dockerfile" ]; then
    ((EXAMPLE_TESTS++))
    echo "  [DEBUG] Docker: Dockerfile exists but README.md missing"
fi

if [ "$EXAMPLE_TESTS" -eq "$EXAMPLE_PASSED" ] && [ "$EXAMPLE_TESTS" -gt 0 ]; then
    print_success "Example Project ($EXAMPLE_PASSED/$EXAMPLE_TESTS complete)"
    ((PASSED++))
else
    print_error "Example Project ($EXAMPLE_PASSED/$EXAMPLE_TESTS complete)"
    ((FAILED++))
fi

# ========================================================
# Result Summary
# ========================================================
echo ""
echo "=========================================="
echo " Test Summary"
echo "=========================================="
echo ""

TOTAL=$((PASSED + FAILED))
PERCENTAGE=$(awk "BEGIN {printf \"%.1f\", ($PASSED/$TOTAL)*100}")

echo "Total tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Success rate: ${PERCENTAGE}%"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}=========================================="
    echo -e " All tests passed!"
    echo -e "==========================================${NC}"
    echo ""
    
    # List of generated SBOM files
    print_header "Generated SBOM files:"
    echo ""
    
    for file in *_bom.json; do
        if [ -f "$file" ]; then
            COMP_COUNT=$(cat "$file" | jq '.components | length' 2>/dev/null || echo "N/A")
            SIZE=$(ls -lh "$file" | awk '{print $5}')
            printf "  ✓ %-40s %4s components (%s)\n" "$file" "$COMP_COUNT" "$SIZE"
        fi
    done
    echo ""
fi
