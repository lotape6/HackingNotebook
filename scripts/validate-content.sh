#!/bin/bash

# Content Validation Script for HackingNotebook
# This script validates markdown content for quality and consistency

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Initialize counters
errors=0
warnings=0
files_checked=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    warnings=$((warnings + 1))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    errors=$((errors + 1))
}

validate_file() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        log_error "File does not exist: $file"
        return 1
    fi
    
    if [[ ! "$file" =~ \.md$ ]]; then
        log_info "Skipping non-markdown file: $file"
        return 0
    fi
    
    files_checked=$((files_checked + 1))
    log_info "=== Validating $file ==="
    
    # Check file size
    local line_count=$(wc -l < "$file")
    if [[ $line_count -lt 3 ]]; then
        log_warning "$file: File is very short ($line_count lines)"
    fi
    
    # Check for headers
    if ! grep -q "^#" "$file"; then
        log_warning "$file: No headers found"
    fi
    
    # Check directory structure
    case "$file" in
        Cheatsheets/*.md)
            log_success "$file: Cheatsheet in correct location"
            ;;
        Tracks/*/*)
            local track_name=$(echo "$file" | cut -d'/' -f2)
            log_success "$file: Track content for '$track_name' properly organized"
            ;;
        LetsDefend/*.md)
            log_success "$file: LetsDefend content in correct location"
            ;;
        README.md)
            log_success "$file: README file"
            ;;
        docs/*.md)
            log_success "$file: Documentation file"
            ;;
        *)
            log_warning "$file: File may be in unexpected location"
            ;;
    esac
    
    echo ""
}

# Main script
log_info "Starting content validation..."

if [[ $# -eq 0 ]]; then
    # Validate all markdown files
    log_info "No files specified, validating all markdown files..."
    while IFS= read -r -d '' file; do
        validate_file "$file"
    done < <(find . -name "*.md" -not -path "./.git/*" -print0)
else
    # Validate specified files
    for file in "$@"; do
        validate_file "$file"
    done
fi

# Summary
echo "========================================="
log_info "Validation Summary:"
log_info "Files checked: $files_checked"

if [[ $errors -gt 0 ]]; then
    log_error "Errors found: $errors"
    exit 1
else
    log_success "No errors found"
fi

if [[ $warnings -gt 0 ]]; then
    log_warning "Warnings found: $warnings"
else
    log_success "No warnings found"
fi