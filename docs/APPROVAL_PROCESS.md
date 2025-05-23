# Automated Jobs Approval Process

This document describes the automated approval system implemented for the HackingNotebook repository to streamline content contributions and reduce manual intervention.

## Overview

The automated jobs approval process is designed to:
- Validate content quality automatically
- Approve small, safe changes without manual review
- Flag larger changes that require human oversight
- Maintain consistent documentation standards
- Accelerate the contribution workflow

## How It Works

### 1. Content Validation

When a pull request is opened or updated, the system automatically:

- **Validates Markdown Format**: Checks syntax, headers, code blocks
- **Checks Content Structure**: Ensures files are in correct directories
- **Validates Links**: Detects broken internal references
- **Analyzes Size**: Evaluates the scope of changes

### 2. Auto-Approval Criteria

Pull requests are eligible for automatic approval if they meet ALL of the following criteria:

✅ **Small Changes**: Less than 50 additions, less than 20 deletions, fewer than 5 files changed
✅ **Markdown Only**: Only `.md` files are modified
✅ **Quality Checks**: Pass all content validation tests
✅ **Proper Structure**: Files are in appropriate directories

### 3. Manual Review Triggers

Pull requests require manual review if they:

❌ **Large Changes**: More than 200 additions, 100 deletions, or 10+ files
❌ **Non-Markdown Files**: Changes to scripts, configs, or binary files
❌ **Validation Failures**: Broken links, malformed markdown, or structural issues

## Content Organization Standards

### Directory Structure

```
HackingNotebook/
├── Cheatsheets/           # General hacking techniques and commands
├── Tracks/                # Organized learning tracks
│   ├── crest_crt/        # CREST CRT certification track
│   └── Intro_to_blue_team/ # Blue team fundamentals
├── LetsDefend/           # LetsDefend.io platform writeups
├── MalwareAnalysis/      # Malware analysis reports
├── Ringzer0CTF/          # Ringzer0 CTF challenges
└── imgs/                 # Shared images and screenshots
```

### Content Standards

- Use proper markdown headers (`#`, `##`, `###`)
- Include code blocks with language specification
- Keep sensitive information redacted or clearly marked as examples
- Ensure internal links are functional

## Labels and Automation

The system automatically applies labels:

- `auto-approved` - Small changes that passed all checks
- `documentation` - Content-only changes
- `large-change` - Significant modifications requiring review
- `needs-review` - Manual intervention required

## Using the Validation Script

You can run content validation locally before submitting:

```bash
# Validate all markdown files
./scripts/validate-content.sh

# Validate specific files
./scripts/validate-content.sh "Cheatsheets/New Technique.md"
```

## Benefits

### For Contributors
- **Faster Feedback**: Immediate validation results
- **Quick Approval**: Small changes merge faster
- **Quality Assurance**: Catch issues before review

### For Maintainers
- **Reduced Workload**: Auto-approval of safe changes
- **Consistent Quality**: Automated validation standards
- **Focus on Complex Changes**: More time for substantial reviews

---

*This automated system helps maintain high-quality documentation while reducing manual overhead.*