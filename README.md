# HackingNotebook

This repository (Obsidian Vault) aims to collect different personal notes learned about hacking in sandbox platforms like Hack The Box or LetsDefend. All the interesting commands gathered along the practice are collected over [Cheatsheets](https://github.com/lotape6/HackingNotebook/tree/master/Cheatsheets).

## Content Organization

Currently there are two different HTB tracks being done:
- [Intro to Blue Team](https://github.com/lotape6/HackingNotebook/tree/master/Tracks/Intro_to_blue_team) (finished)
- [CREST_CRT](https://github.com/lotape6/HackingNotebook/tree/master/Tracks/crest_crt) (in progress)

There are also some malicious files being analyzed over [MalwareAnalysis](https://github.com/lotape6/HackingNotebook/tree/master/MalwareAnalysis). Files were found on https://bazaar.abuse.ch/

## Automated Jobs Approval Process

This repository now features an automated approval system for content contributions to streamline workflows and reduce manual intervention. The system:

- **Automatically validates** content quality (markdown format, structure, links)
- **Auto-approves** small documentation changes that meet quality criteria
- **Flags** larger changes for manual review
- **Maintains** consistent documentation standards

### Quick Start for Contributors

1. **Small changes** (< 50 lines, < 5 files, markdown only) are auto-approved
2. **Run validation** locally before submitting: `./scripts/validate-content.sh`
3. **Follow structure** guidelines in [`docs/APPROVAL_PROCESS.md`](docs/APPROVAL_PROCESS.md)

For detailed information about the approval process, see [docs/APPROVAL_PROCESS.md](docs/APPROVAL_PROCESS.md).
