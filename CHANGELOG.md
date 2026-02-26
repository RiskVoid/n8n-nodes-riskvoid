# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-02-26

### Fixed

- Removed broken documentation links from README (Architecture Overview, CONTRIBUTING.md)
- Removed "Unreleased" section from changelog
- Updated GitHub Release workflow to include meaningful release notes

## [1.2.0] - 2026-02-26

### Added

- **XSS Detection Rule** (RV-XSS-001) - Detects untrusted input flowing to HTML rendering sinks (`html`, `respondToWebhook`)
- **Prototype Pollution Detection Rule** (RV-PP-001) - Detects data flow to object property manipulation operations
- **Expanded Database Sink Coverage** - MariaDB, Oracle, Snowflake, CockroachDB, QuestDB, TimescaleDB, Microsoft SQL Server
- **Expanded LLM Provider Detection** - Ollama, Mistral, Groq, Azure OpenAI, Google PaLM prompt injection detection
- **Configuration-Driven Node Classification** - Node definitions externalized to JSON for easier maintenance

### Fixed

- Reduced false positives with field-level taint propagation through transform nodes
- Disabled nodes are now skipped during graph building
- Removed self-referencing runtime dependency blocking community node review

### Changed

- Improved taint analysis accuracy with data dependency tracking through Set/transform nodes
- Enhanced detection for `function` and `functionItem` legacy code nodes

## [1.1.1] - 2026-01-26

### Fixed

- Credential lookup error when using "Scan Current Workflow" or "Scan by ID" operations
  - Fixed incorrect credential name reference (`n8nApi` → `riskVoidN8nApi`)

## [1.1.0] - 2026-01-25

### Added

- **Comprehensive Documentation Suite**
  - Quick Start Guide - 5-minute setup instructions
  - Complete User Guide - Full feature documentation with examples
  - Troubleshooting Guide - Common issues and solutions
  - API credentials setup instructions with step-by-step guide
  - Example workflows for common use cases
- **Development Workflow Documentation**
  - Git branching strategy (Gitflow)
  - Branch naming conventions
  - PR workflow and release process
  - Version bumping guidelines
  - CHANGELOG.md format standards

### Fixed

- Node icon transparency issue
  - Replaced broken SVG with proper transparent icon
  - Fixed viewBox coordinates for correct rendering

### Changed

- Updated README with documentation links
- Improved npm badge caching (reduced to 5 minutes)
- Enhanced GitHub Actions workflow error handling
- Updated icon file structure (riskvoid-logo.svg)

## [1.0.0] - 2026-01-25

### Initial Release

First public release of RiskVoid Security Scanner for n8n workflows.

### Added

#### Core Features

- **Static Security Analysis** - Analyzes n8n workflows without execution
- **6 Vulnerability Detection Rules**:
  - RV-RCE-001: Code Injection (eval, exec, Function constructors)
  - RV-CMDI-001: Command Injection (shell metacharacters)
  - RV-SQLI-001: SQL Injection (MySQL, Postgres, MongoDB, etc.)
  - RV-SSRF-001: Server-Side Request Forgery (internal IPs, metadata)
  - RV-PI-001: Prompt Injection (LLM manipulation)
  - RV-CRED-001: Credential Exposure (hardcoded secrets)

#### Analysis Engine

- **Workflow Parser** - Parses n8n JSON workflows
- **Graph Builder** - Constructs directed workflow graph, detects cycles
- **Node Classifier** - Categorizes 18+ source types, 16+ sink types
- **Expression Tracer** - Parses n8n expression syntax (`{{ $json.field }}`)
- **Taint Analyzer** - Traces untrusted data flow through workflows
- **Findings Reporter** - Generates risk scores and prioritized findings

#### Export Formats

- **JSON** - Full, summary, or findings-only detail levels
- **HTML** - Self-contained reports with Mermaid.js diagrams
- **Slack** - Block Kit formatted notifications
- **SARIF 2.1.0** - CI/CD integration (GitHub Advanced Security)

#### Operations

- **Scan Current Workflow** - Analyzes workflow containing the node
- **Scan by ID** - Scans any workflow via n8n API
- **Scan Workflow JSON** - Analyzes base64-encoded workflow JSON

#### Detection Capabilities

- Tracks 18+ taint sources (webhook, form, email, Slack, Telegram, etc.)
- Monitors 16+ security sinks (code execution, database, HTTP, LLM)
- Recognizes sanitizers (IF, Switch, Filter nodes)
- Calculates confidence levels (high, medium, low)
- Provides CWE/OWASP references for all findings

### Security

- **100% Local Analysis** - No telemetry, no external API calls
- **Privacy-First** - Workflow data never leaves your n8n instance
- **Open Source** - MIT License, full transparency

### Performance

- Analysis speed: <500ms per workflow
- Tested on 80 realistic vulnerable workflows
- 81.25% detection accuracy
- 488 unit and integration tests
- 93.36% code coverage

### Documentation

- Comprehensive README with usage examples
- API documentation for all export formats
- Security rule references (CWE, OWASP, CAPEC)
- Remediation guidance for all vulnerability types

### Known Limitations

- Does not detect runtime-only vulnerabilities
- Expression value resolution through intermediate Set nodes is basic
- Some advanced SSRF bypass techniques not yet detected
- See internal enhancement documentation for planned improvements

---

[1.2.1]: https://github.com/RiskVoid/n8n-nodes-riskvoid/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/RiskVoid/n8n-nodes-riskvoid/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/RiskVoid/n8n-nodes-riskvoid/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/RiskVoid/n8n-nodes-riskvoid/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/RiskVoid/n8n-nodes-riskvoid/releases/tag/v1.0.0
