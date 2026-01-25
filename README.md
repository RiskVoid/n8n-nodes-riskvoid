# n8n-nodes-riskvoid

![RiskVoid Security](https://img.shields.io/badge/security-scanner-blue)
![npm version](https://img.shields.io/npm/v/n8n-nodes-riskvoid)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

> **The first security scanner for n8n workflows** - Detect vulnerabilities before they reach production. 100% local, no data leaves your instance.

## What is RiskVoid?

RiskVoid is an n8n community node that performs static security analysis on your workflows. It detects critical vulnerabilities like:

- 🔴 **Code Injection (RCE)** - Remote code execution via eval(), exec(), Function constructors
- 🔴 **Command Injection** - Shell command injection with user input
- 🟡 **SQL Injection** - Unsafe database queries with tainted data
- 🟡 **SSRF** - Server-side request forgery to internal networks or cloud metadata
- 🟠 **Prompt Injection** - LLM prompt manipulation attacks
- 🟠 **Credential Exposure** - Hardcoded API keys and secret leakage

## Features

- ✅ **6 Vulnerability Types** - Comprehensive coverage of n8n security risks
- ✅ **18+ Taint Sources** - Tracks untrusted input from webhooks, forms, emails, etc.
- ✅ **16+ Security Sinks** - Monitors dangerous operations (code execution, database queries, HTTP requests)
- ✅ **Smart Taint Analysis** - Traces data flow through complex workflow graphs
- ✅ **Sanitizer Detection** - Recognizes IF/Switch/Filter nodes that reduce risk
- ✅ **4 Export Formats** - JSON, HTML reports, Slack notifications, SARIF for CI/CD
- ✅ **100% Local** - No telemetry, all analysis happens in-process
- ✅ **81% Detection Accuracy** - Tested on 80 realistic vulnerable workflows

## Installation

### Via npm (Recommended)

```bash
npm install n8n-nodes-riskvoid
```

Then restart your n8n instance. The RiskVoid Security node will appear in the node panel.

### Via n8n Community Nodes

1. Go to **Settings** → **Community Nodes**
2. Click **Install** and enter: `n8n-nodes-riskvoid`
3. Click **Install**
4. Restart n8n

## Quick Start

### Scan Current Workflow

1. Add **RiskVoid Security** node to your workflow
2. Select operation: **Scan Current Workflow**
3. Configure n8n API credentials (Settings → Credentials → n8n API)
4. Execute the node
5. Review security findings in JSON output

### Scan Specific Workflow

1. Use operation: **Scan by ID**
2. Enter workflow ID
3. Execute and review findings

### Scan from JSON

1. Use operation: **Scan Workflow JSON**
2. Paste workflow JSON (base64 encoded)
3. Execute and review findings

## Configuration Options

| Option | Description | Values |
| ------ | ----------- | ------ |
| **Export Format** | Output format | json, html, slack, sarif |
| **Minimum Severity** | Filter findings | critical, high, medium, low, info |
| **Categories** | Vulnerability types | injection, ssrf, credential-exposure, etc. |
| **Include Remediation** | Detailed fix guidance | true/false |
| **Output Detail** | Verbosity level | full, summary, findings |

## Example Output

```json
{
  "riskScore": 85,
  "riskLevel": "critical",
  "findings": [
    {
      "id": "RV-RCE-001-abc123",
      "severity": "critical",
      "title": "Remote Code Execution via eval() with User Input",
      "category": "injection",
      "path": ["Webhook", "Set Data", "Execute Code"],
      "description": "User input flows to eval() without sanitization",
      "remediation": {
        "summary": "Never use eval() with user input. Use allowlist validation.",
        "steps": [
          "Add IF node to validate input format",
          "Use JSON.parse() instead of eval() for JSON data",
          "Implement strict allowlist of permitted operations"
        ]
      },
      "references": {
        "cwe": "CWE-94",
        "owasp": "A03:2021-Injection"
      }
    }
  ]
}
```

## Supported Vulnerability Types

### Code Injection (RV-RCE-001)

**Severity**: Critical

Detects dangerous code patterns:

- JavaScript: `eval()`, `Function()`, `setTimeout()`, `vm.run()`
- Python: `exec()`, `compile()`, `subprocess`, `os.system()`

### Command Injection (RV-CMDI-001)

**Severity**: Critical

Detects shell metacharacters in Execute Command nodes:

- `;`, `|`, `&`, `$()`, backticks, `${}`

### SQL Injection (RV-SQLI-001)

**Severity**: High

Detects unsafe database queries:

- MySQL, PostgreSQL, MongoDB, MSSQL, Oracle, MariaDB
- Raw query mode with user input
- Recommends parameterized queries

### SSRF (RV-SSRF-001)

**Severity**: High

Detects server-side request forgery:

- Internal IPs: 127.x, 10.x, 192.168.x, 172.16-31.x
- Cloud metadata: 169.254.169.254, metadata.google.internal
- Protocol abuse: file://, gopher://

### Prompt Injection (RV-PI-001)

**Severity**: Medium

Detects LLM prompt manipulation:

- OpenAI, Anthropic, Ollama, Azure OpenAI, Google PaLM
- Direct user input concatenation
- Missing isolation (XML tags, code blocks)

### Credential Exposure (RV-CRED-001)

**Severity**: High/Medium

Detects hardcoded secrets:

- OpenAI (sk-), GitHub (ghp_), AWS (AKIA), Stripe (sk_live_)
- JWT tokens, API keys in parameters
- Credentials exposed in external outputs

## Requirements

- n8n version: 1.0.0 or higher
- Node.js: 18.x or higher
- n8n API credentials (for "Scan Current Workflow" operation)

## Use Cases

### CI/CD Pipeline

Export findings as SARIF and integrate with GitHub Advanced Security:

```bash
# In your CI pipeline
curl -X POST http://localhost:5678/webhook/riskvoid-scan \
  -H "Content-Type: application/json" \
  -d '{"workflowId": "123"}' > findings.sarif

# Upload to GitHub
gh api repos/owner/repo/code-scanning/sarifs -F sarif=@findings.sarif
```

### Slack Notifications

Configure Slack export format and send security alerts to your team.

### HTML Reports

Generate standalone HTML reports with Mermaid.js workflow diagrams.

## Performance

- Analysis speed: ~0.22ms per workflow (tested on 80 workflows)
- Memory usage: Minimal (in-process analysis)
- No external API calls
- Scales to workflows with 20+ nodes

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development

```bash
# Clone repository
git clone https://github.com/ruslan-sazonov/n8n-nodes-riskvoid.git
cd n8n-nodes-riskvoid

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Lint
npm run lint
```

## Support

- **Issues**: [GitHub Issues](https://github.com/ruslan-sazonov/n8n-nodes-riskvoid/issues)
- **Email**: [hello@riskvoid.com](mailto:hello@riskvoid.com)
- **Documentation**: [Wiki](https://github.com/ruslan-sazonov/n8n-nodes-riskvoid/wiki)

## License

MIT © RiskVoid

## Acknowledgments

Built with the n8n community node framework. Special thanks to the n8n team for creating an extensible automation platform.

---

Made with ❤️ for the n8n community
