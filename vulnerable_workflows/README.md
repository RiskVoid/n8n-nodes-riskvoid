# RiskVoid Test Suite - Vulnerable Workflows

## Overview

This directory contains **80 n8n workflow files** designed to comprehensively test the RiskVoid security scanner. Each workflow represents a specific vulnerability pattern, source type, sink type, or edge case that RiskVoid must detect and report.

**Purpose**: Validate that RiskVoid correctly identifies security vulnerabilities in n8n workflows through static analysis, including:
- Code Injection (RCE)
- Command Injection
- SQL Injection
- SSRF (Server-Side Request Forgery)
- Prompt Injection
- Credential Exposure

All workflows are **intentionally vulnerable** for testing purposes and should **never** be used in production.

---

## Directory Structure

```
vulnerable_workflows/
├── 01-code-injection/           (8 workflows)
├── 02-command-injection/        (7 workflows)
├── 03-sql-injection/            (9 workflows)
├── 04-ssrf/                     (8 workflows)
├── 05-prompt-injection/         (9 workflows)
├── 06-credential-exposure/      (8 workflows)
├── 07-multi-source-coverage/    (7 workflows)
├── 08-multi-sink-coverage/      (6 workflows)
├── 09-sanitizers/               (6 workflows)
├── 10-complex-flows/            (6 workflows)
└── 11-edge-cases/               (6 workflows)
```

**Total**: 80 workflow files across 11 categories

---

## Workflow Index

### Category 1: Code Injection (RCE) - 8 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `rce-webhook-eval.json` | `vuln-rce-001` | Code Injection | `RV-RCE-001` | Critical | Webhook → Code node with `eval()` |
| `rce-form-function-constructor.json` | `vuln-rce-002` | Code Injection | `RV-RCE-001` | Critical | Form → Code with Function constructor |
| `rce-email-settimeout.json` | `vuln-rce-003` | Code Injection | `RV-RCE-001` | Critical | Email → Code with `setTimeout` |
| `rce-slack-python-exec.json` | `vuln-rce-004` | Code Injection | `RV-RCE-001` | Critical | Slack → Code with Python `exec()` |
| `rce-telegram-subprocess.json` | `vuln-rce-005` | Code Injection | `RV-RCE-001` | Critical | Telegram → Code with subprocess |
| `rce-discord-vm-run.json` | `vuln-rce-006` | Code Injection | `RV-RCE-001` | Critical | Discord → Code with `vm.runInNewContext` |
| `rce-rss-os-system.json` | `vuln-rce-007` | Code Injection | `RV-RCE-001` | Critical | RSS Feed → Code with `os.system` |
| `safe-code-trusted-source.json` | `safe-rce-001` | **SAFE** | None | N/A | Schedule → Code (trusted source, no vuln) |

### Category 2: Command Injection - 7 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `cmdi-webhook-semicolon.json` | `vuln-cmdi-001` | Command Injection | `RV-CMDI-001` | Critical | Webhook → Execute Command with semicolon chaining |
| `cmdi-form-pipe.json` | `vuln-cmdi-002` | Command Injection | `RV-CMDI-001` | Critical | Form → Execute Command with pipe operator |
| `cmdi-email-ampersand.json` | `vuln-cmdi-003` | Command Injection | `RV-CMDI-001` | Critical | Email → Execute Command with ampersand background |
| `cmdi-telegram-substitution.json` | `vuln-cmdi-004` | Command Injection | `RV-CMDI-001` | Critical | Telegram → Execute Command with command substitution |
| `cmdi-discord-backticks.json` | `vuln-cmdi-005` | Command Injection | `RV-CMDI-001` | Critical | Discord → Execute Command with backtick substitution |
| `cmdi-slack-variable-expansion.json` | `vuln-cmdi-006` | Command Injection | `RV-CMDI-001` | Critical | Slack → Execute Command with variable expansion |
| `safe-command-hardcoded.json` | `safe-cmdi-001` | **SAFE** | None | N/A | Manual Trigger → Execute Command (hardcoded, no vuln) |

### Category 3: SQL Injection - 9 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `sqli-webhook-mysql-raw.json` | `vuln-sqli-001` | SQL Injection | `RV-SQLI-001` | High | Webhook → MySQL with raw SELECT |
| `sqli-form-postgres-insert.json` | `vuln-sqli-002` | SQL Injection | `RV-SQLI-001` | High | Form → Postgres with raw INSERT |
| `sqli-email-mysql-update.json` | `vuln-sqli-003` | SQL Injection | `RV-SQLI-001` | High | Email → MySQL with raw UPDATE |
| `sqli-telegram-postgres-delete.json` | `vuln-sqli-004` | SQL Injection | `RV-SQLI-001` | High | Telegram → Postgres with raw DELETE |
| `sqli-slack-mysql-union.json` | `vuln-sqli-005` | SQL Injection | `RV-SQLI-001` | High | Slack → MySQL with UNION injection pattern |
| `sqli-discord-mongodb-nosql.json` | `vuln-sqli-006` | NoSQL Injection | `RV-SQLI-001` | High | Discord → MongoDB with NoSQL injection |
| `sqli-http-mssql.json` | `vuln-sqli-007` | SQL Injection | `RV-SQLI-001` | High | HTTP Request → MS SQL with raw query |
| `safe-sql-parameterized.json` | `safe-sqli-001` | **SAFE** | None | N/A | Webhook → MySQL with parameterized query |
| `safe-sql-trusted.json` | `safe-sqli-002` | **SAFE** | None | N/A | Schedule → MySQL (trusted source) |

### Category 4: SSRF - 8 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `ssrf-webhook-localhost.json` | `vuln-ssrf-001` | SSRF | `RV-SSRF-001` | High | Webhook → HTTP Request targeting localhost |
| `ssrf-form-private-class-a.json` | `vuln-ssrf-002` | SSRF | `RV-SSRF-001` | High | Form → HTTP Request targeting 10.x.x.x |
| `ssrf-email-private-class-b.json` | `vuln-ssrf-003` | SSRF | `RV-SSRF-001` | High | Email → HTTP Request targeting 172.16.x.x |
| `ssrf-telegram-private-class-c.json` | `vuln-ssrf-004` | SSRF | `RV-SSRF-001` | High | Telegram → HTTP Request targeting 192.168.x.x |
| `ssrf-slack-metadata-aws.json` | `vuln-ssrf-005` | SSRF (Critical) | `RV-SSRF-001` | Critical | Slack → AWS Metadata API (169.254.169.254) |
| `ssrf-discord-metadata-gcp.json` | `vuln-ssrf-006` | SSRF | `RV-SSRF-001` | High | Discord → GCP Metadata API |
| `ssrf-webhook-file-protocol.json` | `vuln-ssrf-007` | SSRF | `RV-SSRF-001` | High | Webhook → HTTP Request with file:// protocol |
| `safe-ssrf-allowlist.json` | `safe-ssrf-001` | **SAFE** | None | N/A | Webhook → HTTP with domain allowlist validation |

### Category 5: Prompt Injection - 9 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `pi-webhook-openai-direct.json` | `vuln-pi-001` | Prompt Injection | `RV-PI-001` | Medium | Webhook → OpenAI with direct concatenation |
| `pi-form-anthropic-highrisk.json` | `vuln-pi-002` | Prompt Injection | `RV-PI-001` | Medium | Form → Anthropic (high-risk prompt) |
| `pi-email-ollama.json` | `vuln-pi-003` | Prompt Injection | `RV-PI-001` | Medium | Email → Ollama with no isolation |
| `pi-telegram-azure-openai.json` | `vuln-pi-004` | Prompt Injection | `RV-PI-001` | Medium | Telegram → Azure OpenAI |
| `pi-slack-google-palm.json` | `vuln-pi-005` | Prompt Injection | `RV-PI-001` | Medium | Slack → Google PaLM |
| `pi-discord-mistral.json` | `vuln-pi-006` | Prompt Injection | `RV-PI-001` | Medium | Discord → Mistral Cloud |
| `pi-rss-groq.json` | `vuln-pi-007` | Prompt Injection | `RV-PI-001` | Medium | RSS Feed → Groq |
| `safe-pi-xml-tags.json` | `safe-pi-001` | **SAFE** | None | N/A | Webhook → OpenAI with XML tag isolation |
| `safe-pi-code-blocks.json` | `safe-pi-002` | **SAFE** | None | N/A | Webhook → OpenAI with code block isolation |

### Category 6: Credential Exposure - 8 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `cred-hardcoded-openai.json` | `vuln-cred-001` | Hardcoded Secret | `RV-CRED-001` | Medium | Hardcoded OpenAI API key in HTTP Request |
| `cred-hardcoded-github.json` | `vuln-cred-002` | Hardcoded Secret | `RV-CRED-001` | Medium | Hardcoded GitHub PAT in Set node |
| `cred-hardcoded-aws.json` | `vuln-cred-003` | Hardcoded Secret | `RV-CRED-001` | Medium | Hardcoded AWS access key in Set node |
| `cred-hardcoded-stripe.json` | `vuln-cred-004` | Hardcoded Secret | `RV-CRED-001` | Medium | Hardcoded Stripe secret key in Set node |
| `cred-hardcoded-jwt.json` | `vuln-cred-005` | Hardcoded Secret | `RV-CRED-001` | Medium | Hardcoded JWT token in HTTP Request |
| `cred-exposure-slack.json` | `vuln-cred-006` | Credential Exposure | `RV-CRED-002` | Medium | Credentials exposed via Slack output |
| `cred-exposure-webhook-response.json` | `vuln-cred-007` | Credential Exposure | `RV-CRED-002` | Medium | Credentials exposed via webhook response |
| `safe-cred-n8n-credentials.json` | `safe-cred-001` | **SAFE** | None | N/A | Using n8n's built-in credential system |

### Category 7: Multi-Source Coverage - 7 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `source-email-trigger.json` | N/A | SQL Injection | `RV-SQLI-001` | High | Tests EmailReadImap as taint source |
| `source-github.json` | N/A | SQL Injection | `RV-SQLI-001` | High | Tests GitHub Trigger as taint source |
| `source-gmail.json` | N/A | Command Injection | `RV-CMDI-001` | Critical | Tests Gmail Trigger as taint source |
| `source-http-response.json` | N/A | Code Injection | `RV-RCE-001` | Critical | Tests HTTP Response data as taint source |
| `source-hubspot.json` | N/A | SSRF | `RV-SSRF-001` | High | Tests HubSpot Trigger as taint source |
| `source-rss-feed.json` | N/A | Code Injection | `RV-RCE-001` | Critical | Tests RSS Feed as taint source |
| `source-stripe.json` | N/A | Code Injection | `RV-RCE-001` | Critical | Tests Stripe Trigger as taint source |

### Category 8: Multi-Sink Coverage - 6 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `sink-ssh-command.json` | `vuln-sink-001` | Command Injection | `RV-CMDI-001` | Critical | Tests SSH node as command sink |
| `sink-function-node.json` | `vuln-sink-002` | Code Injection | `RV-RCE-001` | Critical | Tests Function node as code sink |
| `sink-function-item.json` | `vuln-sink-003` | Code Injection | `RV-RCE-001` | Critical | Tests FunctionItem node as code sink |
| `sink-mariadb.json` | `vuln-sink-004` | SQL Injection | `RV-SQLI-001` | High | Tests MariaDB node as SQL sink |
| `sink-oracle.json` | `vuln-sink-005` | SQL Injection | `RV-SQLI-001` | High | Tests Oracle Database as SQL sink |
| `sink-respond-webhook.json` | `vuln-sink-006` | XSS/Data Exposure | `RV-XSS-001` | Medium | Tests Respond to Webhook as output sink |

### Category 9: Sanitizers - 6 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `sanitizer-if-regex.json` | `vuln-sanitizer-001` | SQL Injection | `RV-SQLI-001` | High | IF node with regex validation (should reduce severity) |
| `sanitizer-switch-allowlist.json` | `vuln-sanitizer-002` | Command Injection | `RV-CMDI-001` | Critical | Switch node with allowlist (should reduce severity) |
| `sanitizer-filter-blocks.json` | `vuln-sanitizer-003` | Command Injection | `RV-CMDI-001` | Critical | Filter node blocking patterns (should reduce severity) |
| `sanitizer-code-validator.json` | `vuln-sanitizer-004` | SSRF | `RV-SSRF-001` | High | Code node validation (should reduce severity) |
| `sanitizer-chain-multiple.json` | `vuln-sanitizer-005` | Command Injection | `RV-CMDI-001` | Critical | Multiple sanitizers chained (should reduce severity) |
| `sanitizer-weak-bypass.json` | `vuln-sanitizer-006` | SQL Injection | `RV-SQLI-001` | High | Weak sanitizer that can be bypassed (should still detect) |

### Category 10: Complex Flows - 6 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `flow-chain-through-sets.json` | N/A | Code Injection | `RV-RCE-001` | Critical | Taint flows through multiple Set nodes |
| `flow-branching-if-paths.json` | N/A | Multiple | Various | Various | Branching paths with different vulnerabilities |
| `flow-multi-source-convergence.json` | N/A | Code Injection | `RV-RCE-001` | Critical | Multiple sources converging to single sink |
| `flow-fan-out-multi-sink.json` | N/A | Multiple | Various | Various | Single source flowing to multiple sinks |
| `flow-nested-expressions.json` | N/A | Code Injection | `RV-RCE-001` | Critical | Nested n8n expressions like `{{ $('Node').item.json }}` |
| `flow-dual-role-http.json` | N/A | SSRF | `RV-SSRF-001` | High | HTTP Request as both source and sink |

### Category 11: Edge Cases - 6 workflows

| Filename | Workflow ID | Vulnerability | Expected Rule | Severity | Description |
|----------|-------------|---------------|---------------|----------|-------------|
| `edge-disconnected-vulnerable.json` | `edge-001` | Code Injection | None | N/A | Vulnerable node exists but disconnected (should NOT detect) |
| `edge-disabled-vulnerable.json` | `edge-002` | Code Injection | None | N/A | Vulnerable node is disabled (should NOT detect) |
| `edge-circular-reference.json` | `edge-003` | Code Injection | `RV-RCE-001` | Critical | Workflow with circular node references |
| `edge-deep-graph-20-nodes.json` | `vuln-edge-001` | Code Injection | `RV-RCE-001` | Critical | Deep graph with 20+ nodes (stress test) |
| `edge-all-vulnerabilities.json` | `vuln-edge-002` | All Types | Multiple | Various | Single workflow with all vulnerability types |
| `edge-static-values-only.json` | `safe-edge-001` | None | None | N/A | No expressions, only static values (safe) |

---

## Coverage Matrix

### Source Types Tested (18 total)

| Source Type | Node Name | Workflows Using It |
|-------------|-----------|-------------------|
| Webhook | `n8n-nodes-base.webhook` | 25+ workflows |
| Form Trigger | `n8n-nodes-base.formTrigger` | 8 workflows |
| Email Trigger | `n8n-nodes-base.emailReadImap` | 7 workflows |
| Slack Trigger | `n8n-nodes-base.slack` | 8 workflows |
| Telegram Trigger | `n8n-nodes-base.telegram` | 7 workflows |
| Discord Trigger | `n8n-nodes-base.discord` | 6 workflows |
| RSS Feed | `n8n-nodes-base.rssFeedRead` | 3 workflows |
| GitHub Trigger | `n8n-nodes-base.githubTrigger` | 1 workflow |
| Gmail Trigger | `n8n-nodes-base.gmail` | 1 workflow |
| HubSpot Trigger | `n8n-nodes-base.hubspotTrigger` | 1 workflow |
| Stripe Trigger | `n8n-nodes-base.stripeTrigger` | 1 workflow |
| HTTP Request (response) | `n8n-nodes-base.httpRequest` | 2 workflows |
| Schedule Trigger | `n8n-nodes-base.scheduleTrigger` | 3 workflows (safe) |
| Manual Trigger | `n8n-nodes-base.manualTrigger` | 2 workflows (safe) |

### Sink Types Tested (16 total)

| Sink Type | Node Name | Field | Workflows |
|-----------|-----------|-------|-----------|
| Code Node (JS) | `n8n-nodes-base.code` | `jsCode` | 15+ workflows |
| Code Node (Python) | `n8n-nodes-base.code` | `pythonCode` | 3 workflows |
| Execute Command | `n8n-nodes-base.executeCommand` | `command` | 7 workflows |
| MySQL | `n8n-nodes-base.mySql` | `query` | 6 workflows |
| PostgreSQL | `n8n-nodes-base.postgres` | `query` | 3 workflows |
| MongoDB | `n8n-nodes-base.mongoDb` | `query` | 1 workflow |
| MS SQL | `n8n-nodes-base.microsoftSql` | `query` | 1 workflow |
| MariaDB | `n8n-nodes-base.mariaDb` | `query` | 1 workflow |
| Oracle DB | `n8n-nodes-base.oracleDb` | `query` | 1 workflow |
| HTTP Request | `n8n-nodes-base.httpRequest` | `url` | 10+ workflows |
| OpenAI | `@n8n/n8n-nodes-langchain.lmChatOpenAi` | `prompt` | 3 workflows |
| Anthropic | `@n8n/n8n-nodes-langchain.lmChatAnthropic` | `prompt` | 1 workflow |
| Azure OpenAI | `@n8n/n8n-nodes-langchain.lmChatAzureOpenAi` | `prompt` | 1 workflow |
| Google PaLM | `@n8n/n8n-nodes-langchain.lmChatGooglePalm` | `prompt` | 1 workflow |
| SSH | `n8n-nodes-base.ssh` | `command` | 1 workflow |
| Respond to Webhook | `n8n-nodes-base.respondToWebhook` | `body` | 1 workflow |

### Detection Patterns Covered

| Pattern Type | Description | Workflows |
|--------------|-------------|-----------|
| Direct taint flow | Source → Sink (2 nodes) | 30+ workflows |
| Intermediate transformation | Source → Set → Sink | 15+ workflows |
| Branching paths | Source → IF/Switch → Multiple sinks | 8 workflows |
| Multi-source convergence | Multiple sources → Single sink | 2 workflows |
| Fan-out pattern | Single source → Multiple sinks | 2 workflows |
| Deep chains | 10+ nodes in path | 2 workflows |
| Nested expressions | `{{ $('Node').item.json.field }}` | 5 workflows |
| Sanitizer detection | IF/Switch/Filter between source/sink | 6 workflows |
| Circular references | Nodes referencing each other | 1 workflow |
| Disconnected nodes | Vulnerable but unreachable | 1 workflow |
| Disabled nodes | Vulnerable but disabled | 1 workflow |

---

## Expected Detection Results

### Critical Vulnerabilities (should detect)
- **Code Injection (RCE)**: 15 workflows → Should detect 14 (excluding `safe-code-trusted-source.json`)
- **Command Injection**: 7 workflows → Should detect 6 (excluding `safe-command-hardcoded.json`)
- **SSRF to Metadata APIs**: 2 workflows → Should detect both with elevated severity

### High Vulnerabilities (should detect)
- **SQL Injection**: 9 workflows → Should detect 7 (excluding 2 safe workflows)
- **SSRF**: 8 workflows → Should detect 7 (excluding `safe-ssrf-allowlist.json`)

### Medium Vulnerabilities (should detect)
- **Prompt Injection**: 9 workflows → Should detect 7 (excluding 2 safe workflows)
- **Credential Exposure**: 8 workflows → Should detect 7 (excluding `safe-cred-n8n-credentials.json`)

### Safe Workflows (should NOT detect)
- All workflows prefixed with `safe-` (9 total)
- `edge-disconnected-vulnerable.json` (disconnected node)
- `edge-disabled-vulnerable.json` (disabled node)
- `edge-static-values-only.json` (no expressions)

### Sanitizer Workflows (should detect with reduced severity)
- All 6 sanitizer workflows should still detect vulnerabilities
- BUT should note sanitizer presence in findings
- May reduce confidence score or severity in some cases

---

## Usage Instructions

### Manual Testing with RiskVoid Node

1. **Import a workflow** into n8n (see Import Instructions below)
2. **Add RiskVoid node** to your n8n canvas
3. **Configure RiskVoid node**:
   - Set "Analysis Mode" to "Active Workflow"
   - Or set to "JSON Input" and paste workflow JSON
4. **Execute the RiskVoid node**
5. **Review the output** for detected vulnerabilities

Expected output structure:
```json
{
  "riskScore": 85,
  "riskLevel": "critical",
  "findings": [
    {
      "id": "RV-RCE-001-xxx",
      "severity": "critical",
      "title": "Remote Code Execution via User Input",
      "path": ["Webhook", "Set", "Code"],
      "remediation": {
        "summary": "Validate and sanitize user input before code execution",
        "steps": ["Add IF node to validate input", "Use allowlist patterns"]
      }
    }
  ]
}
```

### Automated Testing (Integration Tests)

```bash
# Navigate to project root
cd /Users/ruslansazonov/development/n8n-nodes-riskvoid

# Run integration tests (when implemented)
npm test -- --testPathPattern=integration

# Run specific test category
npm test -- --testPathPattern=code-injection

# Run with coverage
npm test -- --coverage
```

### Testing Individual Workflows

```typescript
// Example integration test
import { analyzeWorkflow } from '../src/analysis';
import rceWebhookWorkflow from './vulnerable_workflows/01-code-injection/rce-webhook-eval.json';

test('RV-RCE-001: Detects webhook to eval() code injection', () => {
  const result = analyzeWorkflow(rceWebhookWorkflow);

  expect(result.findings).toHaveLength(1);
  expect(result.findings[0].ruleId).toBe('RV-RCE-001');
  expect(result.findings[0].severity).toBe('critical');
  expect(result.riskLevel).toBe('critical');
});
```

---

## Import Instructions

### Option 1: Import via n8n UI

1. **Open n8n** in your browser
2. Click **"Add workflow"** (+ button in top right)
3. Click the **three dots menu** (⋯) → **"Import from file"**
4. **Select a JSON file** from this directory
5. Click **"Import"**
6. The workflow will open in the editor

### Option 2: Import via n8n CLI (if available)

```bash
# Copy workflow to n8n's workflow directory
cp vulnerable_workflows/01-code-injection/rce-webhook-eval.json \
   ~/.n8n/workflows/

# Restart n8n to load the workflow
n8n start
```

### Option 3: Copy-Paste JSON

1. **Open the JSON file** in a text editor
2. **Copy the entire contents**
3. In n8n, click **"Add workflow"** → **"Import from URL or JSON"**
4. **Paste the JSON** into the text area
5. Click **"Import"**

### Verifying Import

After importing, you should see:
- **Workflow name** matching the file (e.g., "RCE - Webhook to Code with eval()")
- **All nodes** connected properly (check the canvas)
- **No error indicators** on nodes (red triangles)
- **Proper node connections** (check the arrows between nodes)

---

## Testing Methodology

### Phase 1: Individual Rule Testing
Test each detection rule in isolation:
1. Run all **Code Injection** workflows (01-code-injection/)
2. Verify **RV-RCE-001** detects all vulnerable patterns
3. Verify **safe-code-trusted-source.json** shows no findings
4. Repeat for each vulnerability category

### Phase 2: Source Coverage Testing
Verify all taint sources are recognized:
1. Run all **Multi-Source Coverage** workflows (07-multi-source-coverage/)
2. Confirm each source type (Email, GitHub, Gmail, etc.) is detected
3. Verify taint propagates from source to sink

### Phase 3: Sink Coverage Testing
Verify all dangerous sinks are recognized:
1. Run all **Multi-Sink Coverage** workflows (08-multi-sink-coverage/)
2. Confirm each sink type (SSH, Function, MariaDB, etc.) is detected
3. Verify proper severity assignment per sink type

### Phase 4: Sanitizer Testing
Test sanitizer detection and impact:
1. Run all **Sanitizer** workflows (09-sanitizers/)
2. Verify vulnerabilities are still detected
3. Check if sanitizer presence affects severity/confidence
4. Confirm weak sanitizers (bypass cases) are still flagged

### Phase 5: Complex Flow Testing
Test advanced data flow patterns:
1. Run all **Complex Flows** workflows (10-complex-flows/)
2. Verify multi-step taint propagation
3. Test branching and convergence patterns
4. Validate nested expression parsing

### Phase 6: Edge Case Testing
Test boundary conditions:
1. Run all **Edge Cases** workflows (11-edge-cases/)
2. Verify disconnected nodes are NOT detected
3. Verify disabled nodes are NOT detected
4. Test deep graphs (performance and correctness)
5. Verify multiple vulnerabilities in one workflow

---

## Expected Test Results Summary

| Category | Total Workflows | Should Detect | Should Skip | Expected Rule IDs |
|----------|----------------|---------------|-------------|-------------------|
| Code Injection | 8 | 7 | 1 (safe) | RV-RCE-001 |
| Command Injection | 7 | 6 | 1 (safe) | RV-CMDI-001 |
| SQL Injection | 9 | 7 | 2 (safe) | RV-SQLI-001 |
| SSRF | 8 | 7 | 1 (safe) | RV-SSRF-001 |
| Prompt Injection | 9 | 7 | 2 (safe) | RV-PI-001 |
| Credential Exposure | 8 | 7 | 1 (safe) | RV-CRED-001, RV-CRED-002 |
| Multi-Source | 7 | 7 | 0 | Various |
| Multi-Sink | 6 | 6 | 0 | Various |
| Sanitizers | 6 | 6 | 0 | Various (reduced severity) |
| Complex Flows | 6 | 6 | 0 | Various |
| Edge Cases | 6 | 2 | 4 | Various |
| **TOTAL** | **80** | **68** | **12** | |

**Success Criteria**:
- **True Positives**: 68 vulnerabilities detected correctly
- **True Negatives**: 12 safe workflows with no false alarms
- **False Positives**: 0 (no safe workflows incorrectly flagged)
- **False Negatives**: 0 (all vulnerable workflows detected)

---

## Troubleshooting

### Workflow Import Fails
- **Cause**: Incompatible n8n version
- **Solution**: These workflows are designed for n8n 1.x. Update n8n to latest version.

### Nodes Show as "Unknown"
- **Cause**: Missing node packages (e.g., LangChain nodes)
- **Solution**: Install required community nodes:
  ```bash
  npm install @n8n/n8n-nodes-langchain
  ```

### RiskVoid Shows No Findings on Vulnerable Workflow
- **Potential Issues**:
  1. RiskVoid node not properly built/installed
  2. Analysis mode set incorrectly
  3. Workflow has disabled/disconnected nodes (expected behavior)
- **Solution**: Check RiskVoid logs, verify node configuration

### Tests Fail with "Cannot find module"
- **Cause**: Missing test fixtures or dependencies
- **Solution**: Ensure all workflow files are present in `vulnerable_workflows/`

---

## Contributing

When adding new test workflows:

1. **Follow naming convention**: `{category}-{source}-{pattern}.json`
2. **Include workflow ID**: Use format `vuln-{category}-{number}` or `safe-{category}-{number}`
3. **Document expected behavior**: Update this README with new workflow details
4. **Test thoroughly**: Verify workflow imports and RiskVoid detects correctly
5. **Update coverage matrix**: Add new source/sink types if introduced

---

## License

These test workflows are part of the RiskVoid project and are licensed under the same terms.

**⚠️ WARNING**: All workflows in this directory are **intentionally vulnerable**. Never use them in production environments or with real credentials/data.

---

## Additional Resources

- [RiskVoid Project README](../README.md)
- [Phase 3 PRD - Detection Rules](../docs/03-PRD-PHASE-3-DETECTION-RULES.md)
- [n8n Node Documentation](https://docs.n8n.io/integrations/)
- [n8n Expression Syntax](https://docs.n8n.io/code/expressions/)

---

**Last Updated**: 2026-01-25
**Version**: 1.0.0
**Total Workflows**: 80
