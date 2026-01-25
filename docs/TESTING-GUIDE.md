# RiskVoid Local Testing Guide

This guide provides comprehensive testing scenarios for validating RiskVoid on your local n8n instance.

## Prerequisites

1. **Install RiskVoid in n8n**
   ```bash
   cd /path/to/n8n-nodes-riskvoid
   npm run build
   npm link

   # In your n8n installation directory
   cd ~/.n8n/custom
   npm link n8n-nodes-riskvoid

   # Restart n8n
   ```

2. **Configure n8n API Credential**
   - Go to **Settings > n8n API** in your n8n instance
   - Create an API key
   - In n8n, create a new credential of type "n8n API"
   - Enter your API key and base URL (usually `http://localhost:5678`)

---

## Test Scenarios

### Scenario 1: Basic Scan - JSON Export (Default)

**Purpose**: Verify basic scanning functionality with default JSON output.

**Workflow to Create**:
```
Manual Trigger → RiskVoid (Scan Current Workflow)
```

**RiskVoid Settings**:
- Operation: `Scan Current Workflow`
- Export Format: `JSON (Default)`
- Output Format: `Full Report`

**Expected Output**:
```json
{
  "metadata": { "version": "1.0.0", ... },
  "workflow": { "name": "...", "nodeCount": 2 },
  "risk": { "score": 0, "level": "none" },
  "summary": { "totalFindings": 0 },
  "findings": []
}
```

---

### Scenario 2: Code Injection Detection (Critical)

**Purpose**: Detect Remote Code Execution vulnerability via user input in Code node.

**Workflow to Create**:
```
Webhook (POST /execute) → Code Node
```

**Code Node Configuration**:
```javascript
// In the Code node's JavaScript field:
const userInput = {{ $json.body.code }};
eval(userInput);
return items;
```

**RiskVoid Settings**:
- Operation: `Scan Current Workflow`
- Export Format: `JSON (Default)`
- Minimum Severity: `Medium and Above`

**Test by Executing**:
1. Save the workflow
2. Connect RiskVoid node after the Code node (or create a separate scan workflow)
3. Run the RiskVoid node

**Expected Finding**:
```json
{
  "riskScore": 40+,
  "riskLevel": "high" or "critical",
  "findings": [{
    "ruleId": "RV-RCE-001",
    "severity": "critical",
    "title": "Remote Code Execution via User Input",
    "category": "injection",
    "source": { "node": "Webhook", "field": "body.code" },
    "sink": { "node": "Code", "parameter": "jsCode" }
  }]
}
```

---

### Scenario 3: Command Injection Detection (Critical)

**Purpose**: Detect OS command injection vulnerability.

**Workflow to Create**:
```
Webhook (POST /exec) → Execute Command
```

**Execute Command Configuration**:
```
Command: ls -la {{ $json.body.directory }}
```

**Expected Finding**:
```json
{
  "ruleId": "RV-CMDI-001",
  "severity": "critical",
  "title": "Command Injection via User Input",
  "category": "injection"
}
```

---

### Scenario 4: SQL Injection Detection (High)

**Purpose**: Detect SQL injection in raw query mode.

**Workflow to Create**:
```
Webhook (GET /users) → MySQL (Execute Query)
```

**MySQL Configuration**:
- Operation: `Execute Query`
- Query: `SELECT * FROM users WHERE id = '{{ $json.query.userId }}'`

**Expected Finding**:
```json
{
  "ruleId": "RV-SQLI-001",
  "severity": "high",
  "title": "SQL Injection via User Input",
  "category": "injection"
}
```

---

### Scenario 5: SSRF Detection (High)

**Purpose**: Detect Server-Side Request Forgery vulnerability.

**Workflow to Create**:
```
Webhook (POST /fetch) → HTTP Request
```

**HTTP Request Configuration**:
- URL: `={{ $json.body.targetUrl }}`
- Method: GET

**Expected Finding**:
```json
{
  "ruleId": "RV-SSRF-001",
  "severity": "high",
  "title": "Server-Side Request Forgery via User Input",
  "category": "ssrf"
}
```

---

### Scenario 6: Prompt Injection Detection (Medium)

**Purpose**: Detect prompt injection in LLM nodes.

**Workflow to Create**:
```
Telegram Trigger → OpenAI (or any LangChain node)
```

**OpenAI Configuration**:
```
Prompt: You are a helpful assistant. User says: {{ $json.message.text }}
```

**Expected Finding**:
```json
{
  "ruleId": "RV-PI-001",
  "severity": "medium",
  "title": "Prompt Injection via User Input",
  "category": "prompt-injection"
}
```

---

### Scenario 7: Credential Exposure Detection (Medium)

**Purpose**: Detect hardcoded API keys and secrets.

**Workflow to Create**:
```
Manual Trigger → HTTP Request
```

**HTTP Request Configuration**:
- URL: `https://api.openai.com/v1/chat/completions`
- Headers:
  - Authorization: `Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123456`

**Expected Finding**:
```json
{
  "ruleId": "RV-CRED-001",
  "severity": "medium",
  "title": "Hardcoded API Key Detected",
  "category": "credential-exposure"
}
```

---

### Scenario 8: HTML Report Export

**Purpose**: Test HTML report generation with visual elements.

**Workflow to Create**: Use any vulnerable workflow from scenarios 2-7.

**RiskVoid Settings**:
- Export Format: `HTML Report`

**Expected Output**:
```json
{
  "html": "<!DOCTYPE html>...",
  "mermaid": "graph LR...",
  "riskScore": ...,
  "riskLevel": "...",
  "findingsCount": ...
}
```

**Verification**:
1. Copy the `html` field value
2. Save to a file: `report.html`
3. Open in browser
4. Verify:
   - Risk score gauge displays correctly
   - Severity badges are color-coded
   - Findings table is expandable
   - Mermaid diagram code is shown

---

### Scenario 9: Slack Blocks Export

**Purpose**: Test Slack Block Kit JSON generation.

**Workflow to Create**:
```
Manual Trigger → RiskVoid (scan vulnerable workflow) → Slack (Post Message)
```

**RiskVoid Settings**:
- Export Format: `Slack Blocks`

**Slack Node Configuration**:
- Blocks: `{{ $json.blocks }}`

**Expected Slack Output**:
```json
{
  "blocks": [
    { "type": "header", "text": { "type": "plain_text", "text": "🛡️ Security Scan: ..." }},
    { "type": "section", "fields": [...] },
    { "type": "divider" },
    { "type": "section", "text": { "type": "mrkdwn", "text": "🔴 *Critical Finding*..." }}
  ]
}
```

**Verification**:
1. Use [Slack Block Kit Builder](https://app.slack.com/block-kit-builder) to validate
2. Or send to actual Slack channel and verify formatting

---

### Scenario 10: SARIF Export (CI/CD Integration)

**Purpose**: Test SARIF 2.1.0 output for CI/CD tools.

**Workflow to Create**: Use any vulnerable workflow.

**RiskVoid Settings**:
- Export Format: `SARIF 2.1.0`

**Expected Output**:
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "RiskVoid",
        "version": "1.0.0",
        "rules": [...]
      }
    },
    "results": [...]
  }]
}
```

**Verification**:
1. Validate against SARIF schema: https://sarifweb.azurewebsites.net/Validation
2. Upload to GitHub Code Scanning (if available)

---

### Scenario 11: Mermaid Diagram Generation

**Purpose**: Test workflow visualization with taint paths.

**Workflow to Create**:
```
Webhook → Set Fields → IF → Code (vulnerable path)
                         → HTTP Request (another path)
```

**RiskVoid Settings**:
- Export Format: `JSON (Default)`
- Include Mermaid Diagram: `Yes`

**Expected Mermaid Output**:
```mermaid
graph LR
    subgraph Workflow
        Webhook[/"🟡 Webhook"/]
        Set_Fields["Set Fields"]
        IF["IF"]
        Code[/"🔴 Code"/]
        HTTP_Request["HTTP Request"]
    end
    Webhook -->|"body.cmd"| Set_Fields
    Set_Fields -->|"tainted"| IF
    IF -->|"tainted"| Code

    style Webhook fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style Code fill:#f8d7da,stroke:#dc3545,stroke-width:2px
```

**Verification**:
1. Copy the `mermaid` field value
2. Paste into [Mermaid Live Editor](https://mermaid.live)
3. Verify:
   - Source nodes (yellow) are correctly identified
   - Sink nodes (red) are correctly identified
   - Tainted paths are shown with labels
   - Styling is applied

---

### Scenario 12: Safe Workflow - No Findings

**Purpose**: Verify no false positives on safe patterns.

**Workflow to Create**:
```
Manual Trigger → Set (hardcoded value) → HTTP Request (hardcoded URL)
```

**Set Node Configuration**:
```
Values:
  - message: "Hello World"
```

**HTTP Request Configuration**:
- URL: `https://api.example.com/data` (hardcoded)

**Expected Output**:
```json
{
  "riskScore": 0,
  "riskLevel": "none",
  "findings": []
}
```

---

### Scenario 13: Workflow with Input Validation (Reduced Severity)

**Purpose**: Test that sanitizers (IF nodes) reduce finding severity.

**Workflow to Create**:
```
Webhook → IF (validate input) → Code
```

**IF Node Configuration**:
```
Conditions:
  - {{ $json.input }} matches regex ^[a-zA-Z0-9]+$
```

**Code Node Configuration**:
```javascript
const safe = {{ $json.input }};
return items;
```

**Expected Output**:
- Finding should exist but with **reduced severity** or **lower confidence**
- Path should show the IF node as a sanitizer

---

### Scenario 14: Scan by Workflow ID

**Purpose**: Test scanning a different workflow by ID.

**Workflow to Create**:
1. Create a vulnerable workflow (e.g., Scenario 2)
2. Note its workflow ID from the URL
3. Create a separate scanning workflow

**Scanning Workflow**:
```
Manual Trigger → RiskVoid (Scan by ID)
```

**RiskVoid Settings**:
- Operation: `Scan Workflow by ID`
- Workflow ID: `<paste the ID from step 2>`

**Expected**: Same findings as scanning the workflow directly.

---

### Scenario 15: Scan Workflow JSON (Base64)

**Purpose**: Test scanning from exported workflow JSON.

**Steps**:
1. Export any workflow as JSON from n8n
2. In browser console, run: `btoa(JSON.stringify(workflowJson))`
3. Copy the base64 string

**Workflow to Create**:
```
Manual Trigger → RiskVoid (Scan JSON)
```

**RiskVoid Settings**:
- Operation: `Scan Workflow JSON (Base64)`
- Workflow JSON (Base64): `<paste base64 string>`

**Expected**: Findings based on the scanned workflow.

---

### Scenario 16: Complex Multi-Vulnerability Workflow

**Purpose**: Test detection of multiple vulnerability types in one workflow.

**Workflow to Create**:
```
Webhook → Set Variables → Execute Command (cmd injection)
                       → MySQL (sql injection)
                       → HTTP Request (ssrf)
```

**Set Variables Configuration**:
```
Values:
  - command: {{ $json.cmd }}
  - query: {{ $json.search }}
  - url: {{ $json.endpoint }}
```

**Expected Output**:
- 3+ findings with different rule IDs
- High risk score (60+)
- Multiple categories (injection, ssrf)

---

### Scenario 17: Output Format Options

**Purpose**: Test different JSON output detail levels.

**Test with same workflow, changing Output Format**:

1. **Full Report**: Complete details with node assessments
2. **Summary**: Just risk score and summary counts
3. **Findings Only**: Just the findings array

---

### Scenario 18: Category Filtering

**Purpose**: Test filtering findings by category.

**Workflow**: Use complex multi-vulnerability workflow (Scenario 16)

**RiskVoid Settings**:
- Categories: Select only `SSRF`

**Expected**: Only SSRF findings, other vulnerabilities filtered out.

---

### Scenario 19: Severity Filtering

**Purpose**: Test filtering findings by minimum severity.

**Workflow**: Use complex multi-vulnerability workflow

**RiskVoid Settings**:
- Minimum Severity: `Critical Only`

**Expected**: Only critical findings (RCE, Command Injection).

---

## End-to-End Integration Workflows

### E2E 1: Slack Alert Pipeline

```
Schedule Trigger (daily) → RiskVoid (scan all workflows) → IF (has findings) → Slack Alert
```

### E2E 2: Email Report Pipeline

```
Manual Trigger → RiskVoid (HTML export) → Convert to File → Send Email (attachment)
```

### E2E 3: GitHub Integration Pipeline

```
Manual Trigger → RiskVoid (SARIF export) → HTTP Request (GitHub API upload)
```

---

## Verification Checklist

| Test | Expected | Actual | Pass? |
|------|----------|--------|-------|
| JSON output structure valid | ✓ | | |
| Risk score 0-100 | ✓ | | |
| Code injection detected | ✓ | | |
| Command injection detected | ✓ | | |
| SQL injection detected | ✓ | | |
| SSRF detected | ✓ | | |
| Prompt injection detected | ✓ | | |
| Credential exposure detected | ✓ | | |
| HTML report renders correctly | ✓ | | |
| Slack blocks validate | ✓ | | |
| SARIF schema valid | ✓ | | |
| Mermaid diagram renders | ✓ | | |
| No false positives on safe workflows | ✓ | | |
| Sanitizers reduce severity | ✓ | | |
| Scan by ID works | ✓ | | |
| Scan JSON (Base64) works | ✓ | | |
| Category filtering works | ✓ | | |
| Severity filtering works | ✓ | | |

---

## Sample Vulnerable Workflows (Copy-Paste JSON)

### Vulnerable Code Injection Workflow

```json
{
  "name": "Vulnerable Code Injection",
  "nodes": [
    {
      "parameters": { "httpMethod": "POST", "path": "execute" },
      "name": "Webhook",
      "type": "n8n-nodes-base.webhook",
      "typeVersion": 1,
      "position": [250, 300]
    },
    {
      "parameters": { "jsCode": "const userInput = {{ $json.body.code }};\neval(userInput);\nreturn items;" },
      "name": "Code",
      "type": "n8n-nodes-base.code",
      "typeVersion": 1,
      "position": [450, 300]
    }
  ],
  "connections": {
    "Webhook": { "main": [[{ "node": "Code", "type": "main", "index": 0 }]] }
  }
}
```

### Vulnerable SSRF Workflow

```json
{
  "name": "Vulnerable SSRF",
  "nodes": [
    {
      "parameters": { "httpMethod": "POST", "path": "fetch" },
      "name": "Webhook",
      "type": "n8n-nodes-base.webhook",
      "typeVersion": 1,
      "position": [250, 300]
    },
    {
      "parameters": { "url": "={{ $json.body.targetUrl }}", "method": "GET" },
      "name": "HTTP Request",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [450, 300]
    }
  ],
  "connections": {
    "Webhook": { "main": [[{ "node": "HTTP Request", "type": "main", "index": 0 }]] }
  }
}
```

### Safe Workflow (No Vulnerabilities)

```json
{
  "name": "Safe Workflow",
  "nodes": [
    {
      "parameters": {},
      "name": "Manual Trigger",
      "type": "n8n-nodes-base.manualTrigger",
      "typeVersion": 1,
      "position": [250, 300]
    },
    {
      "parameters": { "url": "https://api.example.com/data", "method": "GET" },
      "name": "HTTP Request",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [450, 300]
    }
  ],
  "connections": {
    "Manual Trigger": { "main": [[{ "node": "HTTP Request", "type": "main", "index": 0 }]] }
  }
}
```

---

## Troubleshooting

### "Cannot determine workflow ID"
- Make sure the workflow is saved before scanning with "Scan Current Workflow"

### "n8n API key is required"
- Create an n8n API credential and select it in the RiskVoid node

### No findings detected
- Check that expressions use `{{ }}` syntax
- Verify the workflow has untrusted sources (Webhook, Telegram, etc.)
- Ensure dangerous sinks (Code, Execute Command, etc.) are connected

### HTML report doesn't render
- Check if the `html` field contains valid HTML starting with `<!DOCTYPE html>`
- Try a different browser

### SARIF validation fails
- Ensure the output matches SARIF 2.1.0 schema
- Check that all required fields are present
