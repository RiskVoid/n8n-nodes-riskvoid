# Multi-Source Coverage Workflows

This directory contains workflows that test various source node types to ensure complete source coverage in RiskVoid's taint analysis engine.

## Purpose

These workflows demonstrate that **different source types all lead to the same vulnerability classes**. This validates that RiskVoid can detect vulnerabilities regardless of the input source.

## Workflow Coverage

| File | Source Node | Vulnerability | Severity | Taint Path |
|------|-------------|---------------|----------|------------|
| `source-rss-feed.json` | rssFeedRead | RCE via eval() | Critical | RSS description → Set → Code (eval) |
| `source-gmail.json` | gmail | Command Injection | Critical | Email subject → Set → executeCommand |
| `source-email-trigger.json` | emailReadImap | SQL Injection | High | Email text → Set → MySQL (raw query) |
| `source-hubspot.json` | hubspotTrigger | SSRF | High | HubSpot propertyValue → Set → httpRequest URL |
| `source-stripe.json` | stripeTrigger | RCE via exec() | Critical | Stripe metadata → Set → Code (execSync) |
| `source-github.json` | githubTrigger | SQL Injection | High | GitHub commit message → Set → Postgres (raw query) |
| `source-http-response.json` | httpRequest (as source) | RCE via eval() | Critical | API response → Set → Code (eval) |

## Vulnerability Patterns

### 1. RSS Feed RCE (source-rss-feed.json)
**Flow**: RSS Feed → Extract RSS Data → Process Feed Content (eval)

**Taint Source**: `{{ $json.description }}` from RSS feed
**Sink**: `eval(script)` in Code node
**Attack Vector**: Malicious RSS feed with JavaScript in description field

### 2. Gmail Command Injection (source-gmail.json)
**Flow**: Gmail → Extract Email Data → Log Email Processing (executeCommand)

**Taint Source**: `{{ $json.payload.headers.find(h => h.name === 'Subject').value }}`
**Sink**: `command` parameter with embedded email subject
**Attack Vector**: Email with subject like `"; rm -rf /; echo "`

### 3. Email Trigger SQL Injection (source-email-trigger.json)
**Flow**: Email Trigger → Parse Email Content → Log Email to Database (MySQL)

**Taint Source**: `{{ $json.subject }}`, `{{ $json.text }}`
**Sink**: Raw SQL query with email fields
**Attack Vector**: Email with subject like `'); DROP TABLE users; --`

### 4. HubSpot SSRF (source-hubspot.json)
**Flow**: HubSpot Trigger → Extract HubSpot Data → Notify Webhook URL (httpRequest)

**Taint Source**: `{{ $json.propertyValue }}` from HubSpot webhook
**Sink**: `url` parameter in HTTP Request node
**Attack Vector**: HubSpot contact property set to `http://169.254.169.254/latest/meta-data/`

### 5. Stripe RCE (source-stripe.json)
**Flow**: Stripe Trigger → Extract Stripe Event → Process Stripe Event (execSync)

**Taint Source**: `{{ $json.data.object.metadata.processor }}`
**Sink**: `execSync(processor)` in Code node
**Attack Vector**: Stripe customer metadata with value like `cat /etc/passwd`

### 6. GitHub SQL Injection (source-github.json)
**Flow**: GitHub Trigger → Extract GitHub Event → Log GitHub Event (Postgres)

**Taint Source**: `{{ $json.body.head_commit.message }}`, `{{ $json.body.sender.login }}`
**Sink**: Raw SQL query with commit message and username
**Attack Vector**: Commit message like `'; DELETE FROM github_events; --`

### 7. HTTP Response RCE (source-http-response.json)
**Flow**: Schedule → Fetch External Tasks (HTTP) → Extract Task Data → Execute Task Script (eval)

**Taint Source**: `{{ $json.script }}` from external API response
**Sink**: `eval(script)` in Code node
**Attack Vector**: External API returns malicious script in response

## Testing Strategy

### Source Coverage
These workflows ensure RiskVoid recognizes these source node types:
- ✅ `n8n-nodes-base.rssFeedRead`
- ✅ `n8n-nodes-base.gmail`
- ✅ `n8n-nodes-base.emailReadImap`
- ✅ `n8n-nodes-base.hubspotTrigger`
- ✅ `n8n-nodes-base.stripeTrigger`
- ✅ `n8n-nodes-base.githubTrigger`
- ✅ `n8n-nodes-base.httpRequest` (when used as a source after a trigger)

### Sink Coverage
Each workflow uses a different sink type:
- Code node with `eval()` (RSS, HTTP Response)
- Code node with `execSync()` (Stripe)
- Execute Command node (Gmail)
- MySQL node (Email Trigger)
- Postgres node (GitHub)
- HTTP Request node URL (HubSpot)

## Expected RiskVoid Behavior

For each workflow, RiskVoid should:

1. **Identify the source node** and mark it as a taint source
2. **Trace taint through Set nodes** that extract and transform data
3. **Detect the sink node** and identify the vulnerable parameter
4. **Report the finding** with:
   - Correct severity level (Critical/High)
   - Full taint path from source to sink
   - Specific vulnerability type (RCE, Command Injection, SQL Injection, SSRF)
   - Actionable remediation steps

## Node Positioning

All workflows follow consistent 250px horizontal spacing:
- Source/Trigger: [250, 300]
- Set node: [500, 300]
- Sink node: [750, 300]
- Additional nodes: [1000, 300], [1250, 300], etc.

## Vulnerability IDs

These workflows should generate findings with IDs:
- `vuln-source-001` (RSS Feed RCE)
- `vuln-source-002` (Gmail Command Injection)
- `vuln-source-003` (Email Trigger SQL Injection)
- `vuln-source-004` (HubSpot SSRF)
- `vuln-source-005` (Stripe RCE)
- `vuln-source-006` (GitHub SQL Injection)
- `vuln-source-007` (HTTP Response RCE)

## Key Insights

1. **Source diversity**: Demonstrates that vulnerabilities arise from many different input sources
2. **Universal taint flow**: All sources → Set → Sink pattern remains consistent
3. **Real-world scenarios**: Each workflow represents a realistic use case
4. **Expression extraction**: Uses proper n8n expressions like `{{ $json.field }}`
5. **Multiple sink types**: Shows same source can lead to different vulnerability classes
