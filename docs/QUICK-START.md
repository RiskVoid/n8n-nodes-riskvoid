# RiskVoid Security Scanner - Quick Start

Get started with RiskVoid in under 5 minutes.

## Installation

```bash
npm install @riskvoid/n8n-nodes-riskvoid
```

Then restart n8n.

## Setup in 3 Steps

### Step 1: Create API Credentials

1. Go to n8n **Settings** → **API**
2. Click **Create API Key**
3. Copy the API key

### Step 2: Add Credentials to n8n

1. In your workflow, go to **Credentials**
2. Create new **"n8n API"** credential
3. Enter:
   - **API Key**: Paste your key
   - **Base URL**: Your n8n URL (e.g., `http://localhost:5678`)
4. Save

### Step 3: Add RiskVoid Node

1. Add **RiskVoid Security** node to your workflow
2. Select Operation: **"Scan Current Workflow"**
3. Choose your API credentials
4. Execute the node

## That's it!

You'll get a security report showing:
- **Risk Score** (0-100)
- **Vulnerabilities** found
- **How to fix them**

## Example Output

```json
{
  "riskScore": 85,
  "riskLevel": "critical",
  "findings": [
    {
      "severity": "critical",
      "title": "Remote Code Execution via User Input",
      "path": ["Webhook", "Code"],
      "remediation": {
        "summary": "Validate input before code execution",
        "steps": ["Add IF node to validate", "Use allowlist"]
      }
    }
  ]
}
```

## Common Use Cases

### Scan Current Workflow
```
Manual Trigger → [Your Nodes] → RiskVoid Security
```

### Scan Another Workflow
```
Manual Trigger → RiskVoid Security (Scan by ID: 123)
```

### Security Gate for Deployments
```
Webhook → RiskVoid → IF (critical?) → Block/Deploy
```

## Next Steps

📖 **Full Documentation**: [User Guide](USER-GUIDE.md)
🔧 **Configuration Options**: [User Guide - Configuration](USER-GUIDE.md#configuration-options)
📊 **Output Formats**: [User Guide - Output Formats](USER-GUIDE.md#output-formats)

## Need Help?

- 🐛 [Report Issues](https://github.com/riskvoid/n8n-nodes-riskvoid/issues)
- 💬 [n8n Community](https://community.n8n.io/)
- 📚 [Full Documentation](USER-GUIDE.md)
