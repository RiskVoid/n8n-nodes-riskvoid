# RiskVoid Security Scanner - Troubleshooting Guide

Common issues and solutions when using RiskVoid.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Credentials & API Issues](#credentials--api-issues)
- [Workflow Scanning Issues](#workflow-scanning-issues)
- [Output & Results Issues](#output--results-issues)
- [Performance Issues](#performance-issues)
- [Error Messages](#error-messages)

---

## Installation Issues

### Node doesn't appear after installation

**Symptoms**: Installed the package but can't find RiskVoid Security node in n8n.

**Solutions**:

1. **Restart n8n**:
   ```bash
   # If using pm2
   pm2 restart n8n

   # If using docker
   docker restart n8n-container

   # If running directly
   # Stop and start n8n
   ```

2. **Verify installation**:
   ```bash
   npm list @riskvoid/n8n-nodes-riskvoid
   ```

3. **Check n8n logs**:
   ```bash
   # Look for errors during node loading
   tail -f ~/.n8n/logs/n8n.log
   ```

4. **Clear n8n cache** (if using self-hosted):
   ```bash
   rm -rf ~/.n8n/cache
   n8n start
   ```

### npm install fails

**Symptoms**: `npm install @riskvoid/n8n-nodes-riskvoid` returns errors.

**Solutions**:

1. **Check Node.js version**:
   ```bash
   node --version  # Should be 18.x or higher
   ```

2. **Update npm**:
   ```bash
   npm install -g npm@latest
   ```

3. **Clear npm cache**:
   ```bash
   npm cache clean --force
   npm install @riskvoid/n8n-nodes-riskvoid
   ```

4. **Check network/proxy**:
   ```bash
   npm config set registry https://registry.npmjs.org/
   ```

---

## Credentials & API Issues

### "n8n API key is required"

**Cause**: API credentials not configured or not selected.

**Solutions**:

1. **Create API key**:
   - Go to n8n **Settings** → **API**
   - Click **Create API Key**
   - Copy the key

2. **Create credential in n8n**:
   - Go to **Credentials** menu
   - Add new **"n8n API"** credential
   - Paste API key
   - Enter Base URL (e.g., `http://localhost:5678`)

3. **Select credential in RiskVoid node**:
   - Click on credential field
   - Select your n8n API credential

### "Error: 401 Unauthorized"

**Cause**: Invalid or expired API key.

**Solutions**:

1. **Regenerate API key**:
   - Go to Settings → API
   - Delete old key
   - Create new key
   - Update credential

2. **Check API key format**:
   - Should start with `n8n_api_`
   - No extra spaces or quotes
   - Copy directly from n8n

### "Error: Could not connect to n8n API"

**Cause**: Wrong Base URL or n8n not accessible.

**Solutions**:

1. **Verify Base URL**:
   - Local: `http://localhost:5678`
   - Docker: `http://n8n:5678` or container IP
   - Remote: Full URL with protocol (https://n8n.yourcompany.com)

2. **Test API manually**:
   ```bash
   curl -H "X-N8N-API-KEY: your_key" \
     http://localhost:5678/api/v1/workflows
   ```

3. **Check firewall/network**:
   - Ensure n8n API port is accessible
   - Check Docker network if using containers
   - Verify no proxy blocking requests

4. **Enable n8n API** (if disabled):
   - Set environment variable: `N8N_API_ENABLED=true`
   - Restart n8n

---

## Workflow Scanning Issues

### "Cannot determine workflow ID. This workflow may not be saved yet."

**Cause**: Workflow hasn't been saved to database.

**Solution**:
- **Save workflow first**: Press Ctrl/Cmd + S
- Give it a name
- Then execute RiskVoid node

### "Error: Workflow not found"

**Cause**: Wrong workflow ID or workflow doesn't exist.

**Solutions**:

1. **Verify workflow ID**:
   - Check URL: `https://n8n.com/workflow/{ID}`
   - ID should be numeric (e.g., 123, 456)

2. **Check workflow exists**:
   ```bash
   curl -H "X-N8N-API-KEY: key" \
     http://localhost:5678/api/v1/workflows/123
   ```

3. **Check permissions**:
   - API key needs read access to workflows
   - In multi-user setups, ensure user has access

### "Invalid Base64" (when scanning JSON)

**Cause**: Workflow JSON not properly base64-encoded.

**Solutions**:

1. **Use browser console** (recommended):
   ```javascript
   const workflow = { /* paste your workflow JSON */ };
   const base64 = btoa(JSON.stringify(workflow));
   console.log(base64);
   // Copy this output
   ```

2. **Use command line**:
   ```bash
   cat workflow.json | base64
   # On Mac: base64 -i workflow.json
   ```

3. **Use Node.js**:
   ```javascript
   const fs = require('fs');
   const json = fs.readFileSync('workflow.json', 'utf8');
   const base64 = Buffer.from(json).toString('base64');
   console.log(base64);
   ```

4. **Verify base64 format**:
   - Should be a single line
   - No spaces or newlines
   - Contains only: A-Z, a-z, 0-9, +, /, =

### "Analysis failed: Could not parse workflow"

**Cause**: Invalid workflow JSON structure.

**Solutions**:

1. **Validate JSON**:
   ```bash
   cat workflow.json | jq .
   ```

2. **Check required fields**:
   - Must have `nodes` array
   - Must have `connections` object
   - Must be exported from n8n

3. **Export correctly from n8n**:
   - Click **...** menu → **Download**
   - This ensures proper format

4. **Test with minimal workflow**:
   - Create simple 2-node workflow
   - Export and try scanning
   - If works, issue is with original workflow JSON

---

## Output & Results Issues

### No findings but workflow has vulnerabilities

**Possible causes**:

1. **Severity filter too high**:
   - Solution: Set "Minimum Severity" to "All"
   - Check if issues are low/info severity

2. **Category filters active**:
   - Solution: Remove category filters
   - Scan for all vulnerability types

3. **No taint flow detected**:
   - RiskVoid tracks data from sources to sinks
   - If vulnerable code isn't reachable from untrusted input, no finding
   - Example: Hardcoded eval() without user input → No finding

4. **Sanitizers detected**:
   - IF/Switch nodes may be reducing taint
   - Check "includeSanitized" option

**Debug steps**:

1. Enable all categories
2. Set severity to "All"
3. Check node classifications in output:
   ```json
   {
     "nodeAssessments": {
       "Webhook": { "isSource": true },
       "Code": { "isSink": true }
     }
   }
   ```

### Too many false positives

**Symptoms**: Getting findings that aren't real vulnerabilities.

**Solutions**:

1. **Increase severity threshold**:
   - Set to "High and Above"
   - Focus on critical issues first

2. **Review remediation**:
   - Each finding explains why it's flagged
   - Verify if the data flow actually reaches vulnerable code

3. **Add validation nodes**:
   - IF nodes with validation reduce taint
   - RiskVoid recognizes these as sanitizers

4. **Report false positives**:
   - [Create GitHub issue](https://github.com/RiskVoid/n8n-nodes-riskvoid/issues)
   - Include workflow JSON (sanitize secrets first!)
   - Helps improve detection rules

### Output format issues

**HTML report not rendering**:

- Save `{{ $json.html }}` to a file
- Open in browser
- Ensure it's complete HTML (starts with `<!DOCTYPE html>`)

**Slack blocks not showing**:

- Use correct format in Slack node:
  - Blocks field: `{{ JSON.stringify($json.slackMessage) }}`
  - NOT: `{{ $json.slackMessage }}`
- Test in Slack Block Kit Builder first

**SARIF not uploading to GitHub**:

- Verify SARIF 2.1.0 format
- Check file size (max 10MB)
- Validate with: https://sarifweb.azurewebsites.net/Validation

---

## Performance Issues

### Scanning takes too long

**Normal performance**:
- Small workflows (<10 nodes): <1 second
- Medium workflows (10-20 nodes): 1-3 seconds
- Large workflows (20+ nodes): 3-10 seconds

**If slower**:

1. **Check workflow size**:
   - Workflows with 50+ nodes may take longer
   - Complex taint analysis is compute-intensive

2. **Check system resources**:
   - n8n container memory limits
   - CPU availability
   - Other running workflows

3. **Optimize options**:
   - Disable Mermaid diagram if not needed
   - Use "Findings Only" output format
   - Skip HTML export for faster results

### Out of memory errors

**Solutions**:

1. **Increase Node.js memory**:
   ```bash
   NODE_OPTIONS="--max-old-space-size=4096" n8n start
   ```

2. **Docker memory limits**:
   ```yaml
   services:
     n8n:
       deploy:
         resources:
           limits:
             memory: 2G
   ```

3. **Scan smaller workflows**:
   - Break large workflows into smaller ones
   - Scan critical paths separately

---

## Error Messages

### "Error: ECONNREFUSED"

**Cause**: Can't connect to n8n instance.

**Solutions**:
- Check Base URL is correct
- Verify n8n is running
- Test with: `curl http://localhost:5678`

### "Error: Request timeout"

**Cause**: API request taking too long.

**Solutions**:
- Check n8n is responding
- Try scanning smaller workflow
- Increase timeout if possible

### "Error: Invalid credentials"

**Cause**: Credential object malformed.

**Solutions**:
- Delete and recreate credential
- Ensure all required fields filled
- Check credential type is "n8n API"

### "TypeError: Cannot read property 'nodes' of undefined"

**Cause**: Workflow JSON missing required fields.

**Solutions**:
- Re-export workflow from n8n
- Verify JSON structure
- Check base64 decoding worked

### "RuleEngine error: Rule XYZ failed"

**Cause**: Internal rule error (rare).

**Solutions**:
- Note the rule ID
- [Report as bug](https://github.com/RiskVoid/n8n-nodes-riskvoid/issues)
- Include workflow JSON (sanitized)
- Workaround: Disable that category temporarily

---

## Debugging Tips

### Enable verbose logging

In n8n, set:
```bash
N8N_LOG_LEVEL=debug
```

### Test API access manually

```bash
# List workflows
curl -H "X-N8N-API-KEY: your_key" \
  http://localhost:5678/api/v1/workflows

# Get specific workflow
curl -H "X-N8N-API-KEY: your_key" \
  http://localhost:5678/api/v1/workflows/123
```

### Validate workflow JSON

```javascript
// In browser console
const workflow = /* paste JSON */;
console.log('Has nodes:', !!workflow.nodes);
console.log('Has connections:', !!workflow.connections);
console.log('Node count:', workflow.nodes?.length);
```

### Check RiskVoid version

```bash
npm list @riskvoid/n8n-nodes-riskvoid
```

### Test with minimal workflow

Create this simple workflow to test:
```
Manual Trigger → Code (with console.log) → RiskVoid
```

If this works, issue is with your specific workflow.

---

## Still Need Help?

### Before reporting an issue:

1. ✅ Check this troubleshooting guide
2. ✅ Search [existing issues](https://github.com/RiskVoid/n8n-nodes-riskvoid/issues)
3. ✅ Test with latest version
4. ✅ Collect error messages and logs

### Report a bug:

Include:
- RiskVoid version
- n8n version
- Node.js version
- Operating system
- Error messages
- Steps to reproduce
- Workflow JSON (sanitized!)

📝 [Create issue on GitHub](https://github.com/RiskVoid/n8n-nodes-riskvoid/issues/new)

### Get help:

- 💬 [n8n Community Forum](https://community.n8n.io/)
- 📧 [Email support](mailto:hello@riskvoid.com)
- 📚 [User Guide](USER-GUIDE.md)
