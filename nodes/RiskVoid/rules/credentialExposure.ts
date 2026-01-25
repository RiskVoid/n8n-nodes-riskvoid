/**
 * Credential Exposure Detection Rule
 *
 * Detects when credentials or secrets may be exposed through outputs, logs,
 * or hardcoded in node parameters.
 *
 * Rule ID: RV-CRED-001
 * Severity: Medium-High (depending on exposure type)
 * CWE: CWE-200 (Exposure of Sensitive Information)
 */

import type {
	DetectionRule,
	RuleMetadata,
	Finding,
	RuleContext,
	RemediationGuidance,
	FindingConfidence,
} from './types';
import { createFindingId } from './types';

/**
 * Patterns that indicate credential-related field names
 */
const CREDENTIAL_FIELD_PATTERNS = [
	/api[_-]?key/i,
	/apikey/i,
	/secret[_-]?key/i,
	/secretkey/i,
	/password/i,
	/passwd/i,
	/token/i,
	/bearer/i,
	/authorization/i,
	/auth[_-]?token/i,
	/access[_-]?token/i,
	/refresh[_-]?token/i,
	/private[_-]?key/i,
	/privatekey/i,
	/aws[_-]?(access|secret)/i,
	/client[_-]?secret/i,
	/client[_-]?id/i,
	/app[_-]?secret/i,
	/api[_-]?secret/i,
	/signing[_-]?key/i,
	/encryption[_-]?key/i,
];

/**
 * Patterns for detecting hardcoded secrets in values
 */
const HARDCODED_SECRET_PATTERNS = [
	// OpenAI API keys
	{ pattern: /sk-[a-zA-Z0-9]{32,}/, name: 'OpenAI API key' },
	// GitHub tokens
	{ pattern: /ghp_[a-zA-Z0-9]{36}/, name: 'GitHub Personal Access Token' },
	{ pattern: /gho_[a-zA-Z0-9]{36}/, name: 'GitHub OAuth Token' },
	{ pattern: /ghs_[a-zA-Z0-9]{36}/, name: 'GitHub Server Token' },
	{ pattern: /ghr_[a-zA-Z0-9]{36}/, name: 'GitHub Refresh Token' },
	// Slack tokens
	{ pattern: /xox[baprs]-[a-zA-Z0-9-]+/, name: 'Slack Token' },
	// AWS keys
	{ pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key ID' },
	// Google API keys
	{ pattern: /AIza[0-9A-Za-z_-]{35}/, name: 'Google API Key' },
	// Stripe keys
	{ pattern: /sk_live_[a-zA-Z0-9]{24,}/, name: 'Stripe Live Secret Key' },
	{ pattern: /sk_test_[a-zA-Z0-9]{24,}/, name: 'Stripe Test Secret Key' },
	{ pattern: /pk_live_[a-zA-Z0-9]{24,}/, name: 'Stripe Live Public Key' },
	{ pattern: /pk_test_[a-zA-Z0-9]{24,}/, name: 'Stripe Test Public Key' },
	// Twilio
	{ pattern: /SK[a-f0-9]{32}/, name: 'Twilio API Key' },
	// SendGrid
	{ pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, name: 'SendGrid API Key' },
	// Mailgun
	{ pattern: /key-[a-f0-9]{32}/, name: 'Mailgun API Key' },
	// Generic long strings that look like secrets
	{ pattern: /["'][a-zA-Z0-9+/=]{40,}["']/, name: 'potential Base64 encoded secret' },
	// JWT tokens
	{ pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/, name: 'JWT Token' },
];

/**
 * External output nodes that could leak credentials
 */
const EXTERNAL_OUTPUT_NODES = [
	'n8n-nodes-base.httpRequest',
	'n8n-nodes-base.slack',
	'n8n-nodes-base.discord',
	'n8n-nodes-base.telegram',
	'n8n-nodes-base.emailSend',
	'n8n-nodes-base.gmail',
	'n8n-nodes-base.microsoftOutlook',
	'n8n-nodes-base.sendGrid',
	'n8n-nodes-base.mailchimp',
	'n8n-nodes-base.webhook', // When responding
	'n8n-nodes-base.respondToWebhook',
	'n8n-nodes-base.airtable',
	'n8n-nodes-base.googleSheets',
	'n8n-nodes-base.notion',
];

/**
 * Credential Exposure Detection Rule
 */
export class CredentialExposureRule implements DetectionRule {
	metadata: RuleMetadata = {
		id: 'RV-CRED-001',
		name: 'Potential Credential Exposure',
		description:
			'Detects when credentials or secrets may be exposed through outputs, logs, or hardcoded in parameters',
		category: 'credential-exposure',
		severity: 'medium',
		tags: ['credentials', 'secrets', 'api-keys', 'information-disclosure', 'hardcoded'],
		references: {
			cwe: 'CWE-200',
			owasp: 'A01:2021-Broken-Access-Control',
		},
	};

	/**
	 * Check if this rule is applicable to the workflow
	 */
	isApplicable(context: RuleContext): boolean {
		// Check if any nodes have credentials or sensitive-looking parameters
		for (const [, node] of context.workflow.nodes) {
			// Has credentials configured
			if (node.credentials && Object.keys(node.credentials).length > 0) {
				return true;
			}

			// Has parameters that look credential-related
			if (this.hasCredentialPattern(JSON.stringify(node.parameters))) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Run detection and return findings
	 */
	detect(context: RuleContext): Finding[] {
		const findings: Finding[] = [];

		// Check for hardcoded secrets in all nodes
		for (const [nodeName, node] of context.workflow.nodes) {
			const hardcodedFindings = this.checkHardcodedSecrets(nodeName, node.type, node.parameters);
			findings.push(...hardcodedFindings);
		}

		// Check for credential references in external outputs
		for (const [nodeName, node] of context.workflow.nodes) {
			if (EXTERNAL_OUTPUT_NODES.includes(node.type)) {
				const exposureFindings = this.checkCredentialExposure(
					nodeName,
					node.type,
					node.parameters,
				);
				findings.push(...exposureFindings);
			}
		}

		return findings;
	}

	/**
	 * Check if text contains credential-related patterns
	 */
	private hasCredentialPattern(text: string): boolean {
		return CREDENTIAL_FIELD_PATTERNS.some((pattern) => pattern.test(text));
	}

	/**
	 * Check for hardcoded secrets in node parameters
	 */
	private checkHardcodedSecrets(
		nodeName: string,
		nodeType: string,
		params: Record<string, unknown>,
	): Finding[] {
		const findings: Finding[] = [];
		const paramStr = JSON.stringify(params);

		for (const { pattern, name } of HARDCODED_SECRET_PATTERNS) {
			const match = paramStr.match(pattern);
			if (match) {
				findings.push({
					id: createFindingId(`${this.metadata.id}-hardcoded`),
					ruleId: this.metadata.id,
					severity: 'high',
					confidence: 'high' as FindingConfidence,
					title: 'Hardcoded Secret Detected',
					description:
						`Node "${nodeName}" contains what appears to be a hardcoded ${name} in its parameters. ` +
						`Hardcoded secrets can be exposed in workflow exports, version control, logs, or error messages.`,
					category: 'credential-exposure',
					source: {
						node: nodeName,
						nodeType: nodeType,
						field: 'parameters',
					},
					sink: {
						node: nodeName,
						nodeType: nodeType,
						parameter: 'parameters',
					},
					path: [nodeName],
					remediation: this.getHardcodedRemediation(name),
					references: this.metadata.references,
					metadata: {
						type: 'hardcoded-secret',
						secretType: name,
						// Don't include the actual secret value
					},
				});

				// Only report one finding per node to avoid noise
				break;
			}
		}

		return findings;
	}

	/**
	 * Check for credential exposure in external outputs
	 */
	private checkCredentialExposure(
		nodeName: string,
		nodeType: string,
		params: Record<string, unknown>,
	): Finding[] {
		const findings: Finding[] = [];
		const paramStr = JSON.stringify(params);

		// Check if parameters reference credential-like fields
		const hasCredentialRef = this.hasCredentialPattern(paramStr);

		// Check if there are n8n expressions that might include credentials
		const hasCredentialExpression =
			/\{\{\s*\$[^}]*?(password|secret|token|key|auth|credential)/i.test(paramStr);

		if (hasCredentialRef || hasCredentialExpression) {
			findings.push({
				id: createFindingId(`${this.metadata.id}-exposure`),
				ruleId: this.metadata.id,
				severity: 'medium',
				confidence: 'medium' as FindingConfidence,
				title: 'Potential Credential Exposure in External Output',
				description:
					`Node "${nodeName}" sends data externally and may include credential-related fields. ` +
					`Verify that sensitive data like API keys, passwords, or tokens are not included in the output.`,
				category: 'credential-exposure',
				source: {
					node: nodeName,
					nodeType: nodeType,
					field: 'credentials',
				},
				sink: {
					node: nodeName,
					nodeType: nodeType,
					parameter: 'output',
				},
				path: [nodeName],
				remediation: this.getExposureRemediation(nodeName, nodeType),
				references: this.metadata.references,
				metadata: {
					type: 'potential-exposure',
					hasCredentialRef,
					hasCredentialExpression,
				},
			});
		}

		return findings;
	}

	/**
	 * Get remediation for hardcoded secrets
	 */
	private getHardcodedRemediation(secretType: string): RemediationGuidance {
		return {
			summary: `Use n8n credentials instead of hardcoding the ${secretType} in node parameters.`,
			steps: [
				`Create a new credential in n8n for this ${secretType}`,
				'Update the node to use the credential instead of the hardcoded value',
				'Remove the hardcoded secret from the node parameters',
				'IMPORTANT: Rotate the exposed secret immediately as it may have been compromised',
				'Check version control history and logs for the exposed secret',
				'Consider using environment variables for additional security',
			],
			safePattern: `
// UNSAFE - Hardcoded API key:
{
  "headers": {
    "Authorization": "Bearer sk-abc123..."
  }
}

// SAFE - Use n8n credentials:
1. Go to Credentials in n8n
2. Create new credential of appropriate type
3. In the node, select the credential from dropdown
4. n8n will securely inject the credential at runtime

// The credential is stored encrypted and never exposed in:
// - Workflow JSON exports
// - Execution logs
// - Error messages
`,
			exampleCode: 'Use n8n\'s built-in credential management instead of hardcoded values',
		};
	}

	/**
	 * Get remediation for credential exposure
	 */
	private getExposureRemediation(nodeName: string, nodeType: string): RemediationGuidance {
		const nodeDescription = nodeType.split('.').pop() || 'external service';

		return {
			summary: `Ensure credentials and sensitive data are not included in the output sent to ${nodeDescription}.`,
			steps: [
				`Review the data being sent from "${nodeName}" to external services`,
				'Use a Set node before this node to explicitly select only needed fields',
				'Remove any authorization headers, tokens, or credentials from the output',
				'Add a Code node to filter out sensitive fields if needed',
				'Consider what data is actually needed vs. what is being sent',
				'Use n8n\'s built-in credential system - credentials are never included in item data',
			],
			safePattern: `
// UNSAFE - Sending all data including credentials:
// HTTP Request node with body: {{ $json }}

// SAFE - Explicitly select only needed fields:
// Add a Set node before the output node:
{
  "name": "{{ $json.name }}",
  "email": "{{ $json.email }}",
  "message": "{{ $json.message }}"
  // Don't include: apiKey, password, token, etc.
}

// Or use a Code node to filter:
const safeData = { ...items[0].json };
delete safeData.password;
delete safeData.apiKey;
delete safeData.token;
return [{ json: safeData }];
`,
			exampleCode:
				'Use a Set node to explicitly select safe fields before sending data externally',
		};
	}
}
