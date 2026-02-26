/**
 * Server-Side Request Forgery (SSRF) Detection Rule
 *
 * Detects when untrusted user input controls HTTP request URLs,
 * which could allow attackers to access internal services or cloud metadata.
 *
 * Rule ID: RV-SSRF-001
 * Severity: High
 * CWE: CWE-918 (Server-Side Request Forgery)
 */

import type {
	DetectionRule,
	RuleMetadata,
	Finding,
	RuleContext,
	RemediationGuidance,
	FindingConfidence,
} from './types';
import { createFindingId, getEffectiveSeverity } from './types';
import type { TaintPath } from '../types/taint';

/**
 * Internal IP/hostname patterns that attackers commonly target
 */
const INTERNAL_PATTERNS = [
	{ pattern: /127\.\d+\.\d+\.\d+/, name: 'localhost (127.x.x.x)' },
	{ pattern: /10\.\d+\.\d+\.\d+/, name: 'private Class A (10.x.x.x)' },
	{ pattern: /172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/, name: 'private Class B (172.16-31.x.x)' },
	{ pattern: /192\.168\.\d+\.\d+/, name: 'private Class C (192.168.x.x)' },
	{ pattern: /localhost/i, name: 'localhost' },
	{ pattern: /0\.0\.0\.0/, name: 'all interfaces (0.0.0.0)' },
	{ pattern: /\[?::1\]?/, name: 'IPv6 localhost (::1)' },
	{ pattern: /\[?::\]?/, name: 'IPv6 all (::)' },
	{ pattern: /169\.254\.\d+\.\d+/, name: 'link-local (169.254.x.x)' },
];

/**
 * Cloud metadata endpoints that are high-value targets
 */
const METADATA_PATTERNS = [
	{ pattern: /169\.254\.169\.254/, name: 'AWS/GCP metadata endpoint' },
	{ pattern: /metadata\.google/, name: 'Google Cloud metadata' },
	{ pattern: /metadata\.azure/, name: 'Azure metadata' },
	{ pattern: /100\.100\.100\.200/, name: 'Alibaba Cloud metadata' },
	{ pattern: /fd00:ec2::254/, name: 'AWS IMDSv2 IPv6' },
];

/**
 * URL scheme patterns that might bypass filters
 */
const BYPASS_PATTERNS = [
	{ pattern: /file:\/\//i, name: 'file:// protocol' },
	{ pattern: /gopher:\/\//i, name: 'gopher:// protocol' },
	{ pattern: /dict:\/\//i, name: 'dict:// protocol' },
	{ pattern: /ftp:\/\//i, name: 'ftp:// protocol' },
	{ pattern: /%00/, name: 'null byte injection' },
	{ pattern: /@/, name: 'URL credential injection' },
];

/**
 * SSRF Detection Rule
 */
export class SsrfRule implements DetectionRule {
	metadata: RuleMetadata = {
		id: 'RV-SSRF-001',
		name: 'Server-Side Request Forgery',
		description:
			'Detects when untrusted user input controls HTTP request URLs, allowing attackers to access internal services or cloud metadata',
		category: 'ssrf',
		severity: 'high',
		tags: ['ssrf', 'http-request', 'url-manipulation', 'internal-access'],
		references: {
			cwe: 'CWE-918',
			owasp: 'A10:2021-SSRF',
			capec: 'CAPEC-664',
		},
	};

	/**
	 * Check if this rule is applicable to the workflow
	 */
	isApplicable(context: RuleContext): boolean {
		return context.sinks.some((sink) => sink.riskType === 'SSRF');
	}

	/**
	 * Run detection and return findings
	 */
	detect(context: RuleContext): Finding[] {
		const findings: Finding[] = [];

		// Get taint paths that flow to HTTP Request nodes, excluding fully sanitized paths
		const ssrfPaths = context.taintPaths.filter(
			(path) => path.sink.riskType === 'SSRF' && !path.sanitized,
		);

		for (const taintPath of ssrfPaths) {
			// Get the sink node to analyze URL content
			const sinkNode = context.workflow.nodes.get(taintPath.sink.nodeName);
			if (!sinkNode) continue;

			// Get URL parameter
			const url = (sinkNode.parameters.url as string) || '';

			// Check for internal network patterns
			const internalPatterns = this.findInternalPatterns(url);

			// Check for cloud metadata patterns
			const metadataPatterns = this.findMetadataPatterns(url);

			// Check for bypass patterns
			const bypassPatterns = this.findBypassPatterns(url);

			// Determine confidence level
			const confidence = this.determineConfidence(
				taintPath,
				internalPatterns,
				metadataPatterns,
				bypassPatterns,
			);

			// Create finding
			findings.push(
				this.createFinding(
					taintPath,
					internalPatterns,
					metadataPatterns,
					bypassPatterns,
					confidence,
				),
			);
		}

		return findings;
	}

	/**
	 * Find internal network patterns in URL
	 */
	private findInternalPatterns(url: string): string[] {
		const found: string[] = [];

		for (const { pattern, name } of INTERNAL_PATTERNS) {
			if (pattern.test(url)) {
				found.push(name);
			}
		}

		return found;
	}

	/**
	 * Find cloud metadata patterns in URL
	 */
	private findMetadataPatterns(url: string): string[] {
		const found: string[] = [];

		for (const { pattern, name } of METADATA_PATTERNS) {
			if (pattern.test(url)) {
				found.push(name);
			}
		}

		return found;
	}

	/**
	 * Find URL bypass patterns
	 */
	private findBypassPatterns(url: string): string[] {
		const found: string[] = [];

		for (const { pattern, name } of BYPASS_PATTERNS) {
			if (pattern.test(url)) {
				found.push(name);
			}
		}

		return found;
	}

	/**
	 * Determine confidence level based on analysis
	 */
	private determineConfidence(
		taintPath: TaintPath,
		internalPatterns: string[],
		metadataPatterns: string[],
		bypassPatterns: string[],
	): FindingConfidence {
		// High confidence if:
		// - Direct taint flow with metadata patterns (critical target)
		// - Or internal patterns detected with no sanitizers
		if (
			metadataPatterns.length > 0 ||
			(internalPatterns.length > 0 && !taintPath.sanitized) ||
			bypassPatterns.length > 0
		) {
			return 'high';
		}

		// Medium confidence if taint flows to URL parameter
		if (!taintPath.sanitized) {
			return 'medium';
		}

		// Low confidence if sanitizers are present
		return 'low';
	}

	/**
	 * Create a finding from a taint path
	 */
	private createFinding(
		taintPath: TaintPath,
		internalPatterns: string[],
		metadataPatterns: string[],
		bypassPatterns: string[],
		confidence: FindingConfidence,
	): Finding {
		const allPatterns = [...metadataPatterns, ...internalPatterns, ...bypassPatterns];
		const patternList =
			allPatterns.length > 0
				? ` Potential targets detected: ${allPatterns.join(', ')}.`
				: '';

		const severity = getEffectiveSeverity(this.metadata.severity, taintPath.sanitized);

		// Increase severity if cloud metadata is a potential target
		const finalSeverity = metadataPatterns.length > 0 && !taintPath.sanitized ? 'critical' : severity;

		return {
			id: createFindingId(this.metadata.id),
			ruleId: this.metadata.id,
			severity: finalSeverity,
			confidence,
			title: 'Server-Side Request Forgery (SSRF)',
			description:
				`Untrusted input from "${taintPath.source.nodeName}" (${taintPath.source.nodeType}) controls the URL in "${taintPath.sink.nodeName}".${patternList}` +
				` An attacker could access internal services, cloud metadata APIs (169.254.169.254), or perform port scanning.`,
			category: 'ssrf',
			source: {
				node: taintPath.source.nodeName,
				nodeType: taintPath.source.nodeType,
				field: taintPath.taintedField,
			},
			sink: {
				node: taintPath.sink.nodeName,
				nodeType: taintPath.sink.nodeType,
				parameter: taintPath.sinkParam,
				dangerousExpression: allPatterns[0],
			},
			path: taintPath.path,
			remediation: this.getRemediation(taintPath),
			references: this.metadata.references,
			metadata: {
				internalPatterns,
				metadataPatterns,
				bypassPatterns,
				sanitized: taintPath.sanitized,
				sanitizerNodes: taintPath.sanitizerNodes,
			},
		};
	}

	/**
	 * Get remediation guidance
	 */
	private getRemediation(taintPath: TaintPath): RemediationGuidance {
		return {
			summary:
				'Implement URL allowlisting and block access to internal networks. Never let users control the full URL.',
			steps: [
				'Create an allowlist of permitted domains or URL patterns',
				`Add URL validation after "${taintPath.source.nodeName}" using URL parsing (not regex)`,
				'Block requests to private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x',
				'Block requests to cloud metadata endpoints: 169.254.169.254, metadata.google, etc.',
				'If only paths should be dynamic, hardcode the base URL and only allow path changes',
				"Consider using n8n's built-in integration nodes instead of raw HTTP requests",
				'Implement a proxy service that validates and sanitizes URLs before making requests',
			],
			safePattern: `
// UNSAFE - User controls full URL:
url: "{{ $json.targetUrl }}"

// SAFE - Allowlist validation:
const allowedDomains = ['api.example.com', 'data.example.com'];

// Parse and validate the URL
const url = new URL($json.targetUrl);

// Check domain is allowed
if (!allowedDomains.includes(url.hostname)) {
  throw new Error('Domain not allowed: ' + url.hostname);
}

// Check for private IPs (simplified)
const privateIpRegex = /^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|127\\.|0\\.0\\.0\\.0|169\\.254\\.)/;
if (privateIpRegex.test(url.hostname)) {
  throw new Error('Internal addresses not allowed');
}

// SAFER - Hardcode base URL, only allow dynamic paths:
url: "https://api.example.com/{{ $json.endpoint }}"
// Validate endpoint doesn't contain ../ or other path traversal
`,
			exampleCode:
				'Use an IF node to validate URLs against an allowlist before the HTTP Request node',
		};
	}
}
