/**
 * Cross-Site Scripting (XSS) Detection Rule
 *
 * Detects when untrusted user input flows to HTML rendering or response output,
 * which could allow attackers to inject malicious scripts.
 *
 * Rule ID: RV-XSS-001
 * Severity: Medium
 * CWE: CWE-79 (Cross-Site Scripting)
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
 * HTML/Script patterns that indicate XSS risk
 */
const XSS_PATTERNS = [
	{ pattern: /<script/i, name: 'script tag' },
	{ pattern: /javascript:/i, name: 'javascript: URL' },
	{ pattern: /on\w+\s*=/i, name: 'event handler attribute' },
	{ pattern: /<iframe/i, name: 'iframe tag' },
	{ pattern: /<object/i, name: 'object tag' },
	{ pattern: /<embed/i, name: 'embed tag' },
	{ pattern: /<svg.*onload/i, name: 'SVG with onload' },
	{ pattern: /data:text\/html/i, name: 'data: HTML URL' },
];

/**
 * XSS Detection Rule
 */
export class XssRule implements DetectionRule {
	metadata: RuleMetadata = {
		id: 'RV-XSS-001',
		name: 'Cross-Site Scripting via User Input',
		description:
			'Detects when untrusted user input flows to HTML rendering or response output, allowing attackers to inject malicious scripts',
		category: 'xss',
		severity: 'medium',
		tags: ['xss', 'html', 'injection', 'script'],
		references: {
			cwe: 'CWE-79',
			owasp: 'A03:2021-Injection',
			capec: 'CAPEC-86',
		},
	};

	/**
	 * Check if this rule is applicable to the workflow
	 */
	isApplicable(context: RuleContext): boolean {
		return context.sinks.some((sink) => sink.riskType === 'XSS');
	}

	/**
	 * Run detection and return findings
	 */
	detect(context: RuleContext): Finding[] {
		const findings: Finding[] = [];

		// Get taint paths that flow to XSS-vulnerable sinks
		const xssPaths = context.taintPaths.filter((path) => path.sink.riskType === 'XSS');

		for (const taintPath of xssPaths) {
			// Get the sink node to analyze content
			const sinkNode = context.workflow.nodes.get(taintPath.sink.nodeName);
			if (!sinkNode) continue;

			// Get the content being rendered/returned
			const content = this.extractContent(sinkNode.parameters);

			// Check for XSS patterns
			const detectedPatterns = this.findXssPatterns(content);

			// Determine if it's HTML output
			const isHtmlOutput = this.isHtmlOutput(sinkNode.type, sinkNode.parameters);

			// Skip non-HTML responses without XSS patterns (e.g., JSON API responses)
			// These are not XSS vulnerabilities
			if (!isHtmlOutput && detectedPatterns.length === 0) {
				continue;
			}

			// Determine confidence level
			const confidence = this.determineConfidence(taintPath, detectedPatterns, isHtmlOutput);

			// Create finding
			findings.push(this.createFinding(taintPath, detectedPatterns, confidence, isHtmlOutput));
		}

		return findings;
	}

	/**
	 * Extract content from node parameters
	 */
	private extractContent(params: Record<string, unknown>): string {
		const possibleFields = ['html', 'responseBody', 'body', 'content', 'text'];
		for (const field of possibleFields) {
			const value = params[field];
			if (typeof value === 'string') {
				return value;
			}
		}
		return JSON.stringify(params);
	}

	/**
	 * Check if the output is HTML
	 */
	private isHtmlOutput(nodeType: string, params: Record<string, unknown>): boolean {
		if (nodeType === 'n8n-nodes-base.html') {
			return true;
		}
		if (nodeType === 'n8n-nodes-base.respondToWebhook') {
			const respondWith = params.respondWith as string;
			const contentType = params.contentType as string;
			return respondWith === 'text' || contentType?.includes('html');
		}
		return false;
	}

	/**
	 * Find XSS patterns in content
	 */
	private findXssPatterns(content: string): string[] {
		const found: string[] = [];
		for (const { pattern, name } of XSS_PATTERNS) {
			if (pattern.test(content)) {
				found.push(name);
			}
		}
		return found;
	}

	/**
	 * Determine confidence level
	 */
	private determineConfidence(
		taintPath: TaintPath,
		detectedPatterns: string[],
		isHtmlOutput: boolean,
	): FindingConfidence {
		// High confidence if HTML output with patterns and no sanitizers
		if (isHtmlOutput && detectedPatterns.length > 0 && !taintPath.sanitized) {
			return 'high';
		}
		// Medium confidence if HTML output or patterns detected
		if (isHtmlOutput || detectedPatterns.length > 0) {
			return 'medium';
		}
		// Low confidence for non-HTML webhook responses
		return 'low';
	}

	/**
	 * Create a finding from a taint path
	 */
	private createFinding(
		taintPath: TaintPath,
		patterns: string[],
		confidence: FindingConfidence,
		isHtmlOutput: boolean,
	): Finding {
		const patternList =
			patterns.length > 0 ? ` Dangerous patterns detected: ${patterns.join(', ')}.` : '';

		const outputType = isHtmlOutput ? 'HTML output' : 'response output';
		const severity = getEffectiveSeverity(this.metadata.severity, taintPath.sanitized);

		return {
			id: createFindingId(this.metadata.id),
			ruleId: this.metadata.id,
			severity,
			confidence,
			title: 'Cross-Site Scripting (XSS) via User Input',
			description:
				`Untrusted input from "${taintPath.source.nodeName}" (${taintPath.source.nodeType}) flows to ${outputType} in "${taintPath.sink.nodeName}".${patternList}` +
				` An attacker could inject malicious scripts that execute in victims' browsers.`,
			category: 'xss',
			source: {
				node: taintPath.source.nodeName,
				nodeType: taintPath.source.nodeType,
				field: taintPath.taintedField,
			},
			sink: {
				node: taintPath.sink.nodeName,
				nodeType: taintPath.sink.nodeType,
				parameter: taintPath.sinkParam,
				dangerousExpression: patterns[0],
			},
			path: taintPath.path,
			remediation: this.getRemediation(taintPath),
			references: this.metadata.references,
			metadata: {
				detectedPatterns: patterns,
				isHtmlOutput,
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
				'Sanitize or encode user input before including it in HTML output. Use context-appropriate encoding.',
			steps: [
				`Add input sanitization after "${taintPath.source.nodeName}" to remove or encode dangerous characters`,
				'Use HTML entity encoding for content inserted into HTML body',
				'Use JavaScript encoding for content inserted into script contexts',
				'Use URL encoding for content inserted into URLs',
				'Consider using a Content Security Policy (CSP) header',
				'If returning JSON, ensure Content-Type is application/json, not text/html',
			],
			safePattern: `
// UNSAFE - Direct user input in HTML:
html: "<div>{{ $json.userComment }}</div>"

// SAFE - Encode HTML entities:
// Use a Code node to sanitize before the HTML node:
const sanitized = $json.userComment
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#x27;');
return { sanitizedComment: sanitized };

// Then use:
html: "<div>{{ $json.sanitizedComment }}</div>"

// For webhook responses returning JSON:
// Ensure respondWith is set to 'json' not 'text'
`,
			exampleCode: 'Use HTML entity encoding or a sanitization library before rendering user input',
		};
	}
}
