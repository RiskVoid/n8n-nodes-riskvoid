/**
 * Command Injection Detection Rule
 *
 * Detects when untrusted user input flows to system command execution,
 * which could allow attackers to execute arbitrary OS commands.
 *
 * Rule ID: RV-CMDI-001
 * Severity: Critical
 * CWE: CWE-78 (OS Command Injection)
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
 * Shell metacharacters that enable command injection
 */
const SHELL_METACHARACTERS = [
	';', // Command separator
	'|', // Pipe
	'&', // Background/AND operator
	'$', // Variable expansion
	'`', // Command substitution
	'(', // Subshell
	')', // Subshell
	'{', // Brace expansion
	'}', // Brace expansion
	'<', // Input redirection
	'>', // Output redirection
	'\n', // Newline (command separator)
	'\r', // Carriage return
	'\\', // Escape character
];

/**
 * Dangerous command patterns
 */
const DANGEROUS_COMMAND_PATTERNS = [
	{ pattern: /\$\{[^}]+\}/, name: 'variable expansion ${}' },
	{ pattern: /\$\([^)]+\)/, name: 'command substitution $()' },
	{ pattern: /`[^`]+`/, name: 'backtick command substitution' },
	{ pattern: /\|\s*\w+/, name: 'pipe to command' },
	{ pattern: /;\s*\w+/, name: 'command chaining with ;' },
	{ pattern: /&&\s*\w+/, name: 'command chaining with &&' },
	{ pattern: /\|\|\s*\w+/, name: 'command chaining with ||' },
];

/**
 * Command Injection Detection Rule
 */
export class CommandInjectionRule implements DetectionRule {
	metadata: RuleMetadata = {
		id: 'RV-CMDI-001',
		name: 'Command Injection via User Input',
		description:
			'Detects when untrusted user input flows to system command execution, allowing attackers to execute arbitrary OS commands',
		category: 'injection',
		severity: 'critical',
		tags: ['command-injection', 'shell', 'os-command', 'exec'],
		references: {
			cwe: 'CWE-78',
			owasp: 'A03:2021-Injection',
			capec: 'CAPEC-88',
		},
	};

	/**
	 * Check if this rule is applicable to the workflow
	 */
	isApplicable(context: RuleContext): boolean {
		return context.sinks.some((sink) => sink.riskType === 'Command Injection');
	}

	/**
	 * Run detection and return findings
	 */
	detect(context: RuleContext): Finding[] {
		const findings: Finding[] = [];

		// Get taint paths that flow to Execute Command nodes
		const cmdPaths = context.taintPaths.filter(
			(path) => path.sink.riskType === 'Command Injection',
		);

		for (const taintPath of cmdPaths) {
			// Get the sink node to analyze command content
			const sinkNode = context.workflow.nodes.get(taintPath.sink.nodeName);
			if (!sinkNode) continue;

			// Get the command parameter
			const command = (sinkNode.parameters.command as string) || '';

			// Detect dangerous patterns in the command
			const detectedPatterns = this.findDangerousPatterns(command);

			// Check if command contains shell metacharacters from user input
			const hasMetacharRisk = this.checkMetacharacterRisk(command);

			// Determine confidence level
			const confidence = this.determineConfidence(taintPath, detectedPatterns, hasMetacharRisk);

			// Create finding
			findings.push(
				this.createFinding(taintPath, detectedPatterns, confidence, hasMetacharRisk),
			);
		}

		return findings;
	}

	/**
	 * Find dangerous patterns in command
	 */
	private findDangerousPatterns(command: string): string[] {
		const found: string[] = [];

		for (const { pattern, name } of DANGEROUS_COMMAND_PATTERNS) {
			if (pattern.test(command)) {
				found.push(name);
			}
		}

		return found;
	}

	/**
	 * Check if the command might be vulnerable to shell metacharacter injection
	 */
	private checkMetacharacterRisk(command: string): boolean {
		// If command contains n8n expression syntax, it's at risk
		const hasExpression = /\{\{\s*\$/.test(command);

		// Check if any shell metacharacters could be injected
		// This is a heuristic - if expressions are present and no obvious escaping
		return hasExpression;
	}

	/**
	 * Determine confidence level based on analysis
	 */
	private determineConfidence(
		taintPath: TaintPath,
		detectedPatterns: string[],
		hasMetacharRisk: boolean,
	): FindingConfidence {
		// High confidence if:
		// - Direct taint flow with no sanitizers
		// - Or dangerous patterns detected
		if (!taintPath.sanitized && (detectedPatterns.length > 0 || hasMetacharRisk)) {
			return 'high';
		}

		// Medium confidence if taint flows but sanitizers present
		if (detectedPatterns.length > 0 || hasMetacharRisk) {
			return 'medium';
		}

		// Low confidence otherwise
		return 'low';
	}

	/**
	 * Create a finding from a taint path
	 */
	private createFinding(
		taintPath: TaintPath,
		patterns: string[],
		confidence: FindingConfidence,
		hasMetacharRisk: boolean,
	): Finding {
		const patternList =
			patterns.length > 0
				? ` Dangerous patterns detected: ${patterns.join(', ')}.`
				: hasMetacharRisk
					? ' Shell metacharacters could be injected via user input.'
					: '';

		const severity = getEffectiveSeverity(this.metadata.severity, taintPath.sanitized);

		const metacharList = SHELL_METACHARACTERS.filter((c) => c !== '\n' && c !== '\r').join(' ');

		return {
			id: createFindingId(this.metadata.id),
			ruleId: this.metadata.id,
			severity,
			confidence,
			title: 'Command Injection via User Input',
			description:
				`Untrusted input from "${taintPath.source.nodeName}" (${taintPath.source.nodeType}) flows to system command execution in "${taintPath.sink.nodeName}".${patternList}` +
				` An attacker could inject shell metacharacters (${metacharList}) to execute arbitrary commands on the server.`,
			category: 'injection',
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
				hasMetacharRisk,
				dangerousChars: SHELL_METACHARACTERS,
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
				'Never pass user input directly to shell commands. Use allowlists, escape input properly, or avoid shell execution entirely.',
			steps: [
				`Add strict input validation after "${taintPath.source.nodeName}" using an allowlist of permitted values`,
				'Escape all shell metacharacters (; | & $ \\` ( ) { } < > \\\\ \\n) if dynamic commands are required',
				'Use parameterized execution (pass arguments as array) instead of string concatenation',
				"Consider using n8n's HTTP Request or dedicated integration nodes instead of shell commands",
				'Implement the principle of least privilege - run n8n with minimal OS permissions',
				'If possible, replace the Execute Command node with safer alternatives',
			],
			safePattern: `
// UNSAFE - Direct user input in command:
command: "process_file {{ $json.filename }}"

// SAFE - Use a strict allowlist:
// First, add an IF node to validate input:
if (!['report.csv', 'data.json', 'log.txt'].includes($json.filename)) {
  throw new Error('Invalid filename');
}

// Or use a Switch node to map user input to predefined commands:
// Switch cases: "report" -> "generate_report.sh"
//               "backup" -> "run_backup.sh"
//               default  -> (Error node)

// If you must use dynamic values, escape shell metacharacters:
const sanitized = $json.filename.replace(/[;&|$\`(){}\\[\\]<>\\'"\\ \\n\\r]/g, '');
`,
			exampleCode:
				'Use an IF or Switch node to validate input against an allowlist before the Execute Command node',
		};
	}
}
