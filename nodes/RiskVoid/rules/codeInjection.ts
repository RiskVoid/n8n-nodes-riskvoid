/**
 * Code Injection (RCE) Detection Rule
 *
 * Detects when untrusted user input flows to code execution functions,
 * which could allow attackers to execute arbitrary code on the server.
 *
 * Rule ID: RV-RCE-001
 * Severity: Critical
 * CWE: CWE-94 (Improper Control of Generation of Code)
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
 * Node types that execute code (RCE sinks)
 */
const CODE_EXECUTION_NODE_TYPES = [
	'n8n-nodes-base.code',
	'n8n-nodes-base.function',
	'n8n-nodes-base.functionItem',
];

/**
 * Dangerous code execution patterns in JavaScript/Python
 */
const DANGEROUS_PATTERNS = [
	// JavaScript patterns
	{ pattern: /\beval\s*\(/, name: 'eval()' },
	{ pattern: /\bFunction\s*\(/, name: 'Function()' },
	{ pattern: /new\s+Function\s*\(/, name: 'new Function()' },
	{ pattern: /\bsetTimeout\s*\(\s*['"`]/, name: 'setTimeout with string' },
	{ pattern: /\bsetInterval\s*\(\s*['"`]/, name: 'setInterval with string' },
	{ pattern: /\$\.globalEval\s*\(/, name: 'jQuery globalEval()' },
	{ pattern: /vm\.run/, name: 'Node.js vm.run()' },
	{ pattern: /vm\.runInContext/, name: 'Node.js vm.runInContext()' },
	{ pattern: /vm\.runInNewContext/, name: 'Node.js vm.runInNewContext()' },
	{ pattern: /child_process/, name: 'Node.js child_process' },
	{ pattern: /require\s*\(\s*['"`][^'"]+['"`]\s*\)/, name: 'dynamic require()' },

	// Python patterns (for Code node in Python mode)
	{ pattern: /\bexec\s*\(/, name: 'Python exec()' },
	{ pattern: /\beval\s*\(/, name: 'Python eval()' },
	{ pattern: /\bcompile\s*\(/, name: 'Python compile()' },
	{ pattern: /__import__\s*\(/, name: 'Python __import__()' },
	{ pattern: /subprocess/, name: 'Python subprocess' },
	{ pattern: /os\.system/, name: 'Python os.system()' },
	{ pattern: /os\.popen/, name: 'Python os.popen()' },
];

/**
 * Code Injection Detection Rule
 */
export class CodeInjectionRule implements DetectionRule {
	metadata: RuleMetadata = {
		id: 'RV-RCE-001',
		name: 'Remote Code Execution via User Input',
		description:
			'Detects when untrusted user input flows to code execution functions, allowing attackers to execute arbitrary code',
		category: 'injection',
		severity: 'critical',
		tags: ['rce', 'code-injection', 'eval', 'code-execution'],
		references: {
			cwe: 'CWE-94',
			owasp: 'A03:2021-Injection',
			capec: 'CAPEC-242',
		},
	};

	/**
	 * Check if this rule is applicable to the workflow
	 */
	isApplicable(context: RuleContext): boolean {
		// Rule is applicable if there are any RCE sinks in the workflow
		const hasRceSinks = context.sinks.some((sink) => sink.riskType === 'RCE');
		const hasCodeExecutionNodes = Array.from(context.workflow.nodes.values()).some((node) =>
			CODE_EXECUTION_NODE_TYPES.includes(node.type),
		);
		return hasRceSinks || hasCodeExecutionNodes;
	}

	/**
	 * Run detection and return findings
	 */
	detect(context: RuleContext): Finding[] {
		const findings: Finding[] = [];

		// Get taint paths that flow to any RCE sink (Code, Function, FunctionItem)
		const rcePaths = context.taintPaths.filter((path) => path.sink.riskType === 'RCE');

		for (const taintPath of rcePaths) {
			// Get the sink node to analyze its content
			const sinkNode = context.workflow.nodes.get(taintPath.sink.nodeName);
			if (!sinkNode) continue;

			// Get the code content (different parameter names for different node types)
			const { codeContent, codeLanguage } = this.extractCodeContent(sinkNode);

			// Detect dangerous patterns in the code
			const detectedPatterns = this.findDangerousPatterns(codeContent);

			// Determine confidence level
			const confidence = this.determineConfidence(taintPath, detectedPatterns);

			// Create finding
			findings.push(this.createFinding(taintPath, detectedPatterns, confidence, codeLanguage));
		}

		// Also check code execution nodes that use dangerous patterns with $input/$json
		// even if there's no explicit untrusted source (potential vulnerability)
		this.detectPotentialVulnerabilities(context, findings);

		return findings;
	}

	/**
	 * Extract code content from a node (handles Code, Function, FunctionItem)
	 */
	private extractCodeContent(node: { type: string; parameters: Record<string, unknown> }): {
		codeContent: string;
		codeLanguage: string;
	} {
		// Code node uses jsCode or pythonCode
		const jsCode = node.parameters.jsCode as string | undefined;
		const pythonCode = node.parameters.pythonCode as string | undefined;
		// Function and FunctionItem nodes use functionCode
		const functionCode = node.parameters.functionCode as string | undefined;

		const codeContent = jsCode || pythonCode || functionCode || '';
		const codeLanguage = pythonCode ? 'Python' : 'JavaScript';

		return { codeContent, codeLanguage };
	}

	/**
	 * Detect code execution nodes that use dangerous patterns with input data
	 * These are potential vulnerabilities even without an untrusted source
	 */
	private detectPotentialVulnerabilities(context: RuleContext, findings: Finding[]): void {
		// Get nodes that weren't already flagged
		const flaggedNodes = new Set(findings.map((f) => f.sink.node));

		for (const [nodeName, node] of context.workflow.nodes) {
			// Check all code execution node types (Code, Function, FunctionItem)
			if (!CODE_EXECUTION_NODE_TYPES.includes(node.type)) continue;
			if (flaggedNodes.has(nodeName)) continue;

			const { codeContent, codeLanguage } = this.extractCodeContent(node);

			// Check if code uses dangerous patterns
			const detectedPatterns = this.findDangerousPatterns(codeContent);
			if (detectedPatterns.length === 0) continue;

			// Check if code references input data ($input, $json, $('NodeName'))
			const usesInputData = this.usesInputData(codeContent);
			if (!usesInputData) continue;

			// This is a potential vulnerability - dangerous pattern + input data usage
			findings.push(this.createPotentialFinding(nodeName, node, detectedPatterns, codeLanguage, context));
		}
	}

	/**
	 * Get the code parameter name based on node type and language
	 */
	private getCodeParameterName(nodeType: string, codeLanguage: string): string {
		if (nodeType === 'n8n-nodes-base.function' || nodeType === 'n8n-nodes-base.functionItem') {
			return 'functionCode';
		}
		return codeLanguage === 'Python' ? 'pythonCode' : 'jsCode';
	}

	/**
	 * Check if code references input data
	 */
	private usesInputData(code: string): boolean {
		const inputPatterns = [
			/\$input/,
			/\$json/,
			/\$\(['"][^'"]+['"]\)/,  // $('NodeName')
			/items\[\d*\]/,  // items[0] or items[]
		];
		return inputPatterns.some(p => p.test(code));
	}

	/**
	 * Create a finding for potential vulnerability (no confirmed untrusted source)
	 */
	private createPotentialFinding(
		nodeName: string,
		node: { type: string; parameters: Record<string, unknown> },
		patterns: string[],
		codeLanguage: string,
		context: RuleContext,
	): Finding {
		// Find what node feeds into this Code node
		const graphNode = context.graph.nodes.get(nodeName);
		const predecessors = graphNode?.predecessors || [];
		const sourceNode = predecessors[0] || 'unknown';

		return {
			id: createFindingId(this.metadata.id),
			ruleId: this.metadata.id,
			severity: 'high',  // High instead of critical since source is unknown/trusted
			confidence: 'medium',
			title: 'Potential Code Execution with Input Data',
			description:
				`Code node "${nodeName}" uses dangerous patterns (${patterns.join(', ')}) with input data. ` +
				`If this node receives data from an untrusted source (webhook, form, email, etc.), ` +
				`an attacker could execute arbitrary code. Currently receiving data from "${sourceNode}".`,
			category: 'injection',
			source: {
				node: sourceNode,
				nodeType: context.workflow.nodes.get(sourceNode)?.type || 'unknown',
				field: '$input',
			},
			sink: {
				node: nodeName,
				nodeType: node.type,
				parameter: this.getCodeParameterName(node.type, codeLanguage),
				dangerousExpression: patterns[0],
			},
			path: predecessors.length > 0 ? [sourceNode, nodeName] : [nodeName],
			remediation: {
				summary: 'Avoid using eval() or similar functions with input data. Use allowlists instead.',
				steps: [
					'Replace eval() with a predefined function lookup (allowlist pattern)',
					'If the input source is ever changed to a webhook or form, this becomes a critical RCE vulnerability',
					'Consider using Switch node to map inputs to safe predefined operations',
					'Add input validation before the Code node',
				],
				safePattern: this.getRemediation({ source: { nodeName: sourceNode } } as TaintPath, codeLanguage).safePattern,
			},
			references: this.metadata.references,
			metadata: {
				detectedPatterns: patterns,
				codeLanguage,
				isPotential: true,
			},
		};
	}

	/**
	 * Find dangerous patterns in code
	 */
	private findDangerousPatterns(code: string): string[] {
		const found: string[] = [];

		for (const { pattern, name } of DANGEROUS_PATTERNS) {
			if (pattern.test(code)) {
				found.push(name);
			}
		}

		return found;
	}

	/**
	 * Determine confidence level based on analysis
	 */
	private determineConfidence(taintPath: TaintPath, detectedPatterns: string[]): FindingConfidence {
		// High confidence if:
		// - Dangerous patterns are detected AND taint flows directly
		// - No sanitizers in the path
		if (detectedPatterns.length > 0 && !taintPath.sanitized) {
			return 'high';
		}

		// Medium confidence if:
		// - Dangerous patterns detected but sanitizers present
		// - Or no dangerous patterns but direct taint flow
		if (detectedPatterns.length > 0 || !taintPath.sanitized) {
			return 'medium';
		}

		// Low confidence if sanitizers are present and no dangerous patterns
		return 'low';
	}

	/**
	 * Create a finding from a taint path
	 */
	private createFinding(
		taintPath: TaintPath,
		patterns: string[],
		confidence: FindingConfidence,
		codeLanguage: string,
	): Finding {
		const patternList =
			patterns.length > 0
				? ` Dangerous patterns detected: ${patterns.join(', ')}.`
				: ' The code may dynamically execute user-controlled input.';

		const severity = getEffectiveSeverity(this.metadata.severity, taintPath.sanitized);

		return {
			id: createFindingId(this.metadata.id),
			ruleId: this.metadata.id,
			severity,
			confidence,
			title: 'Remote Code Execution via User Input',
			description:
				`Untrusted input from "${taintPath.source.nodeName}" (${taintPath.source.nodeType}) flows to ${codeLanguage} code execution in "${taintPath.sink.nodeName}".${patternList}` +
				` An attacker could execute arbitrary code on the server, leading to complete system compromise.`,
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
			remediation: this.getRemediation(taintPath, codeLanguage),
			references: this.metadata.references,
			metadata: {
				detectedPatterns: patterns,
				codeLanguage,
				sanitized: taintPath.sanitized,
				sanitizerNodes: taintPath.sanitizerNodes,
			},
		};
	}

	/**
	 * Get remediation guidance
	 */
	private getRemediation(taintPath: TaintPath, codeLanguage: string): RemediationGuidance {
		const jsExample = `
// UNSAFE - Executing user input:
const userCommand = $json.command;
eval(userCommand);  // DANGER!

// SAFE - Use an allowlist:
const allowedCommands = {
  'greet': () => 'Hello!',
  'time': () => new Date().toISOString(),
  'version': () => '1.0.0',
};

const command = $json.command;
if (allowedCommands[command]) {
  return allowedCommands[command]();
} else {
  throw new Error('Invalid command: ' + command);
}`;

		const pythonExample = `
# UNSAFE - Executing user input:
user_command = items[0].json.get('command')
exec(user_command)  # DANGER!

# SAFE - Use an allowlist:
allowed_commands = {
    'greet': lambda: 'Hello!',
    'time': lambda: str(datetime.now()),
}

command = items[0].json.get('command')
if command in allowed_commands:
    return allowed_commands[command]()
else:
    raise ValueError(f'Invalid command: {command}')`;

		return {
			summary:
				'Never execute user-controlled input as code. Use allowlists and predefined functions instead.',
			steps: [
				`Add input validation immediately after "${taintPath.source.nodeName}" to restrict allowed values`,
				'Use a Switch node to map user input to predefined safe operations',
				'If dynamic behavior is required, create a strict allowlist of permitted operations',
				"Replace dynamic code execution with n8n's built-in nodes where possible",
				'If code execution is unavoidable, validate input against a strict schema',
				'Consider using sandboxed execution environments for untrusted code',
			],
			safePattern: codeLanguage === 'Python' ? pythonExample : jsExample,
			exampleCode: 'Use predefined functions with an allowlist lookup instead of dynamic code execution',
		};
	}
}
