/**
 * Tests for Command Injection Detection Rule
 */

import { CommandInjectionRule } from '../../nodes/RiskVoid/rules/commandInjection';
import type { RuleContext } from '../../nodes/RiskVoid/rules/types';
import type { TaintPath, SecuritySink } from '../../nodes/RiskVoid/types/taint';
import type { ParsedWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import type { WorkflowGraph } from '../../nodes/RiskVoid/types/graph';
import type { N8nNode } from '../../nodes/RiskVoid/types/workflow';

describe('CommandInjectionRule', () => {
	let rule: CommandInjectionRule;

	beforeEach(() => {
		rule = new CommandInjectionRule();
	});

	// Helper to create mock workflow
	function createMockWorkflow(nodes: N8nNode[]): ParsedWorkflow {
		const nodeMap = new Map<string, N8nNode>();
		const nodesByType = new Map<string, N8nNode[]>();

		for (const node of nodes) {
			nodeMap.set(node.name, node);
			const list = nodesByType.get(node.type) ?? [];
			list.push(node);
			nodesByType.set(node.type, list);
		}

		return {
			id: 'test-workflow',
			name: 'Test Workflow',
			nodes: nodeMap,
			nodesByType,
			connections: {},
			nodeCount: nodes.length,
			connectionCount: 0,
			metadata: {
				hasTriggers: true,
				triggerTypes: [],
				nodeTypes: nodes.map((n) => n.type),
				usesCredentials: false,
				credentialTypes: [],
			},
			raw: {
				name: 'Test Workflow',
				active: false,
				nodes,
				connections: {},
			},
		};
	}

	// Helper to create mock context
	function createMockContext(
		nodes: N8nNode[],
		taintPaths: TaintPath[],
		sinks: SecuritySink[] = [],
	): RuleContext {
		const workflow = createMockWorkflow(nodes);

		return {
			workflow,
			graph: {
				nodes: new Map(),
				edges: [],
				entryPoints: [],
				exitPoints: [],
				hasCycles: false,
			} as WorkflowGraph,
			sources: [],
			sinks,
			taintPaths,
		};
	}

	// Helper to create Execute Command node
	function createExecNode(name: string, command: string): N8nNode {
		return {
			id: `node-${name}`,
			name,
			type: 'n8n-nodes-base.executeCommand',
			typeVersion: 1,
			position: [0, 0],
			parameters: {
				command,
			},
		};
	}

	// Helper to create a taint path to Execute Command node
	function createTaintPath(
		sourceName: string,
		sinkName: string,
		sanitized = false,
	): TaintPath {
		return {
			id: `path-${sourceName}-${sinkName}`,
			source: {
				nodeName: sourceName,
				nodeType: 'n8n-nodes-base.webhook',
				trustLevel: 'untrusted',
				taintedFields: ['body'],
				classification: {
					role: 'source',
					trustLevel: 'untrusted',
					taintedFields: ['body'],
					description: 'Webhook receives untrusted input',
				},
			},
			sink: {
				nodeName: sinkName,
				nodeType: 'n8n-nodes-base.executeCommand',
				severity: 'critical',
				riskType: 'Command Injection',
				dangerousParams: [
					{ paramPath: 'command', value: '', hasExpressions: true, expressions: [] },
				],
				classification: {
					role: 'sink',
					severity: 'critical',
					riskType: 'Command Injection',
					dangerousParams: ['command'],
					description: 'Command execution sink',
				},
			},
			path: [sourceName, sinkName],
			taintedField: 'body',
			sinkParam: 'command',
			severity: 'critical',
			sanitized,
			sanitizerNodes: sanitized ? ['IF Node'] : [],
			confidence: 'high',
		};
	}

	// Helper to create Command Injection sink
	function createCmdSink(nodeName: string): SecuritySink {
		return {
			nodeName,
			nodeType: 'n8n-nodes-base.executeCommand',
			severity: 'critical',
			riskType: 'Command Injection',
			dangerousParams: [],
			classification: {
				role: 'sink',
				severity: 'critical',
				riskType: 'Command Injection',
				dangerousParams: ['command'],
				description: 'Command execution',
			},
		};
	}

	describe('metadata', () => {
		it('should have correct rule ID', () => {
			expect(rule.metadata.id).toBe('RV-CMDI-001');
		});

		it('should have critical severity', () => {
			expect(rule.metadata.severity).toBe('critical');
		});

		it('should have correct category', () => {
			expect(rule.metadata.category).toBe('injection');
		});

		it('should have CWE reference', () => {
			expect(rule.metadata.references.cwe).toBe('CWE-78');
		});
	});

	describe('isApplicable', () => {
		it('should return true when Execute Command sinks exist', () => {
			const context = createMockContext(
				[createExecNode('Exec', 'ls -la')],
				[],
				[createCmdSink('Exec')],
			);

			expect(rule.isApplicable(context)).toBe(true);
		});

		it('should return false when no command injection sinks exist', () => {
			const context = createMockContext([], [], []);
			expect(rule.isApplicable(context)).toBe(false);
		});
	});

	describe('detect', () => {
		it('should detect taint flow to Execute Command node', () => {
			const execNode = createExecNode('Exec', 'process_file {{ $json.filename }}');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('critical');
			expect(findings[0].confidence).toBe('high');
		});

		it('should detect pipe command chaining', () => {
			const execNode = createExecNode('Exec', 'cat file.txt | grep {{ $json.pattern }}');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('pipe to command');
		});

		it('should detect command substitution with $()', () => {
			const execNode = createExecNode('Exec', 'echo $(cat {{ $json.file }})');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('command substitution $()');
		});

		it('should detect backtick command substitution', () => {
			const execNode = createExecNode('Exec', 'echo `whoami`');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('backtick command substitution');
		});

		it('should detect semicolon command chaining', () => {
			const execNode = createExecNode('Exec', 'ls; rm -rf /');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('command chaining with ;');
		});

		it('should detect && command chaining', () => {
			const execNode = createExecNode('Exec', 'test -f file && cat file');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('command chaining with &&');
		});

		it('should reduce severity when sanitizers are present', () => {
			const execNode = createExecNode('Exec', 'process {{ $json.input }}');
			const taintPath = createTaintPath('Webhook', 'Exec', true); // sanitized
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('high'); // reduced from critical
		});

		it('should include shell metacharacters in description', () => {
			const execNode = createExecNode('Exec', 'echo {{ $json.msg }}');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings[0].description).toContain(';');
			expect(findings[0].description).toContain('|');
			expect(findings[0].description).toContain('&');
		});

		it('should include remediation guidance', () => {
			const execNode = createExecNode('Exec', 'process {{ $json.file }}');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings[0].remediation.summary).toContain('allowlist');
			expect(findings[0].remediation.steps.length).toBeGreaterThan(0);
			expect(findings[0].remediation.safePattern).toBeDefined();
		});

		it('should return empty array when no taint paths to Execute Command', () => {
			const execNode = createExecNode('Exec', 'ls -la');
			const context = createMockContext([execNode], [], [createCmdSink('Exec')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(0);
		});

		it('should track the path from source to sink', () => {
			const execNode = createExecNode('Exec', 'process {{ $json.file }}');
			const taintPath: TaintPath = {
				...createTaintPath('Webhook', 'Exec'),
				path: ['Webhook', 'Set', 'Exec'],
			};
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings[0].path).toEqual(['Webhook', 'Set', 'Exec']);
		});

		it('should have high confidence for metacharacter risk', () => {
			const execNode = createExecNode('Exec', 'process {{ $json.file }}');
			const taintPath = createTaintPath('Webhook', 'Exec');
			const context = createMockContext(
				[execNode],
				[taintPath],
				[createCmdSink('Exec')],
			);

			const findings = rule.detect(context);

			expect(findings[0].confidence).toBe('high');
			expect(findings[0].metadata.hasMetacharRisk).toBe(true);
		});
	});
});
