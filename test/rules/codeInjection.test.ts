/**
 * Tests for Code Injection (RCE) Detection Rule
 */

import { CodeInjectionRule } from '../../nodes/RiskVoid/rules/codeInjection';
import type { RuleContext } from '../../nodes/RiskVoid/rules/types';
import type { TaintPath, SecuritySink } from '../../nodes/RiskVoid/types/taint';
import type { ParsedWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import type { WorkflowGraph } from '../../nodes/RiskVoid/types/graph';
import type { N8nNode } from '../../nodes/RiskVoid/types/workflow';

describe('CodeInjectionRule', () => {
	let rule: CodeInjectionRule;

	beforeEach(() => {
		rule = new CodeInjectionRule();
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

	// Helper to create a Code node
	function createCodeNode(name: string, jsCode: string): N8nNode {
		return {
			id: `node-${name}`,
			name,
			type: 'n8n-nodes-base.code',
			typeVersion: 1,
			position: [0, 0],
			parameters: {
				jsCode,
				mode: 'runOnceForAllItems',
			},
		};
	}

	// Helper to create a taint path to Code node
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
				nodeType: 'n8n-nodes-base.code',
				severity: 'critical',
				riskType: 'RCE',
				dangerousParams: [{ paramPath: 'jsCode', value: '', hasExpressions: true, expressions: [] }],
				classification: {
					role: 'sink',
					severity: 'critical',
					riskType: 'RCE',
					dangerousParams: ['jsCode'],
					description: 'Code execution sink',
				},
			},
			path: [sourceName, sinkName],
			taintedField: 'body',
			sinkParam: 'jsCode',
			severity: 'critical',
			sanitized,
			sanitizerNodes: sanitized ? ['IF Node'] : [],
			confidence: 'high',
		};
	}

	// Helper to create RCE sink
	function createRceSink(nodeName: string): SecuritySink {
		return {
			nodeName,
			nodeType: 'n8n-nodes-base.code',
			severity: 'critical',
			riskType: 'RCE',
			dangerousParams: [],
			classification: {
				role: 'sink',
				severity: 'critical',
				riskType: 'RCE',
				dangerousParams: ['jsCode'],
				description: 'Code execution',
			},
		};
	}

	describe('metadata', () => {
		it('should have correct rule ID', () => {
			expect(rule.metadata.id).toBe('RV-RCE-001');
		});

		it('should have critical severity', () => {
			expect(rule.metadata.severity).toBe('critical');
		});

		it('should have correct category', () => {
			expect(rule.metadata.category).toBe('injection');
		});

		it('should have CWE reference', () => {
			expect(rule.metadata.references.cwe).toBe('CWE-94');
		});
	});

	describe('isApplicable', () => {
		it('should return true when Code nodes with RCE risk exist', () => {
			const context = createMockContext(
				[createCodeNode('Code', 'return items;')],
				[],
				[createRceSink('Code')],
			);

			expect(rule.isApplicable(context)).toBe(true);
		});

		it('should return false when no Code nodes exist', () => {
			const context = createMockContext([], [], []);
			expect(rule.isApplicable(context)).toBe(false);
		});

		it('should return false when sinks are not RCE type', () => {
			const context = createMockContext(
				[],
				[],
				[
					{
						nodeName: 'HTTP Request',
						nodeType: 'n8n-nodes-base.httpRequest',
						severity: 'high',
						riskType: 'SSRF',
						dangerousParams: [],
						classification: {
							role: 'sink',
							severity: 'high',
							riskType: 'SSRF',
							dangerousParams: ['url'],
							description: 'SSRF sink',
						},
					},
				],
			);

			expect(rule.isApplicable(context)).toBe(false);
		});
	});

	describe('detect', () => {
		it('should detect taint flow to Code node with eval()', () => {
			const codeNode = createCodeNode('Code', 'const result = eval($json.command);');
			const taintPath = createTaintPath('Webhook', 'Code');
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('critical');
			expect(findings[0].confidence).toBe('high');
			expect(findings[0].metadata.detectedPatterns).toContain('eval()');
		});

		it('should detect Function constructor usage', () => {
			const codeNode = createCodeNode('Code', 'const fn = new Function($json.code);');
			const taintPath = createTaintPath('Webhook', 'Code');
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('new Function()');
		});

		it('should detect setTimeout with string argument', () => {
			const codeNode = createCodeNode('Code', 'setTimeout("alert(1)", 1000);');
			const taintPath = createTaintPath('Webhook', 'Code');
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('setTimeout with string');
		});

		it('should detect child_process usage', () => {
			const codeNode = createCodeNode(
				'Code',
				'const { exec } = require("child_process"); exec($json.cmd);',
			);
			const taintPath = createTaintPath('Webhook', 'Code');
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('Node.js child_process');
		});

		it('should detect multiple dangerous patterns', () => {
			const codeNode = createCodeNode('Code', 'eval($json.a); new Function($json.b);');
			const taintPath = createTaintPath('Webhook', 'Code');
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('eval()');
			expect(findings[0].metadata.detectedPatterns).toContain('new Function()');
		});

		it('should reduce severity when sanitizers are present', () => {
			const codeNode = createCodeNode('Code', 'eval($json.command);');
			const taintPath = createTaintPath('Webhook', 'Code', true); // sanitized
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('high'); // reduced from critical
		});

		it('should set medium confidence when no dangerous patterns but taint flows', () => {
			const codeNode = createCodeNode('Code', 'return { data: $json.userInput };');
			const taintPath = createTaintPath('Webhook', 'Code');
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].confidence).toBe('medium');
		});

		it('should include remediation guidance', () => {
			const codeNode = createCodeNode('Code', 'eval($json.command);');
			const taintPath = createTaintPath('Webhook', 'Code');
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings[0].remediation.summary).toContain('allowlist');
			expect(findings[0].remediation.steps.length).toBeGreaterThan(0);
			expect(findings[0].remediation.safePattern).toBeDefined();
		});

		it('should detect potential vulnerability when Code node uses dangerous patterns with input data', () => {
			const codeNode = createCodeNode('Code', 'eval($json.command);');
			const context = createMockContext([codeNode], [], [createRceSink('Code')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('high'); // Not critical without confirmed untrusted source
			expect(findings[0].confidence).toBe('medium');
			expect(findings[0].title).toContain('Potential');
		});

		it('should handle Python code detection', () => {
			const pythonNode: N8nNode = {
				id: 'node-python',
				name: 'Python Code',
				type: 'n8n-nodes-base.code',
				typeVersion: 1,
				position: [0, 0],
				parameters: {
					pythonCode: 'exec(items[0].json.get("command"))',
					mode: 'runOnceForAllItems',
				},
			};

			const taintPath: TaintPath = {
				...createTaintPath('Webhook', 'Python Code'),
				sink: {
					...createTaintPath('Webhook', 'Python Code').sink,
					nodeName: 'Python Code',
					dangerousParams: [
						{ paramPath: 'pythonCode', value: '', hasExpressions: true, expressions: [] },
					],
				},
				path: ['Webhook', 'Python Code'],
			};

			const context = createMockContext(
				[pythonNode],
				[taintPath],
				[{ ...createRceSink('Python Code'), nodeName: 'Python Code' }],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.codeLanguage).toBe('Python');
			expect(findings[0].metadata.detectedPatterns).toContain('Python exec()');
		});

		it('should track the path from source to sink', () => {
			const codeNode = createCodeNode('Code', 'eval($json.cmd);');
			const taintPath: TaintPath = {
				...createTaintPath('Webhook', 'Code'),
				path: ['Webhook', 'Set', 'IF', 'Code'],
			};
			const context = createMockContext(
				[codeNode],
				[taintPath],
				[createRceSink('Code')],
			);

			const findings = rule.detect(context);

			expect(findings[0].path).toEqual(['Webhook', 'Set', 'IF', 'Code']);
		});
	});
});
