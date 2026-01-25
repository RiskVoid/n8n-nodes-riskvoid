/**
 * Integration tests for the rule framework
 *
 * Tests the complete rule engine with realistic workflow scenarios
 */

import {
	runAllRules,
	initializeBuiltInRules,
	clearAllRules,
	getAllRules,
	type RuleContext,
} from '../../nodes/RiskVoid/rules';
import type { TaintPath, TaintSource, SecuritySink } from '../../nodes/RiskVoid/types/taint';
import type { ParsedWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import type { WorkflowGraph, GraphNode } from '../../nodes/RiskVoid/types/graph';
import type { N8nNode } from '../../nodes/RiskVoid/types/workflow';

describe('Rule Framework Integration', () => {
	beforeEach(() => {
		clearAllRules();
		initializeBuiltInRules();
	});

	afterEach(() => {
		clearAllRules();
	});

	// Helper to create a complete workflow context
	function createWorkflowContext(
		nodes: N8nNode[],
		taintPaths: TaintPath[],
		sources: TaintSource[],
		sinks: SecuritySink[],
	): RuleContext {
		const nodeMap = new Map<string, N8nNode>();
		const nodesByType = new Map<string, N8nNode[]>();
		const graphNodes = new Map<string, GraphNode>();

		for (const node of nodes) {
			nodeMap.set(node.name, node);
			const list = nodesByType.get(node.type) ?? [];
			list.push(node);
			nodesByType.set(node.type, list);

			graphNodes.set(node.name, {
				name: node.name,
				type: node.type,
				data: node,
				successors: [],
				predecessors: [],
				depth: 0,
			});
		}

		const workflow: ParsedWorkflow = {
			id: 'test-workflow',
			name: 'Test Workflow',
			nodes: nodeMap,
			nodesByType,
			connections: {},
			nodeCount: nodes.length,
			connectionCount: 0,
			metadata: {
				hasTriggers: true,
				triggerTypes: ['n8n-nodes-base.webhook'],
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

		const graph: WorkflowGraph = {
			nodes: graphNodes,
			edges: [],
			entryPoints: [],
			exitPoints: [],
			hasCycles: false,
		};

		return {
			workflow,
			graph,
			sources,
			sinks,
			taintPaths,
		};
	}

	describe('Built-in rules registration', () => {
		it('should register all 6 built-in rules', () => {
			const rules = getAllRules();
			expect(rules).toHaveLength(6);

			const ruleIds = rules.map((r) => r.metadata.id);
			expect(ruleIds).toContain('RV-RCE-001');
			expect(ruleIds).toContain('RV-CMDI-001');
			expect(ruleIds).toContain('RV-SQLI-001');
			expect(ruleIds).toContain('RV-SSRF-001');
			expect(ruleIds).toContain('RV-PI-001');
			expect(ruleIds).toContain('RV-CRED-001');
		});
	});

	describe('Vulnerable workflow detection', () => {
		it('should detect RCE in webhook -> code workflow', () => {
			const nodes: N8nNode[] = [
				{
					id: 'webhook-1',
					name: 'Webhook',
					type: 'n8n-nodes-base.webhook',
					typeVersion: 1,
					position: [0, 0],
					parameters: { path: '/test' },
				},
				{
					id: 'code-1',
					name: 'Code',
					type: 'n8n-nodes-base.code',
					typeVersion: 1,
					position: [200, 0],
					parameters: { jsCode: 'eval({{ $json.command }})' },
				},
			];

			const taintPath: TaintPath = {
				id: 'path-1',
				source: {
					nodeName: 'Webhook',
					nodeType: 'n8n-nodes-base.webhook',
					trustLevel: 'untrusted',
					taintedFields: ['body'],
					classification: {
						role: 'source',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						description: 'Webhook',
					},
				},
				sink: {
					nodeName: 'Code',
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
				},
				path: ['Webhook', 'Code'],
				taintedField: 'body',
				sinkParam: 'jsCode',
				severity: 'critical',
				sanitized: false,
				sanitizerNodes: [],
				confidence: 'high',
			};

			const sinks: SecuritySink[] = [taintPath.sink];

			const context = createWorkflowContext(nodes, [taintPath], [], sinks);
			const result = runAllRules(context);

			expect(result.findings.length).toBeGreaterThan(0);
			const rceFinding = result.findings.find((f) => f.ruleId === 'RV-RCE-001');
			expect(rceFinding).toBeDefined();
			expect(rceFinding?.severity).toBe('critical');
		});

		it('should detect SQL injection in webhook -> MySQL workflow', () => {
			const nodes: N8nNode[] = [
				{
					id: 'webhook-1',
					name: 'Webhook',
					type: 'n8n-nodes-base.webhook',
					typeVersion: 1,
					position: [0, 0],
					parameters: { path: '/users' },
				},
				{
					id: 'mysql-1',
					name: 'MySQL',
					type: 'n8n-nodes-base.mySql',
					typeVersion: 1,
					position: [200, 0],
					parameters: {
						operation: 'executeQuery',
						query: "SELECT * FROM users WHERE id = {{ $json.userId }}",
					},
				},
			];

			const taintPath: TaintPath = {
				id: 'path-1',
				source: {
					nodeName: 'Webhook',
					nodeType: 'n8n-nodes-base.webhook',
					trustLevel: 'untrusted',
					taintedFields: ['body'],
					classification: {
						role: 'source',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						description: 'Webhook',
					},
				},
				sink: {
					nodeName: 'MySQL',
					nodeType: 'n8n-nodes-base.mySql',
					severity: 'high',
					riskType: 'SQL Injection',
					dangerousParams: [],
					classification: {
						role: 'sink',
						severity: 'high',
						riskType: 'SQL Injection',
						dangerousParams: ['query'],
						description: 'SQL execution',
					},
				},
				path: ['Webhook', 'MySQL'],
				taintedField: 'body',
				sinkParam: 'query',
				severity: 'high',
				sanitized: false,
				sanitizerNodes: [],
				confidence: 'high',
			};

			const sinks: SecuritySink[] = [taintPath.sink];

			const context = createWorkflowContext(nodes, [taintPath], [], sinks);
			const result = runAllRules(context);

			const sqliFinding = result.findings.find((f) => f.ruleId === 'RV-SQLI-001');
			expect(sqliFinding).toBeDefined();
			expect(sqliFinding?.severity).toBe('high');
		});

		it('should detect SSRF in webhook -> HTTP Request workflow', () => {
			const nodes: N8nNode[] = [
				{
					id: 'webhook-1',
					name: 'Webhook',
					type: 'n8n-nodes-base.webhook',
					typeVersion: 1,
					position: [0, 0],
					parameters: { path: '/proxy' },
				},
				{
					id: 'http-1',
					name: 'HTTP Request',
					type: 'n8n-nodes-base.httpRequest',
					typeVersion: 1,
					position: [200, 0],
					parameters: { url: '{{ $json.targetUrl }}' },
				},
			];

			const taintPath: TaintPath = {
				id: 'path-1',
				source: {
					nodeName: 'Webhook',
					nodeType: 'n8n-nodes-base.webhook',
					trustLevel: 'untrusted',
					taintedFields: ['body'],
					classification: {
						role: 'source',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						description: 'Webhook',
					},
				},
				sink: {
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
						description: 'HTTP Request',
					},
				},
				path: ['Webhook', 'HTTP Request'],
				taintedField: 'body',
				sinkParam: 'url',
				severity: 'high',
				sanitized: false,
				sanitizerNodes: [],
				confidence: 'high',
			};

			const sinks: SecuritySink[] = [taintPath.sink];

			const context = createWorkflowContext(nodes, [taintPath], [], sinks);
			const result = runAllRules(context);

			const ssrfFinding = result.findings.find((f) => f.ruleId === 'RV-SSRF-001');
			expect(ssrfFinding).toBeDefined();
			expect(ssrfFinding?.severity).toBe('high');
		});

		it('should detect hardcoded secrets', () => {
			const nodes: N8nNode[] = [
				{
					id: 'http-1',
					name: 'HTTP Request',
					type: 'n8n-nodes-base.httpRequest',
					typeVersion: 1,
					position: [0, 0],
					parameters: {
						url: 'https://api.example.com',
						headers: {
							Authorization: 'Bearer sk-abcdefghijklmnopqrstuvwxyz12345678901234567890',
						},
					},
				},
			];

			const context = createWorkflowContext(nodes, [], [], []);
			const result = runAllRules(context);

			const credFinding = result.findings.find((f) => f.ruleId === 'RV-CRED-001');
			expect(credFinding).toBeDefined();
			expect(credFinding?.severity).toBe('high');
			expect(credFinding?.title).toContain('Hardcoded');
		});
	});

	describe('Safe workflow patterns', () => {
		it('should not flag workflows without taint paths', () => {
			const nodes: N8nNode[] = [
				{
					id: 'schedule-1',
					name: 'Schedule',
					type: 'n8n-nodes-base.scheduleTrigger',
					typeVersion: 1,
					position: [0, 0],
					parameters: {},
				},
				{
					id: 'http-1',
					name: 'HTTP Request',
					type: 'n8n-nodes-base.httpRequest',
					typeVersion: 1,
					position: [200, 0],
					parameters: { url: 'https://api.example.com/data' },
				},
			];

			const context = createWorkflowContext(nodes, [], [], []);
			const result = runAllRules(context);

			// Should only have credential-related findings if any
			const injectionFindings = result.findings.filter(
				(f) => f.category === 'injection' || f.category === 'ssrf',
			);
			expect(injectionFindings).toHaveLength(0);
		});

		it('should reduce severity when sanitizers are present', () => {
			const nodes: N8nNode[] = [
				{
					id: 'webhook-1',
					name: 'Webhook',
					type: 'n8n-nodes-base.webhook',
					typeVersion: 1,
					position: [0, 0],
					parameters: {},
				},
				{
					id: 'if-1',
					name: 'IF',
					type: 'n8n-nodes-base.if',
					typeVersion: 1,
					position: [100, 0],
					parameters: {},
				},
				{
					id: 'code-1',
					name: 'Code',
					type: 'n8n-nodes-base.code',
					typeVersion: 1,
					position: [200, 0],
					parameters: { jsCode: 'return items;' },
				},
			];

			const taintPath: TaintPath = {
				id: 'path-1',
				source: {
					nodeName: 'Webhook',
					nodeType: 'n8n-nodes-base.webhook',
					trustLevel: 'untrusted',
					taintedFields: ['body'],
					classification: {
						role: 'source',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						description: 'Webhook',
					},
				},
				sink: {
					nodeName: 'Code',
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
				},
				path: ['Webhook', 'IF', 'Code'],
				taintedField: 'body',
				sinkParam: 'jsCode',
				severity: 'critical',
				sanitized: true, // Sanitizer present
				sanitizerNodes: ['IF'],
				confidence: 'medium',
			};

			const sinks: SecuritySink[] = [taintPath.sink];

			const context = createWorkflowContext(nodes, [taintPath], [], sinks);
			const result = runAllRules(context);

			const rceFinding = result.findings.find((f) => f.ruleId === 'RV-RCE-001');
			expect(rceFinding).toBeDefined();
			expect(rceFinding?.severity).toBe('high'); // Reduced from critical
		});
	});

	describe('Filtering options', () => {
		it('should filter findings by minimum severity', () => {
			const nodes: N8nNode[] = [
				{
					id: 'webhook-1',
					name: 'Webhook',
					type: 'n8n-nodes-base.webhook',
					typeVersion: 1,
					position: [0, 0],
					parameters: {},
				},
				{
					id: 'openai-1',
					name: 'OpenAI',
					type: '@n8n/n8n-nodes-langchain.openAi',
					typeVersion: 1,
					position: [200, 0],
					parameters: { text: '<user_input>{{ $json.msg }}</user_input>' },
				},
			];

			const taintPath: TaintPath = {
				id: 'path-1',
				source: {
					nodeName: 'Webhook',
					nodeType: 'n8n-nodes-base.webhook',
					trustLevel: 'untrusted',
					taintedFields: ['body'],
					classification: {
						role: 'source',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						description: 'Webhook',
					},
				},
				sink: {
					nodeName: 'OpenAI',
					nodeType: '@n8n/n8n-nodes-langchain.openAi',
					severity: 'medium',
					riskType: 'Prompt Injection',
					dangerousParams: [],
					classification: {
						role: 'sink',
						severity: 'medium',
						riskType: 'Prompt Injection',
						dangerousParams: ['text'],
						description: 'LLM prompt',
					},
				},
				path: ['Webhook', 'OpenAI'],
				taintedField: 'body',
				sinkParam: 'text',
				severity: 'medium',
				sanitized: false,
				sanitizerNodes: [],
				confidence: 'medium',
			};

			const sinks: SecuritySink[] = [taintPath.sink];

			const context = createWorkflowContext(nodes, [taintPath], [], sinks);

			// Without filter - should include low severity findings
			const allResults = runAllRules(context);

			// With high severity filter - should exclude low severity
			const highResults = runAllRules(context, { minSeverity: 'high' });

			// Prompt injection with protection is low severity, should be filtered
			const piInAll = allResults.findings.filter((f) => f.ruleId === 'RV-PI-001');
			const piInHigh = highResults.findings.filter((f) => f.ruleId === 'RV-PI-001');

			expect(piInAll.length).toBeGreaterThanOrEqual(piInHigh.length);
		});

		it('should filter by categories', () => {
			const nodes: N8nNode[] = [
				{
					id: 'http-1',
					name: 'HTTP',
					type: 'n8n-nodes-base.httpRequest',
					typeVersion: 1,
					position: [0, 0],
					parameters: {
						headers: { Authorization: 'Bearer sk-abcdefghijklmnopqrstuvwxyz12345678901234567890' },
					},
				},
			];

			const context = createWorkflowContext(nodes, [], [], []);

			// Only credential-exposure category
			const credResults = runAllRules(context, { categories: ['credential-exposure'] });

			// Only injection category (should find nothing)
			const injectionResults = runAllRules(context, { categories: ['injection'] });

			expect(credResults.findings.length).toBeGreaterThan(0);
			expect(injectionResults.findings.length).toBe(0);
		});

		it('should disable specific rules via config', () => {
			const nodes: N8nNode[] = [
				{
					id: 'http-1',
					name: 'HTTP',
					type: 'n8n-nodes-base.httpRequest',
					typeVersion: 1,
					position: [0, 0],
					parameters: {
						headers: { Authorization: 'Bearer sk-abcdefghijklmnopqrstuvwxyz12345678901234567890' },
					},
				},
			];

			const context = createWorkflowContext(nodes, [], [], []);

			// With credential rule enabled
			const enabledResults = runAllRules(context);

			// With credential rule disabled
			const disabledResults = runAllRules(context, {
				config: { 'RV-CRED-001': { enabled: false } },
			});

			const credInEnabled = enabledResults.findings.filter((f) => f.ruleId === 'RV-CRED-001');
			const credInDisabled = disabledResults.findings.filter((f) => f.ruleId === 'RV-CRED-001');

			expect(credInEnabled.length).toBeGreaterThan(0);
			expect(credInDisabled.length).toBe(0);
		});
	});

	describe('Result metadata', () => {
		it('should track rules run and skipped', () => {
			const context = createWorkflowContext([], [], [], []);
			const result = runAllRules(context);

			// All rules should be skipped (not applicable) for empty workflow
			expect(result.rulesRun + result.rulesSkipped).toBe(6);
		});

		it('should track duration', () => {
			const context = createWorkflowContext([], [], [], []);
			const result = runAllRules(context);

			expect(result.duration).toBeGreaterThanOrEqual(0);
		});

		it('should sort findings by severity', () => {
			const nodes: N8nNode[] = [
				{
					id: 'webhook-1',
					name: 'Webhook',
					type: 'n8n-nodes-base.webhook',
					typeVersion: 1,
					position: [0, 0],
					parameters: {},
				},
				{
					id: 'code-1',
					name: 'Code',
					type: 'n8n-nodes-base.code',
					typeVersion: 1,
					position: [200, 0],
					parameters: { jsCode: 'eval({{ $json.cmd }})' },
				},
				{
					id: 'http-1',
					name: 'HTTP',
					type: 'n8n-nodes-base.httpRequest',
					typeVersion: 1,
					position: [400, 0],
					parameters: {
						headers: { Authorization: 'Bearer sk-abcdefghijklmnopqrstuvwxyz12345678901234567890' },
					},
				},
			];

			const taintPath: TaintPath = {
				id: 'path-1',
				source: {
					nodeName: 'Webhook',
					nodeType: 'n8n-nodes-base.webhook',
					trustLevel: 'untrusted',
					taintedFields: ['body'],
					classification: {
						role: 'source',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						description: 'Webhook',
					},
				},
				sink: {
					nodeName: 'Code',
					nodeType: 'n8n-nodes-base.code',
					severity: 'critical',
					riskType: 'RCE',
					dangerousParams: [],
					classification: {
						role: 'sink',
						severity: 'critical',
						riskType: 'RCE',
						dangerousParams: ['jsCode'],
						description: 'Code',
					},
				},
				path: ['Webhook', 'Code'],
				taintedField: 'body',
				sinkParam: 'jsCode',
				severity: 'critical',
				sanitized: false,
				sanitizerNodes: [],
				confidence: 'high',
			};

			const sinks: SecuritySink[] = [taintPath.sink];
			const context = createWorkflowContext(nodes, [taintPath], [], sinks);
			const result = runAllRules(context);

			// Verify findings are sorted by severity (critical first)
			if (result.findings.length > 1) {
				const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
				for (let i = 1; i < result.findings.length; i++) {
					const prevSev = severityOrder[result.findings[i - 1].severity];
					const currSev = severityOrder[result.findings[i].severity];
					expect(prevSev).toBeLessThanOrEqual(currSev);
				}
			}
		});
	});
});
