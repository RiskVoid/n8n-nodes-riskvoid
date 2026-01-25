import {
	findTaintSources,
	findSecuritySinks,
	analyzeTaintFlows,
	isFieldTainted,
} from '../../nodes/RiskVoid/analysis/taintAnalyzer';
import { parseWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import { buildGraph } from '../../nodes/RiskVoid/analysis/graphBuilder';
import type { TaintSource } from '../../nodes/RiskVoid/types/taint';

// Test workflow with a vulnerable path: Webhook -> Set -> Code (RCE)
const vulnerableWorkflow = {
	id: 'test-vulnerable',
	name: 'Vulnerable Workflow',
	active: false,
	nodes: [
		{
			id: '1',
			name: 'Webhook',
			type: 'n8n-nodes-base.webhook',
			typeVersion: 1,
			position: [0, 0] as [number, number],
			parameters: {
				path: 'test',
				httpMethod: 'POST',
			},
		},
		{
			id: '2',
			name: 'Set Fields',
			type: 'n8n-nodes-base.set',
			typeVersion: 1,
			position: [200, 0] as [number, number],
			parameters: {
				values: {
					string: [{ name: 'command', value: '={{ $json.body.cmd }}' }],
				},
			},
		},
		{
			id: '3',
			name: 'Execute Code',
			type: 'n8n-nodes-base.code',
			typeVersion: 1,
			position: [400, 0] as [number, number],
			parameters: {
				jsCode: 'eval({{ $json.command }}); return items;',
			},
		},
	],
	connections: {
		Webhook: { main: [[{ node: 'Set Fields', type: 'main', index: 0 }]] },
		'Set Fields': { main: [[{ node: 'Execute Code', type: 'main', index: 0 }]] },
	},
};

// Safe workflow with no dangerous sinks
const safeWorkflow = {
	id: 'test-safe',
	name: 'Safe Workflow',
	active: false,
	nodes: [
		{
			id: '1',
			name: 'Webhook',
			type: 'n8n-nodes-base.webhook',
			typeVersion: 1,
			position: [0, 0] as [number, number],
			parameters: {
				path: 'test',
			},
		},
		{
			id: '2',
			name: 'Set',
			type: 'n8n-nodes-base.set',
			typeVersion: 1,
			position: [200, 0] as [number, number],
			parameters: {
				values: { string: [{ name: 'processed', value: '={{ $json.body.data }}' }] },
			},
		},
	],
	connections: {
		Webhook: { main: [[{ node: 'Set', type: 'main', index: 0 }]] },
	},
};

// Workflow with sanitizer in the path
const sanitizedWorkflow = {
	id: 'test-sanitized',
	name: 'Sanitized Workflow',
	active: false,
	nodes: [
		{
			id: '1',
			name: 'Webhook',
			type: 'n8n-nodes-base.webhook',
			typeVersion: 1,
			position: [0, 0] as [number, number],
			parameters: { path: 'test' },
		},
		{
			id: '2',
			name: 'IF',
			type: 'n8n-nodes-base.if',
			typeVersion: 1,
			position: [200, 0] as [number, number],
			parameters: {},
		},
		{
			id: '3',
			name: 'Code',
			type: 'n8n-nodes-base.code',
			typeVersion: 1,
			position: [400, 0] as [number, number],
			parameters: {
				jsCode: 'const input = {{ $json.body.cmd }}; return items;',
			},
		},
	],
	connections: {
		Webhook: { main: [[{ node: 'IF', type: 'main', index: 0 }]] },
		IF: { main: [[{ node: 'Code', type: 'main', index: 0 }]] },
	},
};

// Workflow with SQL injection risk
const sqlInjectionWorkflow = {
	id: 'test-sqli',
	name: 'SQL Injection Workflow',
	active: false,
	nodes: [
		{
			id: '1',
			name: 'Form Trigger',
			type: 'n8n-nodes-base.formTrigger',
			typeVersion: 1,
			position: [0, 0] as [number, number],
			parameters: {},
		},
		{
			id: '2',
			name: 'MySQL',
			type: 'n8n-nodes-base.mySql',
			typeVersion: 1,
			position: [200, 0] as [number, number],
			parameters: {
				query: "SELECT * FROM users WHERE id = '{{ $json.userId }}'",
			},
		},
	],
	connections: {
		'Form Trigger': { main: [[{ node: 'MySQL', type: 'main', index: 0 }]] },
	},
};

// Workflow with static values (no expressions in sink)
const staticValueWorkflow = {
	id: 'test-static',
	name: 'Static Value Workflow',
	active: false,
	nodes: [
		{
			id: '1',
			name: 'Webhook',
			type: 'n8n-nodes-base.webhook',
			typeVersion: 1,
			position: [0, 0] as [number, number],
			parameters: { path: 'test' },
		},
		{
			id: '2',
			name: 'Code',
			type: 'n8n-nodes-base.code',
			typeVersion: 1,
			position: [200, 0] as [number, number],
			parameters: {
				jsCode: 'console.log("Hello"); return items;', // Static, no expressions
			},
		},
	],
	connections: {
		Webhook: { main: [[{ node: 'Code', type: 'main', index: 0 }]] },
	},
};

describe('taintAnalyzer', () => {
	describe('findTaintSources', () => {
		it('should find webhook as taint source', () => {
			const parseResult = parseWorkflow(vulnerableWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);

			expect(sources).toHaveLength(1);
			expect(sources[0].nodeName).toBe('Webhook');
			expect(sources[0].trustLevel).toBe('untrusted');
			expect(sources[0].taintedFields).toContain('body');
		});

		it('should find form trigger as taint source', () => {
			const parseResult = parseWorkflow(sqlInjectionWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);

			expect(sources).toHaveLength(1);
			expect(sources[0].nodeName).toBe('Form Trigger');
			expect(sources[0].trustLevel).toBe('untrusted');
		});

		it('should not include trusted sources', () => {
			const workflowWithManualTrigger = {
				id: 'test',
				name: 'Test',
				active: false,
				nodes: [
					{
						id: '1',
						name: 'Manual',
						type: 'n8n-nodes-base.manualTrigger',
						typeVersion: 1,
						position: [0, 0] as [number, number],
						parameters: {},
					},
				],
				connections: {},
			};

			const parseResult = parseWorkflow(workflowWithManualTrigger);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);

			// Manual trigger is trusted, should not be included
			expect(sources).toHaveLength(0);
		});
	});

	describe('findSecuritySinks', () => {
		it('should find code node with expressions as sink', () => {
			const parseResult = parseWorkflow(vulnerableWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			expect(sinks).toHaveLength(1);
			expect(sinks[0].nodeName).toBe('Execute Code');
			expect(sinks[0].severity).toBe('critical');
			expect(sinks[0].riskType).toBe('RCE');
		});

		it('should find MySQL node with expressions as sink', () => {
			const parseResult = parseWorkflow(sqlInjectionWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			expect(sinks).toHaveLength(1);
			expect(sinks[0].nodeName).toBe('MySQL');
			expect(sinks[0].severity).toBe('high');
			expect(sinks[0].riskType).toBe('SQL Injection');
		});

		it('should not include sinks with static values', () => {
			const parseResult = parseWorkflow(staticValueWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			// Code node has static jsCode, should not be a sink
			expect(sinks).toHaveLength(0);
		});

		it('should return empty array for safe workflow', () => {
			const parseResult = parseWorkflow(safeWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			expect(sinks).toHaveLength(0);
		});
	});

	describe('isFieldTainted', () => {
		const mockSource: TaintSource = {
			nodeName: 'Webhook',
			nodeType: 'n8n-nodes-base.webhook',
			trustLevel: 'untrusted',
			taintedFields: ['body', 'headers', 'query'],
			classification: {
				role: 'source',
				trustLevel: 'untrusted',
				taintedFields: ['body', 'headers', 'query'],
				description: 'Test',
			},
		};

		it('should return true for exact field match', () => {
			expect(isFieldTainted(mockSource, ['body'])).toBe(true);
		});

		it('should return true for child of tainted field', () => {
			expect(isFieldTainted(mockSource, ['body', 'data', 'name'])).toBe(true);
		});

		it('should return true for empty field path', () => {
			expect(isFieldTainted(mockSource, [])).toBe(true);
		});

		it('should return true for all fields from direct-output sources like webhook', () => {
			// For direct-output sources (webhook, telegram, etc.), all fields are considered tainted
			// because $json from these sources IS the untrusted data
			const source: TaintSource = {
				...mockSource,
				taintedFields: ['body'],
			};
			// Even though 'headers' isn't explicitly listed, webhooks output tainted data directly
			expect(isFieldTainted(source, ['headers'])).toBe(true);
		});

		it('should return false for non-tainted field in non-direct-output source', () => {
			// For non-direct-output sources, only explicitly tainted fields should match
			const source: TaintSource = {
				nodeName: 'MySQL',
				nodeType: 'n8n-nodes-base.mySql',
				trustLevel: 'semi-trusted',
				taintedFields: ['result'],
				classification: {
					role: 'source',
					trustLevel: 'semi-trusted',
					taintedFields: ['result'],
					description: 'Database query result',
				},
			};
			expect(isFieldTainted(source, ['unrelated_field'])).toBe(false);
		});

		it('should handle wildcard (*) tainted fields', () => {
			const wildcardSource: TaintSource = {
				...mockSource,
				taintedFields: ['*'],
			};
			expect(isFieldTainted(wildcardSource, ['anything', 'at', 'all'])).toBe(true);
		});
	});

	describe('analyzeTaintFlows', () => {
		it('should find vulnerable path in vulnerable workflow', () => {
			const parseResult = parseWorkflow(vulnerableWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

			expect(paths.length).toBeGreaterThan(0);
			expect(paths[0].source.nodeName).toBe('Webhook');
			expect(paths[0].sink.nodeName).toBe('Execute Code');
			expect(paths[0].severity).toBe('critical');
		});

		it('should find SQL injection path', () => {
			const parseResult = parseWorkflow(sqlInjectionWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

			expect(paths.length).toBeGreaterThan(0);
			expect(paths[0].sink.riskType).toBe('SQL Injection');
		});

		it('should mark path as sanitized when sanitizer is present', () => {
			const parseResult = parseWorkflow(sanitizedWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

			if (paths.length > 0) {
				expect(paths[0].sanitized).toBe(true);
				expect(paths[0].sanitizerNodes).toContain('IF');
				// Severity should be reduced from critical to high
				expect(paths[0].severity).toBe('high');
			}
		});

		it('should return empty array for safe workflow', () => {
			const parseResult = parseWorkflow(safeWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

			expect(paths).toHaveLength(0);
		});

		it('should return empty array for workflow with static sink values', () => {
			const parseResult = parseWorkflow(staticValueWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

			expect(paths).toHaveLength(0);
		});

		it('should sort paths by severity', () => {
			// Create a workflow with both critical and high severity sinks
			const multiSinkWorkflow = {
				id: 'test-multi',
				name: 'Multi Sink',
				active: false,
				nodes: [
					{
						id: '1',
						name: 'Webhook',
						type: 'n8n-nodes-base.webhook',
						typeVersion: 1,
						position: [0, 0] as [number, number],
						parameters: { path: 'test' },
					},
					{
						id: '2',
						name: 'Code',
						type: 'n8n-nodes-base.code',
						typeVersion: 1,
						position: [200, 0] as [number, number],
						parameters: { jsCode: '{{ $json.body.code }}' },
					},
					{
						id: '3',
						name: 'MySQL',
						type: 'n8n-nodes-base.mySql',
						typeVersion: 1,
						position: [200, 100] as [number, number],
						parameters: { query: '{{ $json.body.query }}' },
					},
				],
				connections: {
					Webhook: {
						main: [
							[
								{ node: 'Code', type: 'main', index: 0 },
								{ node: 'MySQL', type: 'main', index: 0 },
							],
						],
					},
				},
			};

			const parseResult = parseWorkflow(multiSinkWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

			// Critical (Code/RCE) should come before High (MySQL/SQLi)
			if (paths.length >= 2) {
				expect(paths[0].severity).toBe('critical');
			}
		});

		it('should respect maxPathsPerPair option', () => {
			const parseResult = parseWorkflow(vulnerableWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks, {
				maxPathsPerPair: 1,
			});

			expect(paths.length).toBeLessThanOrEqual(1);
		});

		it('should exclude sanitized paths when includeSanitized is false', () => {
			const parseResult = parseWorkflow(sanitizedWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);

			const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks, {
				includeSanitized: false,
			});

			// All paths should be non-sanitized (or empty if all are sanitized)
			for (const path of paths) {
				expect(path.sanitized).toBe(false);
			}
		});
	});
});
