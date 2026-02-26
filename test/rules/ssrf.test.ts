/**
 * Tests for SSRF Detection Rule
 */

import { SsrfRule } from '../../nodes/RiskVoid/rules/ssrf';
import type { RuleContext } from '../../nodes/RiskVoid/rules/types';
import type { TaintPath, SecuritySink } from '../../nodes/RiskVoid/types/taint';
import type { ParsedWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import type { WorkflowGraph } from '../../nodes/RiskVoid/types/graph';
import type { N8nNode } from '../../nodes/RiskVoid/types/workflow';

describe('SsrfRule', () => {
	let rule: SsrfRule;

	beforeEach(() => {
		rule = new SsrfRule();
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

	// Helper to create HTTP Request node
	function createHttpNode(name: string, url: string): N8nNode {
		return {
			id: `node-${name}`,
			name,
			type: 'n8n-nodes-base.httpRequest',
			typeVersion: 1,
			position: [0, 0],
			parameters: {
				url,
				method: 'GET',
			},
		};
	}

	// Helper to create a taint path to HTTP Request node
	function createTaintPath(sourceName: string, sinkName: string, sanitized = false): TaintPath {
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
				nodeType: 'n8n-nodes-base.httpRequest',
				severity: 'high',
				riskType: 'SSRF',
				dangerousParams: [{ paramPath: 'url', value: '', hasExpressions: true, expressions: [] }],
				classification: {
					role: 'sink',
					severity: 'high',
					riskType: 'SSRF',
					dangerousParams: ['url'],
					description: 'HTTP Request sink',
				},
			},
			path: [sourceName, sinkName],
			taintedField: 'body',
			sinkParam: 'url',
			severity: 'high',
			sanitized,
			sanitizerNodes: sanitized ? ['IF Node'] : [],
			confidence: 'high',
		};
	}

	// Helper to create SSRF sink
	function createSsrfSink(nodeName: string): SecuritySink {
		return {
			nodeName,
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
		};
	}

	describe('metadata', () => {
		it('should have correct rule ID', () => {
			expect(rule.metadata.id).toBe('RV-SSRF-001');
		});

		it('should have high severity', () => {
			expect(rule.metadata.severity).toBe('high');
		});

		it('should have ssrf category', () => {
			expect(rule.metadata.category).toBe('ssrf');
		});

		it('should have CWE reference', () => {
			expect(rule.metadata.references.cwe).toBe('CWE-918');
		});

		it('should have OWASP reference', () => {
			expect(rule.metadata.references.owasp).toBe('A10:2021-SSRF');
		});
	});

	describe('isApplicable', () => {
		it('should return true when SSRF sinks exist', () => {
			const context = createMockContext(
				[createHttpNode('HTTP', 'https://example.com')],
				[],
				[createSsrfSink('HTTP')],
			);

			expect(rule.isApplicable(context)).toBe(true);
		});

		it('should return false when no SSRF sinks exist', () => {
			const context = createMockContext([], [], []);
			expect(rule.isApplicable(context)).toBe(false);
		});
	});

	describe('detect', () => {
		it('should detect taint flow to HTTP Request URL', () => {
			const httpNode = createHttpNode('HTTP', '{{ $json.targetUrl }}');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('high');
		});

		it('should detect localhost patterns', () => {
			const httpNode = createHttpNode('HTTP', 'http://127.0.0.1:8080/admin');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].confidence).toBe('high');
			expect(findings[0].metadata.internalPatterns).toContain('localhost (127.x.x.x)');
		});

		it('should detect localhost hostname', () => {
			const httpNode = createHttpNode('HTTP', 'http://localhost:3000/api');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.internalPatterns).toContain('localhost');
		});

		it('should detect private Class A IP (10.x.x.x)', () => {
			const httpNode = createHttpNode('HTTP', 'http://10.0.0.1/internal');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.internalPatterns).toContain('private Class A (10.x.x.x)');
		});

		it('should detect private Class B IP (172.16-31.x.x)', () => {
			const httpNode = createHttpNode('HTTP', 'http://172.16.0.1/internal');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.internalPatterns).toContain('private Class B (172.16-31.x.x)');
		});

		it('should detect private Class C IP (192.168.x.x)', () => {
			const httpNode = createHttpNode('HTTP', 'http://192.168.1.1/router');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.internalPatterns).toContain('private Class C (192.168.x.x)');
		});

		it('should detect AWS metadata endpoint with critical severity', () => {
			const httpNode = createHttpNode('HTTP', 'http://169.254.169.254/latest/meta-data/');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('critical'); // elevated due to metadata
			expect(findings[0].metadata.metadataPatterns).toContain('AWS/GCP metadata endpoint');
		});

		it('should detect Google Cloud metadata', () => {
			const httpNode = createHttpNode('HTTP', 'http://metadata.google.internal/');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.metadataPatterns).toContain('Google Cloud metadata');
		});

		it('should detect file:// protocol bypass', () => {
			const httpNode = createHttpNode('HTTP', 'file:///etc/passwd');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.bypassPatterns).toContain('file:// protocol');
		});

		it('should detect gopher:// protocol bypass', () => {
			const httpNode = createHttpNode('HTTP', 'gopher://internal:80/_GET%20/');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.bypassPatterns).toContain('gopher:// protocol');
		});

		it('should suppress findings when path is fully sanitized', () => {
			const httpNode = createHttpNode('HTTP', '{{ $json.url }}');
			const taintPath = createTaintPath('Webhook', 'HTTP', true); // sanitized
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			// Sanitized paths are filtered out entirely
			expect(findings).toHaveLength(0);
		});

		it('should include cloud metadata warning in description', () => {
			const httpNode = createHttpNode('HTTP', '{{ $json.url }}');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings[0].description).toContain('169.254.169.254');
		});

		it('should include remediation guidance', () => {
			const httpNode = createHttpNode('HTTP', '{{ $json.url }}');
			const taintPath = createTaintPath('Webhook', 'HTTP');
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings[0].remediation.summary).toContain('allowlist');
			expect(findings[0].remediation.steps.length).toBeGreaterThan(0);
			expect(findings[0].remediation.safePattern).toContain('allowedDomains');
		});

		it('should return empty array when no taint paths to HTTP nodes', () => {
			const httpNode = createHttpNode('HTTP', 'https://api.example.com');
			const context = createMockContext([httpNode], [], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(0);
		});

		it('should track the path from source to sink', () => {
			const httpNode = createHttpNode('HTTP', '{{ $json.url }}');
			const taintPath: TaintPath = {
				...createTaintPath('Webhook', 'HTTP'),
				path: ['Webhook', 'Set', 'HTTP'],
			};
			const context = createMockContext([httpNode], [taintPath], [createSsrfSink('HTTP')]);

			const findings = rule.detect(context);

			expect(findings[0].path).toEqual(['Webhook', 'Set', 'HTTP']);
		});
	});
});
