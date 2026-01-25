/**
 * Tests for Credential Exposure Detection Rule
 */

import { CredentialExposureRule } from '../../nodes/RiskVoid/rules/credentialExposure';
import type { RuleContext } from '../../nodes/RiskVoid/rules/types';
import type { ParsedWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import type { WorkflowGraph } from '../../nodes/RiskVoid/types/graph';
import type { N8nNode } from '../../nodes/RiskVoid/types/workflow';

describe('CredentialExposureRule', () => {
	let rule: CredentialExposureRule;

	beforeEach(() => {
		rule = new CredentialExposureRule();
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
				usesCredentials: nodes.some((n) => n.credentials),
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
	function createMockContext(nodes: N8nNode[]): RuleContext {
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
			sinks: [],
			taintPaths: [],
		};
	}

	// Helper to create a generic node
	function createNode(
		name: string,
		type: string,
		parameters: Record<string, unknown> = {},
		credentials?: Record<string, { id: string; name: string }>,
	): N8nNode {
		return {
			id: `node-${name}`,
			name,
			type,
			typeVersion: 1,
			position: [0, 0],
			parameters,
			credentials,
		};
	}

	describe('metadata', () => {
		it('should have correct rule ID', () => {
			expect(rule.metadata.id).toBe('RV-CRED-001');
		});

		it('should have medium severity', () => {
			expect(rule.metadata.severity).toBe('medium');
		});

		it('should have credential-exposure category', () => {
			expect(rule.metadata.category).toBe('credential-exposure');
		});

		it('should have CWE reference', () => {
			expect(rule.metadata.references.cwe).toBe('CWE-200');
		});
	});

	describe('isApplicable', () => {
		it('should return true when nodes have credentials', () => {
			const context = createMockContext([
				createNode('HTTP', 'n8n-nodes-base.httpRequest', {}, {
					httpBasicAuth: { id: '123', name: 'My Auth' },
				}),
			]);

			expect(rule.isApplicable(context)).toBe(true);
		});

		it('should return true when nodes have credential-like parameters', () => {
			const context = createMockContext([
				createNode('Set', 'n8n-nodes-base.set', {
					values: {
						string: [{ name: 'apiKey', value: 'test' }],
					},
				}),
			]);

			expect(rule.isApplicable(context)).toBe(true);
		});

		it('should return false when no credential patterns exist', () => {
			const context = createMockContext([
				createNode('Set', 'n8n-nodes-base.set', {
					values: {
						string: [{ name: 'name', value: 'John' }],
					},
				}),
			]);

			expect(rule.isApplicable(context)).toBe(false);
		});
	});

	describe('detect - hardcoded secrets', () => {
		it('should detect hardcoded OpenAI API key', () => {
			const context = createMockContext([
				createNode('HTTP', 'n8n-nodes-base.httpRequest', {
					headers: {
						Authorization: 'Bearer sk-abcdefghijklmnopqrstuvwxyz12345678901234567890',
					},
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const hardcodedFinding = findings.find((f) => f.metadata.type === 'hardcoded-secret');
			expect(hardcodedFinding).toBeDefined();
			expect(hardcodedFinding?.severity).toBe('high');
			expect(hardcodedFinding?.metadata.secretType).toBe('OpenAI API key');
		});

		it('should detect hardcoded GitHub token', () => {
			// Use string concatenation to avoid triggering GitHub's secret scanner
			const fakeGithubToken = 'gh' + 'p_EXAMPLEFAKETESTTOKEN1234567890ABCDEF';
			const context = createMockContext([
				createNode('Code', 'n8n-nodes-base.code', {
					jsCode: `const token = "${fakeGithubToken}";`,
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const hardcodedFinding = findings.find((f) => f.metadata.type === 'hardcoded-secret');
			expect(hardcodedFinding).toBeDefined();
			expect(hardcodedFinding?.metadata.secretType).toBe('GitHub Personal Access Token');
		});

		it('should detect hardcoded Slack token', () => {
			const context = createMockContext([
				createNode('Set', 'n8n-nodes-base.set', {
					token: 'xoxb-123456789-abcdefghij',
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const hardcodedFinding = findings.find((f) => f.metadata.type === 'hardcoded-secret');
			expect(hardcodedFinding).toBeDefined();
			expect(hardcodedFinding?.metadata.secretType).toBe('Slack Token');
		});

		it('should detect hardcoded AWS Access Key ID', () => {
			const context = createMockContext([
				createNode('Set', 'n8n-nodes-base.set', {
					awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const hardcodedFinding = findings.find((f) => f.metadata.type === 'hardcoded-secret');
			expect(hardcodedFinding).toBeDefined();
			expect(hardcodedFinding?.metadata.secretType).toBe('AWS Access Key ID');
		});

		it('should detect hardcoded Stripe key', () => {
			// Use string concatenation to avoid triggering GitHub's secret scanner
			const fakeStripeKey = 'sk_' + 'live_EXAMPLEFAKETESTKEY1234567';
			const context = createMockContext([
				createNode('HTTP', 'n8n-nodes-base.httpRequest', {
					apiKey: fakeStripeKey,
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const hardcodedFinding = findings.find((f) => f.metadata.type === 'hardcoded-secret');
			expect(hardcodedFinding).toBeDefined();
			expect(hardcodedFinding?.metadata.secretType).toBe('Stripe Live Secret Key');
		});

		it('should detect JWT tokens', () => {
			const context = createMockContext([
				createNode('Set', 'n8n-nodes-base.set', {
					jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const hardcodedFinding = findings.find((f) => f.metadata.type === 'hardcoded-secret');
			expect(hardcodedFinding).toBeDefined();
			expect(hardcodedFinding?.metadata.secretType).toBe('JWT Token');
		});

		it('should include remediation for hardcoded secrets', () => {
			const context = createMockContext([
				createNode('HTTP', 'n8n-nodes-base.httpRequest', {
					headers: {
						Authorization: 'Bearer sk-abcdefghijklmnopqrstuvwxyz12345678901234567890',
					},
				}),
			]);

			const findings = rule.detect(context);
			const hardcodedFinding = findings.find((f) => f.metadata.type === 'hardcoded-secret');

			expect(hardcodedFinding?.remediation.summary).toContain('credential');
			expect(hardcodedFinding?.remediation.steps.some((s) => s.includes('Rotate'))).toBe(true);
		});
	});

	describe('detect - credential exposure in outputs', () => {
		it('should detect credential fields in HTTP Request', () => {
			const context = createMockContext([
				createNode('HTTP', 'n8n-nodes-base.httpRequest', {
					body: '{{ $json.password }}',
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const exposureFinding = findings.find((f) => f.metadata.type === 'potential-exposure');
			expect(exposureFinding).toBeDefined();
			expect(exposureFinding?.severity).toBe('medium');
		});

		it('should detect credential fields in Slack node', () => {
			const context = createMockContext([
				createNode('Slack', 'n8n-nodes-base.slack', {
					text: 'API Key: {{ $json.apiKey }}',
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const exposureFinding = findings.find((f) => f.metadata.type === 'potential-exposure');
			expect(exposureFinding).toBeDefined();
		});

		it('should detect credential fields in email', () => {
			const context = createMockContext([
				createNode('Email', 'n8n-nodes-base.emailSend', {
					body: 'Your token is: {{ $json.secret_token }}',
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const exposureFinding = findings.find((f) => f.metadata.type === 'potential-exposure');
			expect(exposureFinding).toBeDefined();
		});

		it('should detect credential expressions in webhooks', () => {
			const context = createMockContext([
				createNode('Respond', 'n8n-nodes-base.respondToWebhook', {
					responseBody: '{{ $json.authorization }}',
				}),
			]);

			const findings = rule.detect(context);

			expect(findings.length).toBeGreaterThan(0);
			const exposureFinding = findings.find((f) => f.metadata.type === 'potential-exposure');
			expect(exposureFinding).toBeDefined();
		});

		it('should include remediation for exposure findings', () => {
			const context = createMockContext([
				createNode('HTTP', 'n8n-nodes-base.httpRequest', {
					body: '{{ $json.password }}',
				}),
			]);

			const findings = rule.detect(context);
			const exposureFinding = findings.find((f) => f.metadata.type === 'potential-exposure');

			expect(exposureFinding?.remediation.summary).toContain('sensitive data');
			expect(exposureFinding?.remediation.steps.length).toBeGreaterThan(0);
		});

		it('should not flag nodes without credential patterns', () => {
			const context = createMockContext([
				createNode('HTTP', 'n8n-nodes-base.httpRequest', {
					body: '{{ $json.name }}',
				}),
			]);

			const findings = rule.detect(context);
			const exposureFinding = findings.find((f) => f.metadata.type === 'potential-exposure');

			expect(exposureFinding).toBeUndefined();
		});
	});

	describe('detect - multiple issues', () => {
		it('should detect both hardcoded secrets and exposure', () => {
			const context = createMockContext([
				createNode('Code', 'n8n-nodes-base.code', {
					jsCode: 'const key = "sk-abcdefghijklmnopqrstuvwxyz12345678901234567890";',
				}),
				createNode('HTTP', 'n8n-nodes-base.httpRequest', {
					body: '{{ $json.password }}',
				}),
			]);

			const findings = rule.detect(context);

			const hardcodedFinding = findings.find((f) => f.metadata.type === 'hardcoded-secret');
			const exposureFinding = findings.find((f) => f.metadata.type === 'potential-exposure');

			expect(hardcodedFinding).toBeDefined();
			expect(exposureFinding).toBeDefined();
		});
	});
});
