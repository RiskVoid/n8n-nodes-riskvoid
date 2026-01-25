/**
 * Tests for Prompt Injection Detection Rule
 */

import { PromptInjectionRule } from '../../nodes/RiskVoid/rules/promptInjection';
import type { RuleContext } from '../../nodes/RiskVoid/rules/types';
import type { TaintPath, SecuritySink } from '../../nodes/RiskVoid/types/taint';
import type { ParsedWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import type { WorkflowGraph } from '../../nodes/RiskVoid/types/graph';
import type { N8nNode } from '../../nodes/RiskVoid/types/workflow';

describe('PromptInjectionRule', () => {
	let rule: PromptInjectionRule;

	beforeEach(() => {
		rule = new PromptInjectionRule();
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

	// Helper to create OpenAI node
	function createOpenAiNode(name: string, prompt: string): N8nNode {
		return {
			id: `node-${name}`,
			name,
			type: '@n8n/n8n-nodes-langchain.openAi',
			typeVersion: 1,
			position: [0, 0],
			parameters: {
				text: prompt,
			},
		};
	}

	// Helper to create Anthropic node
	function createAnthropicNode(name: string, prompt: string): N8nNode {
		return {
			id: `node-${name}`,
			name,
			type: '@n8n/n8n-nodes-langchain.anthropic',
			typeVersion: 1,
			position: [0, 0],
			parameters: {
				prompt,
			},
		};
	}

	// Helper to create a taint path to LLM node
	function createTaintPath(
		sourceName: string,
		sinkName: string,
		sinkType = '@n8n/n8n-nodes-langchain.openAi',
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
				nodeType: sinkType,
				severity: 'medium',
				riskType: 'Prompt Injection',
				dangerousParams: [{ paramPath: 'text', value: '', hasExpressions: true, expressions: [] }],
				classification: {
					role: 'sink',
					severity: 'medium',
					riskType: 'Prompt Injection',
					dangerousParams: ['text', 'prompt'],
					description: 'LLM prompt',
				},
			},
			path: [sourceName, sinkName],
			taintedField: 'body',
			sinkParam: 'text',
			severity: 'medium',
			sanitized,
			sanitizerNodes: sanitized ? ['IF Node'] : [],
			confidence: 'medium',
		};
	}

	// Helper to create Prompt Injection sink
	function createPromptSink(
		nodeName: string,
		nodeType = '@n8n/n8n-nodes-langchain.openAi',
	): SecuritySink {
		return {
			nodeName,
			nodeType,
			severity: 'medium',
			riskType: 'Prompt Injection',
			dangerousParams: [],
			classification: {
				role: 'sink',
				severity: 'medium',
				riskType: 'Prompt Injection',
				dangerousParams: ['text', 'prompt'],
				description: 'LLM prompt',
			},
		};
	}

	describe('metadata', () => {
		it('should have correct rule ID', () => {
			expect(rule.metadata.id).toBe('RV-PI-001');
		});

		it('should have medium severity', () => {
			expect(rule.metadata.severity).toBe('medium');
		});

		it('should have prompt-injection category', () => {
			expect(rule.metadata.category).toBe('prompt-injection');
		});

		it('should have OWASP LLM reference', () => {
			expect(rule.metadata.references.owasp).toBe('LLM01:2023-Prompt-Injection');
		});
	});

	describe('isApplicable', () => {
		it('should return true when Prompt Injection sinks exist', () => {
			const context = createMockContext(
				[createOpenAiNode('OpenAI', 'Hello')],
				[],
				[createPromptSink('OpenAI')],
			);

			expect(rule.isApplicable(context)).toBe(true);
		});

		it('should return false when no Prompt Injection sinks exist', () => {
			const context = createMockContext([], [], []);
			expect(rule.isApplicable(context)).toBe(false);
		});
	});

	describe('detect', () => {
		it('should detect taint flow to OpenAI prompt', () => {
			const llmNode = createOpenAiNode('OpenAI', 'Answer this: {{ $json.question }}');
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.llmProvider).toBe('OpenAI');
		});

		it('should detect direct variable injection as high risk', () => {
			const llmNode = createOpenAiNode('OpenAI', '{{ $json.userMessage }}');
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('high');
			expect(findings[0].confidence).toBe('high');
			expect(findings[0].metadata.isHighRisk).toBe(true);
		});

		it('should detect XML-style tag protection', () => {
			const llmNode = createOpenAiNode(
				'OpenAI',
				'Answer the user query:\n<user_input>{{ $json.query }}</user_input>',
			);
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.hasProtection).toBe(true);
			expect(findings[0].metadata.protectionPatterns).toContain('XML input tags');
			expect(findings[0].severity).toBe('low');
		});

		it('should detect code block protection', () => {
			const llmNode = createOpenAiNode(
				'OpenAI',
				'Analyze this code:\n```\n{{ $json.code }}\n```',
			);
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.hasProtection).toBe(true);
			expect(findings[0].metadata.protectionPatterns).toContain('code block delimiters');
		});

		it('should detect bracket marker protection', () => {
			const llmNode = createOpenAiNode(
				'OpenAI',
				'Process this:\n[USER_INPUT]\n{{ $json.text }}\n[END]',
			);
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.hasProtection).toBe(true);
			expect(findings[0].metadata.protectionPatterns).toContain('bracket markers');
		});

		it('should work with Anthropic nodes', () => {
			const llmNode = createAnthropicNode('Claude', '{{ $json.prompt }}');
			const taintPath = createTaintPath(
				'Webhook',
				'Claude',
				'@n8n/n8n-nodes-langchain.anthropic',
			);
			const context = createMockContext(
				[llmNode],
				[taintPath],
				[createPromptSink('Claude', '@n8n/n8n-nodes-langchain.anthropic')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.llmProvider).toBe('Anthropic');
		});

		it('should reduce confidence when protection is present', () => {
			const llmNode = createOpenAiNode(
				'OpenAI',
				'<user_message>{{ $json.msg }}</user_message>',
			);
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].confidence).toBe('low');
		});

		it('should have medium confidence without protection', () => {
			const llmNode = createOpenAiNode('OpenAI', 'Help with: {{ $json.query }}');
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].confidence).toBe('medium');
		});

		it('should reduce severity when sanitizers are present', () => {
			const llmNode = createOpenAiNode('OpenAI', '{{ $json.query }}');
			const taintPath = createTaintPath('Webhook', 'OpenAI', '@n8n/n8n-nodes-langchain.openAi', true);
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			// High risk but sanitized, so reduced from high to medium
			expect(findings[0].severity).toBe('medium');
		});

		it('should include remediation guidance', () => {
			const llmNode = createOpenAiNode('OpenAI', '{{ $json.msg }}');
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings[0].remediation.summary).toContain('delimiters');
			expect(findings[0].remediation.steps.length).toBeGreaterThan(0);
			expect(findings[0].remediation.safePattern).toContain('<user_message>');
		});

		it('should return empty array when no taint paths to LLM nodes', () => {
			const llmNode = createOpenAiNode('OpenAI', 'Static prompt');
			const context = createMockContext([llmNode], [], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(0);
		});

		it('should track the path from source to sink', () => {
			const llmNode = createOpenAiNode('OpenAI', '{{ $json.msg }}');
			const taintPath: TaintPath = {
				...createTaintPath('Webhook', 'OpenAI'),
				path: ['Webhook', 'Set', 'OpenAI'],
			};
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings[0].path).toEqual(['Webhook', 'Set', 'OpenAI']);
		});

		it('should detect separator line protection', () => {
			const llmNode = createOpenAiNode(
				'OpenAI',
				'Instructions above\n---\n{{ $json.input }}\n---\nInstructions below',
			);
			const taintPath = createTaintPath('Webhook', 'OpenAI');
			const context = createMockContext([llmNode], [taintPath], [createPromptSink('OpenAI')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.hasProtection).toBe(true);
			expect(findings[0].metadata.protectionPatterns).toContain('separator lines');
		});
	});
});
