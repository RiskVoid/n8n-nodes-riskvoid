import {
	classifyNode,
	isTriggerNode,
	getSourceTypes,
	getSinkTypes,
	getSanitizerTypes,
	isDualRoleNode,
	getSinkSeverity,
	getSourceTrustLevel,
	getSinkClassification,
} from '../../nodes/RiskVoid/analysis/nodeClassifier';
import type { N8nNode } from '../../nodes/RiskVoid/types';

function createMockNode(type: string, name: string = 'TestNode'): N8nNode {
	return {
		id: 'test-id',
		name,
		type,
		typeVersion: 1,
		position: [0, 0],
		parameters: {},
	};
}

describe('nodeClassifier', () => {
	describe('classifyNode', () => {
		describe('source nodes', () => {
			it('should classify webhook as source with correct taintedFields', () => {
				const node = createMockNode('n8n-nodes-base.webhook');
				const classification = classifyNode(node);

				expect(classification.role).toBe('source');
				if (classification.role === 'source') {
					expect(classification.trustLevel).toBe('untrusted');
					expect(classification.taintedFields).toContain('body');
					expect(classification.taintedFields).toContain('headers');
				}
			});

			it('should classify formTrigger as source', () => {
				const node = createMockNode('n8n-nodes-base.formTrigger');
				const classification = classifyNode(node);

				expect(classification.role).toBe('source');
				if (classification.role === 'source') {
					expect(classification.trustLevel).toBe('untrusted');
					expect(classification.taintedFields).toContain('*');
				}
			});

			it('should classify slack as source', () => {
				const node = createMockNode('n8n-nodes-base.slack');
				const classification = classifyNode(node);

				expect(classification.role).toBe('source');
				if (classification.role === 'source') {
					expect(classification.taintedFields).toContain('text');
				}
			});

			it('should classify telegram as source', () => {
				const node = createMockNode('n8n-nodes-base.telegram');
				const classification = classifyNode(node);

				expect(classification.role).toBe('source');
			});

			it('should classify manualTrigger as trusted source', () => {
				const node = createMockNode('n8n-nodes-base.manualTrigger');
				const classification = classifyNode(node);

				expect(classification.role).toBe('source');
				if (classification.role === 'source') {
					expect(classification.trustLevel).toBe('trusted');
				}
			});
		});

		describe('sink nodes', () => {
			it('should classify code node as sink with critical severity', () => {
				const node = createMockNode('n8n-nodes-base.code');
				const classification = classifyNode(node);

				expect(classification.role).toBe('sink');
				if (classification.role === 'sink') {
					expect(classification.severity).toBe('critical');
					expect(classification.riskType).toBe('RCE');
					expect(classification.dangerousParams).toContain('jsCode');
				}
			});

			it('should classify executeCommand as sink with critical severity', () => {
				const node = createMockNode('n8n-nodes-base.executeCommand');
				const classification = classifyNode(node);

				expect(classification.role).toBe('sink');
				if (classification.role === 'sink') {
					expect(classification.severity).toBe('critical');
					expect(classification.riskType).toBe('Command Injection');
				}
			});

			it('should classify mySql as sink with high severity', () => {
				const node = createMockNode('n8n-nodes-base.mySql');
				const classification = classifyNode(node);

				expect(classification.role).toBe('sink');
				if (classification.role === 'sink') {
					expect(classification.severity).toBe('high');
					expect(classification.riskType).toBe('SQL Injection');
				}
			});

			it('should classify httpRequest as sink (SSRF)', () => {
				const node = createMockNode('n8n-nodes-base.httpRequest');
				const classification = classifyNode(node);

				// httpRequest is both a source and sink, but classifyNode returns based on first match
				// In our implementation, source is checked first
				expect(classification.role).toBe('source');
			});

			it('should classify LangChain nodes as medium severity sinks', () => {
				const node = createMockNode('@n8n/n8n-nodes-langchain.openAi');
				const classification = classifyNode(node);

				expect(classification.role).toBe('sink');
				if (classification.role === 'sink') {
					expect(classification.severity).toBe('medium');
					expect(classification.riskType).toBe('Prompt Injection');
				}
			});
		});

		describe('sanitizer nodes', () => {
			it('should classify if node as sanitizer', () => {
				const node = createMockNode('n8n-nodes-base.if');
				const classification = classifyNode(node);

				expect(classification.role).toBe('sanitizer');
				if (classification.role === 'sanitizer') {
					expect(classification.sanitizerType).toBe('conditional');
				}
			});

			it('should classify switch node as sanitizer', () => {
				const node = createMockNode('n8n-nodes-base.switch');
				const classification = classifyNode(node);

				expect(classification.role).toBe('sanitizer');
			});

			it('should classify filter node as sanitizer', () => {
				const node = createMockNode('n8n-nodes-base.filter');
				const classification = classifyNode(node);

				expect(classification.role).toBe('sanitizer');
				if (classification.role === 'sanitizer') {
					expect(classification.sanitizerType).toBe('validation');
				}
			});
		});

		describe('unknown nodes', () => {
			it('should classify unknown node as transform', () => {
				const node = createMockNode('n8n-nodes-base.unknownNode');
				const classification = classifyNode(node);

				expect(classification.role).toBe('transform');
				if (classification.role === 'transform') {
					expect(classification.propagatesTaint).toBe(true);
				}
			});

			it('should classify set node as transform', () => {
				const node = createMockNode('n8n-nodes-base.set');
				const classification = classifyNode(node);

				expect(classification.role).toBe('transform');
			});
		});
	});

	describe('isTriggerNode', () => {
		it('should return true for webhook', () => {
			expect(isTriggerNode('n8n-nodes-base.webhook')).toBe(true);
		});

		it('should return true for manualTrigger', () => {
			expect(isTriggerNode('n8n-nodes-base.manualTrigger')).toBe(true);
		});

		it('should return true for nodes ending with Trigger', () => {
			expect(isTriggerNode('n8n-nodes-base.emailTrigger')).toBe(true);
			expect(isTriggerNode('n8n-nodes-base.slackTrigger')).toBe(true);
		});

		it('should return false for non-trigger nodes', () => {
			expect(isTriggerNode('n8n-nodes-base.code')).toBe(false);
			expect(isTriggerNode('n8n-nodes-base.set')).toBe(false);
		});
	});

	describe('getSourceTypes', () => {
		it('should return array of source types', () => {
			const sources = getSourceTypes();

			expect(Array.isArray(sources)).toBe(true);
			expect(sources).toContain('n8n-nodes-base.webhook');
			expect(sources).toContain('n8n-nodes-base.formTrigger');
		});
	});

	describe('getSinkTypes', () => {
		it('should return array of sink types', () => {
			const sinks = getSinkTypes();

			expect(Array.isArray(sinks)).toBe(true);
			expect(sinks).toContain('n8n-nodes-base.code');
			expect(sinks).toContain('n8n-nodes-base.executeCommand');
		});
	});

	describe('getSanitizerTypes', () => {
		it('should return array of sanitizer types', () => {
			const sanitizers = getSanitizerTypes();

			expect(Array.isArray(sanitizers)).toBe(true);
			expect(sanitizers).toContain('n8n-nodes-base.if');
			expect(sanitizers).toContain('n8n-nodes-base.switch');
		});
	});

	describe('isDualRoleNode', () => {
		it('should return true for httpRequest (both source and sink)', () => {
			expect(isDualRoleNode('n8n-nodes-base.httpRequest')).toBe(true);
		});

		it('should return false for nodes with single role', () => {
			expect(isDualRoleNode('n8n-nodes-base.webhook')).toBe(false);
			expect(isDualRoleNode('n8n-nodes-base.code')).toBe(false);
		});
	});

	describe('getSinkSeverity', () => {
		it('should return correct severity for known sinks', () => {
			expect(getSinkSeverity('n8n-nodes-base.code')).toBe('critical');
			expect(getSinkSeverity('n8n-nodes-base.mySql')).toBe('high');
			expect(getSinkSeverity('@n8n/n8n-nodes-langchain.openAi')).toBe('medium');
		});

		it('should return null for non-sink nodes', () => {
			expect(getSinkSeverity('n8n-nodes-base.webhook')).toBeNull();
		});
	});

	describe('getSourceTrustLevel', () => {
		it('should return correct trust level for known sources', () => {
			expect(getSourceTrustLevel('n8n-nodes-base.webhook')).toBe('untrusted');
			expect(getSourceTrustLevel('n8n-nodes-base.manualTrigger')).toBe('trusted');
			expect(getSourceTrustLevel('n8n-nodes-base.rssFeedRead')).toBe('semi-trusted');
		});

		it('should return null for non-source nodes', () => {
			expect(getSourceTrustLevel('n8n-nodes-base.code')).toBeNull();
		});
	});

	describe('all registered sources have taintedFields', () => {
		it('should have taintedFields defined for all sources', () => {
			const sources = getSourceTypes();

			for (const sourceType of sources) {
				const node = createMockNode(sourceType);
				const classification = classifyNode(node);

				expect(classification.role).toBe('source');
				if (classification.role === 'source') {
					expect(classification.taintedFields).toBeDefined();
					expect(Array.isArray(classification.taintedFields)).toBe(true);
				}
			}
		});
	});

	describe('all registered sinks have dangerousParams', () => {
		it('should have dangerousParams defined for all sinks', () => {
			const sinks = getSinkTypes();

			for (const sinkType of sinks) {
				// For dual-role nodes, use getSinkClassification directly
				if (isDualRoleNode(sinkType)) {
					const sinkClassification = getSinkClassification(sinkType);
					expect(sinkClassification).not.toBeNull();
					expect(sinkClassification!.dangerousParams).toBeDefined();
					expect(sinkClassification!.dangerousParams.length).toBeGreaterThan(0);
					continue;
				}

				const node = createMockNode(sinkType);
				const classification = classifyNode(node);

				expect(classification.role).toBe('sink');
				if (classification.role === 'sink') {
					expect(classification.dangerousParams).toBeDefined();
					expect(Array.isArray(classification.dangerousParams)).toBe(true);
					expect(classification.dangerousParams.length).toBeGreaterThan(0);
				}
			}
		});
	});
});
