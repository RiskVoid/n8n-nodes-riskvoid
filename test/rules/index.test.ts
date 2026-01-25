/**
 * Tests for rule registry and orchestrator
 */

import {
	registerRule,
	unregisterRule,
	getAllRules,
	getRule,
	getAllRuleMetadata,
	getRulesByCategory,
	getRulesByTag,
	runAllRules,
	runRule,
	clearAllRules,
	type DetectionRule,
	type RuleContext,
	type Finding,
	type RuleMetadata,
} from '../../nodes/RiskVoid/rules';

// Create mock rules for testing
function createMockRule(
	id: string,
	category: 'injection' | 'ssrf' | 'credential-exposure' | 'prompt-injection' = 'injection',
	tags: string[] = [],
	isApplicable = true,
	findings: Finding[] = [],
): DetectionRule {
	const metadata: RuleMetadata = {
		id,
		name: `Mock Rule ${id}`,
		description: `Test rule ${id}`,
		category,
		severity: 'high',
		tags,
		references: {
			cwe: 'CWE-TEST',
		},
	};

	return {
		metadata,
		isApplicable: () => isApplicable,
		detect: () => findings,
	};
}

function createMockFinding(ruleId: string, severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'high'): Finding {
	return {
		id: `${ruleId}-test-${Date.now()}`,
		ruleId,
		severity,
		confidence: 'high',
		title: `Test Finding for ${ruleId}`,
		description: 'Test description',
		category: 'injection',
		source: {
			node: 'Webhook',
			nodeType: 'n8n-nodes-base.webhook',
			field: 'body',
		},
		sink: {
			node: 'Code',
			nodeType: 'n8n-nodes-base.code',
			parameter: 'jsCode',
		},
		path: ['Webhook', 'Code'],
		remediation: {
			summary: 'Fix it',
			steps: ['Step 1'],
		},
		references: {
			cwe: 'CWE-TEST',
		},
		metadata: {},
	};
}

// Mock context for testing
const mockContext: RuleContext = {
	workflow: {
		id: 'test-workflow',
		name: 'Test Workflow',
		nodes: new Map(),
		nodesByType: new Map(),
		connections: {},
		nodeCount: 0,
		connectionCount: 0,
		metadata: {
			hasTriggers: false,
			triggerTypes: [],
			nodeTypes: [],
			usesCredentials: false,
			credentialTypes: [],
		},
		raw: {
			name: 'Test Workflow',
			active: false,
			nodes: [],
			connections: {},
		},
	},
	graph: {
		nodes: new Map(),
		edges: [],
		entryPoints: [],
		exitPoints: [],
		hasCycles: false,
	},
	sources: [],
	sinks: [],
	taintPaths: [],
};

describe('rules/index', () => {
	beforeEach(() => {
		clearAllRules();
	});

	describe('registerRule', () => {
		it('should register a new rule', () => {
			const rule = createMockRule('TEST-001');
			registerRule(rule);

			expect(getAllRules()).toHaveLength(1);
			expect(getRule('TEST-001')).toBe(rule);
		});

		it('should replace existing rule with same ID', () => {
			const rule1 = createMockRule('TEST-001');
			const rule2 = createMockRule('TEST-001');

			registerRule(rule1);
			registerRule(rule2);

			expect(getAllRules()).toHaveLength(1);
			expect(getRule('TEST-001')).toBe(rule2);
		});

		it('should allow multiple different rules', () => {
			registerRule(createMockRule('TEST-001'));
			registerRule(createMockRule('TEST-002'));
			registerRule(createMockRule('TEST-003'));

			expect(getAllRules()).toHaveLength(3);
		});
	});

	describe('unregisterRule', () => {
		it('should remove an existing rule', () => {
			registerRule(createMockRule('TEST-001'));
			expect(getAllRules()).toHaveLength(1);

			const result = unregisterRule('TEST-001');

			expect(result).toBe(true);
			expect(getAllRules()).toHaveLength(0);
		});

		it('should return false for non-existent rule', () => {
			const result = unregisterRule('NON-EXISTENT');
			expect(result).toBe(false);
		});
	});

	describe('getRule', () => {
		it('should return rule by ID', () => {
			const rule = createMockRule('TEST-001');
			registerRule(rule);

			expect(getRule('TEST-001')).toBe(rule);
		});

		it('should return undefined for non-existent rule', () => {
			expect(getRule('NON-EXISTENT')).toBeUndefined();
		});
	});

	describe('getAllRuleMetadata', () => {
		it('should return metadata for all rules', () => {
			registerRule(createMockRule('TEST-001'));
			registerRule(createMockRule('TEST-002'));

			const metadata = getAllRuleMetadata();

			expect(metadata).toHaveLength(2);
			expect(metadata[0].id).toBe('TEST-001');
			expect(metadata[1].id).toBe('TEST-002');
		});
	});

	describe('getRulesByCategory', () => {
		it('should filter rules by category', () => {
			registerRule(createMockRule('RCE-001', 'injection'));
			registerRule(createMockRule('SSRF-001', 'ssrf'));
			registerRule(createMockRule('RCE-002', 'injection'));

			const injectionRules = getRulesByCategory('injection');
			const ssrfRules = getRulesByCategory('ssrf');

			expect(injectionRules).toHaveLength(2);
			expect(ssrfRules).toHaveLength(1);
		});
	});

	describe('getRulesByTag', () => {
		it('should filter rules by tag', () => {
			registerRule(createMockRule('RCE-001', 'injection', ['rce', 'code-execution']));
			registerRule(createMockRule('CMD-001', 'injection', ['command', 'shell']));
			registerRule(createMockRule('RCE-002', 'injection', ['rce']));

			const rceRules = getRulesByTag('rce');
			const shellRules = getRulesByTag('shell');

			expect(rceRules).toHaveLength(2);
			expect(shellRules).toHaveLength(1);
		});
	});

	describe('runAllRules', () => {
		it('should run all applicable rules', () => {
			const finding1 = createMockFinding('TEST-001');
			const finding2 = createMockFinding('TEST-002');

			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding1]));
			registerRule(createMockRule('TEST-002', 'injection', [], true, [finding2]));

			const result = runAllRules(mockContext);

			expect(result.rulesRun).toBe(2);
			expect(result.rulesSkipped).toBe(0);
			expect(result.findings).toHaveLength(2);
			expect(result.errors).toHaveLength(0);
		});

		it('should skip non-applicable rules', () => {
			const finding = createMockFinding('TEST-001');

			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding]));
			registerRule(createMockRule('TEST-002', 'injection', [], false, []));

			const result = runAllRules(mockContext);

			expect(result.rulesRun).toBe(1);
			expect(result.rulesSkipped).toBe(1);
			expect(result.findings).toHaveLength(1);
		});

		it('should skip disabled rules', () => {
			const finding = createMockFinding('TEST-001');

			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding]));
			registerRule(createMockRule('TEST-002', 'injection', [], true, [finding]));

			const result = runAllRules(mockContext, {
				config: {
					'TEST-002': { enabled: false },
				},
			});

			expect(result.rulesRun).toBe(1);
			expect(result.rulesSkipped).toBe(1);
		});

		it('should filter by rule IDs', () => {
			const finding = createMockFinding('TEST-001');

			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding]));
			registerRule(createMockRule('TEST-002', 'injection', [], true, [finding]));

			const result = runAllRules(mockContext, {
				ruleIds: ['TEST-001'],
			});

			expect(result.rulesRun).toBe(1);
			expect(result.rulesSkipped).toBe(1);
		});

		it('should filter by categories', () => {
			const finding = createMockFinding('TEST-001');

			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding]));
			registerRule(createMockRule('TEST-002', 'ssrf', [], true, [finding]));

			const result = runAllRules(mockContext, {
				categories: ['injection'],
			});

			expect(result.rulesRun).toBe(1);
			expect(result.rulesSkipped).toBe(1);
		});

		it('should filter findings by minimum severity', () => {
			const criticalFinding = createMockFinding('TEST-001', 'critical');
			const lowFinding = createMockFinding('TEST-002', 'low');

			registerRule(createMockRule('TEST-001', 'injection', [], true, [criticalFinding]));
			registerRule(createMockRule('TEST-002', 'injection', [], true, [lowFinding]));

			const result = runAllRules(mockContext, {
				minSeverity: 'high',
			});

			expect(result.findings).toHaveLength(1);
			expect(result.findings[0].severity).toBe('critical');
		});

		it('should sort findings by severity', () => {
			const lowFinding = createMockFinding('TEST-001', 'low');
			const criticalFinding = createMockFinding('TEST-002', 'critical');
			const mediumFinding = createMockFinding('TEST-003', 'medium');

			registerRule(createMockRule('TEST-001', 'injection', [], true, [lowFinding]));
			registerRule(createMockRule('TEST-002', 'injection', [], true, [criticalFinding]));
			registerRule(createMockRule('TEST-003', 'injection', [], true, [mediumFinding]));

			const result = runAllRules(mockContext);

			expect(result.findings[0].severity).toBe('critical');
			expect(result.findings[1].severity).toBe('medium');
			expect(result.findings[2].severity).toBe('low');
		});

		it('should apply severity override from config', () => {
			const finding = createMockFinding('TEST-001', 'low');

			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding]));

			const result = runAllRules(mockContext, {
				config: {
					'TEST-001': { enabled: true, severityOverride: 'critical' },
				},
			});

			expect(result.findings[0].severity).toBe('critical');
		});

		it('should deduplicate similar findings', () => {
			const finding1 = createMockFinding('TEST-001');
			const finding2 = { ...createMockFinding('TEST-001'), id: 'different-id' };

			// Same rule, source, sink, parameter = duplicate
			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding1, finding2]));

			const result = runAllRules(mockContext);

			expect(result.findings).toHaveLength(1);
		});

		it('should capture errors from failing rules', () => {
			const failingRule: DetectionRule = {
				metadata: {
					id: 'FAILING-001',
					name: 'Failing Rule',
					description: 'Always fails',
					category: 'injection',
					severity: 'high',
					tags: [],
					references: {},
				},
				isApplicable: () => true,
				detect: () => {
					throw new Error('Rule failed');
				},
			};

			registerRule(failingRule);

			const result = runAllRules(mockContext);

			expect(result.errors).toHaveLength(1);
			expect(result.errors[0].ruleId).toBe('FAILING-001');
			expect(result.errors[0].message).toContain('Rule failed');
		});

		it('should track duration', () => {
			registerRule(createMockRule('TEST-001'));

			const result = runAllRules(mockContext);

			expect(result.duration).toBeGreaterThanOrEqual(0);
		});
	});

	describe('runRule', () => {
		it('should run a single rule by ID', () => {
			const finding = createMockFinding('TEST-001');
			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding]));

			const result = runRule('TEST-001', mockContext);

			expect(result).not.toBeNull();
			expect(result).toHaveLength(1);
		});

		it('should return null for non-existent rule', () => {
			const result = runRule('NON-EXISTENT', mockContext);
			expect(result).toBeNull();
		});

		it('should return empty array for disabled rule', () => {
			const finding = createMockFinding('TEST-001');
			registerRule(createMockRule('TEST-001', 'injection', [], true, [finding]));

			const result = runRule('TEST-001', mockContext, {
				'TEST-001': { enabled: false },
			});

			expect(result).toEqual([]);
		});

		it('should return empty array for non-applicable rule', () => {
			registerRule(createMockRule('TEST-001', 'injection', [], false, []));

			const result = runRule('TEST-001', mockContext);

			expect(result).toEqual([]);
		});
	});

	describe('clearAllRules', () => {
		it('should remove all registered rules', () => {
			registerRule(createMockRule('TEST-001'));
			registerRule(createMockRule('TEST-002'));
			expect(getAllRules()).toHaveLength(2);

			clearAllRules();

			expect(getAllRules()).toHaveLength(0);
		});
	});
});
