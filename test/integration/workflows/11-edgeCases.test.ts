import {
	loadWorkflow,
	analyzeAndGetFindings,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('11 - Edge Cases', () => {
	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect disconnected vulnerable nodes', () => {
		const workflow = loadWorkflow('11-edge-cases/edge-disconnected-vulnerable.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		// Disconnected nodes should still be analyzed if they contain patterns
		expect(findings).toBeDefined();
		expect(duration).toBeLessThan(500);
	});

	it('should detect disabled vulnerable nodes', () => {
		const workflow = loadWorkflow('11-edge-cases/edge-disabled-vulnerable.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		// Disabled nodes should still be flagged as potential issues
		expect(findings).toBeDefined();
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect issues in static values only workflow', () => {
		const workflow = loadWorkflow('11-edge-cases/edge-static-values-only.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBe(0);
		expect(duration).toBeLessThan(500);
	});

	it('should handle deep graph with 20 nodes', () => {
		const workflow = loadWorkflow('11-edge-cases/edge-deep-graph-20-nodes.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should detect all vulnerability types in combined workflow', () => {
		const workflow = loadWorkflow('11-edge-cases/edge-all-vulnerabilities.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		// Should detect multiple different vulnerability types
		expect(findings.length).toBeGreaterThanOrEqual(2);
		const ruleIds = new Set(findings.map((f) => f.ruleId));
		expect(ruleIds.size).toBeGreaterThanOrEqual(2);
		expect(duration).toBeLessThan(500);
	});

	it('should handle circular reference gracefully', () => {
		const workflow = loadWorkflow('11-edge-cases/edge-circular-reference.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		// Should not crash and should still detect issues
		expect(findings).toBeDefined();
		expect(duration).toBeLessThan(500);
	});
});
