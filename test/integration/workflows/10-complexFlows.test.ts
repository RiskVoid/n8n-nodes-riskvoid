import {
	loadWorkflow,
	analyzeAndGetFindings,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('10 - Complex Flows', () => {
	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect multi-source convergence vulnerability', () => {
		const workflow = loadWorkflow('10-complex-flows/flow-multi-source-convergence.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should detect fan-out multi-sink vulnerability', () => {
		const workflow = loadWorkflow('10-complex-flows/flow-fan-out-multi-sink.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should detect vulnerability in chain through sets', () => {
		const workflow = loadWorkflow('10-complex-flows/flow-chain-through-sets.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should detect nested expression vulnerability', () => {
		const workflow = loadWorkflow('10-complex-flows/flow-nested-expressions.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should detect vulnerability in branching IF paths', () => {
		const workflow = loadWorkflow('10-complex-flows/flow-branching-if-paths.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should detect vulnerability in dual-role HTTP node', () => {
		const workflow = loadWorkflow('10-complex-flows/flow-dual-role-http.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});
});
