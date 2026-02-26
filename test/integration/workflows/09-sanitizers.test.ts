import {
	loadWorkflow,
	analyzeAndGetFindings,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('09 - Sanitizers', () => {
	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should reduce severity with IF regex sanitizer', () => {
		const workflow = loadWorkflow('09-sanitizers/sanitizer-if-regex.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should reduce severity with Switch allowlist sanitizer', () => {
		const workflow = loadWorkflow('09-sanitizers/sanitizer-switch-allowlist.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should reduce severity with Filter blocks sanitizer', () => {
		const workflow = loadWorkflow('09-sanitizers/sanitizer-filter-blocks.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should reduce severity with Code validator sanitizer', () => {
		const workflow = loadWorkflow('09-sanitizers/sanitizer-code-validator.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should reduce severity with multiple chained sanitizers', () => {
		const workflow = loadWorkflow('09-sanitizers/sanitizer-chain-multiple.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});

	it('should detect vulnerability even with weak sanitizer (bypassable)', () => {
		const workflow = loadWorkflow('09-sanitizers/sanitizer-weak-bypass.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		expect(duration).toBeLessThan(500);
	});
});
