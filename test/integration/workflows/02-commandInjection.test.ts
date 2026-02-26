import {
	loadWorkflow,
	analyzeAndGetFindings,
	assertFinding,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('02 - Command Injection (CMDI)', () => {
	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect CMDI with semicolon injection', () => {
		const workflow = loadWorkflow('02-command-injection/cmdi-webhook-semicolon.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const cmdiFinding = findings.find((f) => f.ruleId === 'RV-CMDI-001');
		expect(cmdiFinding).toBeDefined();
		assertFinding(cmdiFinding!, 'RV-CMDI-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect CMDI with pipe injection', () => {
		const workflow = loadWorkflow('02-command-injection/cmdi-form-pipe.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const cmdiFinding = findings.find((f) => f.ruleId === 'RV-CMDI-001');
		expect(cmdiFinding).toBeDefined();
		assertFinding(cmdiFinding!, 'RV-CMDI-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect CMDI with ampersand injection', () => {
		const workflow = loadWorkflow('02-command-injection/cmdi-email-ampersand.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const cmdiFinding = findings.find((f) => f.ruleId === 'RV-CMDI-001');
		expect(cmdiFinding).toBeDefined();
		assertFinding(cmdiFinding!, 'RV-CMDI-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect CMDI with command substitution', () => {
		const workflow = loadWorkflow(
			'02-command-injection/cmdi-telegram-substitution.json',
		);
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const cmdiFinding = findings.find((f) => f.ruleId === 'RV-CMDI-001');
		expect(cmdiFinding).toBeDefined();
		assertFinding(cmdiFinding!, 'RV-CMDI-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect CMDI with backticks injection', () => {
		const workflow = loadWorkflow('02-command-injection/cmdi-discord-backticks.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const cmdiFinding = findings.find((f) => f.ruleId === 'RV-CMDI-001');
		expect(cmdiFinding).toBeDefined();
		assertFinding(cmdiFinding!, 'RV-CMDI-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect CMDI with variable expansion', () => {
		const workflow = loadWorkflow(
			'02-command-injection/cmdi-slack-variable-expansion.json',
		);
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const cmdiFinding = findings.find((f) => f.ruleId === 'RV-CMDI-001');
		expect(cmdiFinding).toBeDefined();
		assertFinding(cmdiFinding!, 'RV-CMDI-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect CMDI in safe hardcoded command', () => {
		const workflow = loadWorkflow('02-command-injection/safe-command-hardcoded.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const cmdiFinding = findings.find((f) => f.ruleId === 'RV-CMDI-001');
		expect(cmdiFinding).toBeUndefined();
		expect(duration).toBeLessThan(500);
	});
});
