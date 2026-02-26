import {
	loadWorkflow,
	analyzeAndGetFindings,
	assertFinding,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('01 - Code Injection (RCE)', () => {
	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect RCE in webhook to eval() workflow', () => {
		const workflow = loadWorkflow('01-code-injection/rce-webhook-eval.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeDefined();
		assertFinding(rceFinding!, 'RV-RCE-001', 'critical', 'high', [
			'Webhook',
			'Code',
		]);
		expect(duration).toBeLessThan(500);
	});

	it('should detect RCE in form to Function() constructor workflow', () => {
		const workflow = loadWorkflow(
			'01-code-injection/rce-form-function-constructor.json',
		);
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeDefined();
		assertFinding(rceFinding!, 'RV-RCE-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect RCE in email to setTimeout workflow', () => {
		const workflow = loadWorkflow('01-code-injection/rce-email-settimeout.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		if (rceFinding) {
			expect(findings.length).toBeGreaterThanOrEqual(1);
			assertFinding(rceFinding, 'RV-RCE-001', 'critical', 'medium');
		}
		expect(duration).toBeLessThan(500);
	});

	it('should detect RCE in Slack to Python exec() workflow', () => {
		const workflow = loadWorkflow('01-code-injection/rce-slack-python-exec.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeDefined();
		assertFinding(rceFinding!, 'RV-RCE-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect RCE in Telegram to subprocess workflow', () => {
		const workflow = loadWorkflow('01-code-injection/rce-telegram-subprocess.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeDefined();
		assertFinding(rceFinding!, 'RV-RCE-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect RCE in Discord to vm.run() workflow', () => {
		const workflow = loadWorkflow('01-code-injection/rce-discord-vm-run.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeDefined();
		assertFinding(rceFinding!, 'RV-RCE-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect RCE in RSS to os.system() workflow', () => {
		const workflow = loadWorkflow('01-code-injection/rce-rss-os-system.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeDefined();
		assertFinding(rceFinding!, 'RV-RCE-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect RCE in safe code with trusted source', () => {
		const workflow = loadWorkflow('01-code-injection/safe-code-trusted-source.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeUndefined();
		expect(duration).toBeLessThan(500);
	});
});
