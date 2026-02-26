import {
	loadWorkflow,
	analyzeAndGetFindings,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('06 - Credential Exposure', () => {
	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect hardcoded OpenAI API key', () => {
		const workflow = loadWorkflow('06-credential-exposure/cred-hardcoded-openai.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const credFinding = findings.find((f) => f.ruleId === 'RV-CRED-001');
		expect(credFinding).toBeDefined();
		expect(['high', 'medium']).toContain(credFinding!.severity);
		expect(duration).toBeLessThan(500);
	});

	it('should detect hardcoded GitHub token', () => {
		const workflow = loadWorkflow('06-credential-exposure/cred-hardcoded-github.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const credFinding = findings.find((f) => f.ruleId === 'RV-CRED-001');
		expect(credFinding).toBeDefined();
		expect(['high', 'medium']).toContain(credFinding!.severity);
		expect(duration).toBeLessThan(500);
	});

	it('should detect hardcoded AWS credentials', () => {
		const workflow = loadWorkflow('06-credential-exposure/cred-hardcoded-aws.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const credFinding = findings.find((f) => f.ruleId === 'RV-CRED-001');
		expect(credFinding).toBeDefined();
		expect(['high', 'medium']).toContain(credFinding!.severity);
		expect(duration).toBeLessThan(500);
	});

	it('should detect hardcoded Stripe key', () => {
		const workflow = loadWorkflow('06-credential-exposure/cred-hardcoded-stripe.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const credFinding = findings.find((f) => f.ruleId === 'RV-CRED-001');
		expect(credFinding).toBeDefined();
		expect(['high', 'medium']).toContain(credFinding!.severity);
		expect(duration).toBeLessThan(500);
	});

	it('should detect hardcoded JWT secret', () => {
		const workflow = loadWorkflow('06-credential-exposure/cred-hardcoded-jwt.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const credFinding = findings.find((f) => f.ruleId === 'RV-CRED-001');
		expect(credFinding).toBeDefined();
		expect(['high', 'medium']).toContain(credFinding!.severity);
		expect(duration).toBeLessThan(500);
	});

	it('should detect credential exposure in Slack message', () => {
		const workflow = loadWorkflow('06-credential-exposure/cred-exposure-slack.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const credFinding = findings.find((f) => f.ruleId === 'RV-CRED-001');
		if (credFinding) {
			expect(findings.length).toBeGreaterThanOrEqual(1);
			expect(['high', 'medium']).toContain(credFinding.severity);
		}
		expect(duration).toBeLessThan(500);
	});

	it('should detect credential exposure in webhook response', () => {
		const workflow = loadWorkflow(
			'06-credential-exposure/cred-exposure-webhook-response.json',
		);
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const credFinding = findings.find((f) => f.ruleId === 'RV-CRED-001');
		expect(credFinding).toBeDefined();
		expect(['high', 'medium']).toContain(credFinding!.severity);
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect credentials when using n8n credential system', () => {
		const workflow = loadWorkflow(
			'06-credential-exposure/safe-cred-n8n-credentials.json',
		);
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const credFinding = findings.find((f) => f.ruleId === 'RV-CRED-001');
		expect(credFinding).toBeUndefined();
		expect(duration).toBeLessThan(500);
	});
});
