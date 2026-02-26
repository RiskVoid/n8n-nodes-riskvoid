import {
	loadWorkflow,
	analyzeAndGetFindings,
	assertVulnerabilityDetection,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('05 - Prompt Injection', () => {
	const testStats = {
		truePositives: 0,
		trueNegatives: 0,
		falsePositives: 0,
		falseNegatives: 0,
		totalDuration: 0,
	};

	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect prompt injection in OpenAI direct prompt', () => {
		const workflow = loadWorkflow('05-prompt-injection/pi-webhook-openai-direct.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-PI-001', 'medium', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect prompt injection in Anthropic high-risk prompt', () => {
		const workflow = loadWorkflow(
			'05-prompt-injection/pi-form-anthropic-highrisk.json',
		);
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-PI-001', 'medium', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect prompt injection in Ollama', () => {
		const workflow = loadWorkflow('05-prompt-injection/pi-email-ollama.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-PI-001', 'medium', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect prompt injection in Azure OpenAI', () => {
		const workflow = loadWorkflow('05-prompt-injection/pi-telegram-azure-openai.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-PI-001', 'medium', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect prompt injection in Google PaLM', () => {
		const workflow = loadWorkflow('05-prompt-injection/pi-slack-google-palm.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-PI-001', 'medium', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect prompt injection in Mistral', () => {
		const workflow = loadWorkflow('05-prompt-injection/pi-discord-mistral.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-PI-001', 'medium', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect prompt injection in Groq', () => {
		const workflow = loadWorkflow('05-prompt-injection/pi-rss-groq.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-PI-001', 'medium', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect prompt injection with XML tag sanitization', () => {
		const workflow = loadWorkflow('05-prompt-injection/safe-pi-xml-tags.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const piFinding = findings.find((f) => f.ruleId === 'RV-PI-001');
		expect(piFinding).toBeUndefined();
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect prompt injection with code block sanitization', () => {
		const workflow = loadWorkflow('05-prompt-injection/safe-pi-code-blocks.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const piFinding = findings.find((f) => f.ruleId === 'RV-PI-001');
		// Note: Protection patterns in upstream Set nodes are not visible when checking
		// the sink node's parameters directly. This is a known limitation.
		expect(piFinding).toBeUndefined();
		expect(duration).toBeLessThan(500);
	});
});
