import {
	loadWorkflow,
	analyzeAndGetFindings,
	assertVulnerabilityDetection,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('04 - SSRF (Server-Side Request Forgery)', () => {
	const testStats = {
		truePositives: 0,
		trueNegatives: 0,
		falsePositives: 0,
		falseNegatives: 0,
		totalDuration: 0,
	};

	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect SSRF to localhost', () => {
		const workflow = loadWorkflow('04-ssrf/ssrf-webhook-localhost.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SSRF-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SSRF to private Class A network', () => {
		const workflow = loadWorkflow('04-ssrf/ssrf-form-private-class-a.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SSRF-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SSRF to private Class B network', () => {
		const workflow = loadWorkflow('04-ssrf/ssrf-email-private-class-b.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SSRF-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SSRF to private Class C network', () => {
		const workflow = loadWorkflow('04-ssrf/ssrf-telegram-private-class-c.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SSRF-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SSRF to AWS metadata service', () => {
		const workflow = loadWorkflow('04-ssrf/ssrf-slack-metadata-aws.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SSRF-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SSRF to GCP metadata service', () => {
		const workflow = loadWorkflow('04-ssrf/ssrf-discord-metadata-gcp.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SSRF-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SSRF with file:// protocol', () => {
		const workflow = loadWorkflow('04-ssrf/ssrf-webhook-file-protocol.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SSRF-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect SSRF with allowlist validation', () => {
		const workflow = loadWorkflow('04-ssrf/safe-ssrf-allowlist.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const ssrfFinding = findings.find((f) => f.ruleId === 'RV-SSRF-001');
		expect(ssrfFinding).toBeUndefined();
		expect(duration).toBeLessThan(500);
	});
});
