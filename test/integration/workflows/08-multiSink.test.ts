import {
	loadWorkflow,
	analyzeAndGetFindings,
	assertFinding,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('08 - Multi-Sink Coverage', () => {
	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect taint to SSH command sink', () => {
		const workflow = loadWorkflow('08-multi-sink-coverage/sink-ssh-command.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const cmdiFinding = findings.find((f) => f.ruleId === 'RV-CMDI-001');
		expect(cmdiFinding).toBeDefined();
		assertFinding(cmdiFinding!, 'RV-CMDI-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect taint to Function node sink', () => {
		const workflow = loadWorkflow('08-multi-sink-coverage/sink-function-node.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeDefined();
		assertFinding(rceFinding!, 'RV-RCE-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect taint to Function Item node sink', () => {
		const workflow = loadWorkflow('08-multi-sink-coverage/sink-function-item.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const rceFinding = findings.find((f) => f.ruleId === 'RV-RCE-001');
		expect(rceFinding).toBeDefined();
		assertFinding(rceFinding!, 'RV-RCE-001', 'critical', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect taint to MariaDB sink', () => {
		const workflow = loadWorkflow('08-multi-sink-coverage/sink-mariadb.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const sqliFinding = findings.find((f) => f.ruleId === 'RV-SQLI-001');
		expect(sqliFinding).toBeDefined();
		assertFinding(sqliFinding!, 'RV-SQLI-001', 'high', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect taint to Oracle sink', () => {
		const workflow = loadWorkflow('08-multi-sink-coverage/sink-oracle.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const sqliFinding = findings.find((f) => f.ruleId === 'RV-SQLI-001');
		expect(sqliFinding).toBeDefined();
		assertFinding(sqliFinding!, 'RV-SQLI-001', 'high', 'high');
		expect(duration).toBeLessThan(500);
	});

	it('should detect taint to Respond to Webhook sink', () => {
		const workflow = loadWorkflow('08-multi-sink-coverage/sink-respond-webhook.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		expect(findings.length).toBeGreaterThanOrEqual(1);
		const xssFinding = findings.find((f) => f.ruleId === 'RV-XSS-001');
		expect(xssFinding).toBeDefined();
		assertFinding(xssFinding!, 'RV-XSS-001', 'medium', 'medium');
		expect(duration).toBeLessThan(500);
	});
});
