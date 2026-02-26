import {
	loadWorkflow,
	analyzeAndGetFindings,
	assertVulnerabilityDetection,
	setupRules,
	teardownRules,
} from '../../helpers/workflowTestUtils';

describe('03 - SQL Injection', () => {
	const testStats = {
		truePositives: 0,
		trueNegatives: 0,
		falsePositives: 0,
		falseNegatives: 0,
		totalDuration: 0,
	};

	beforeAll(() => setupRules());
	afterAll(() => teardownRules());

	it('should detect SQLi in webhook to MySQL raw query', () => {
		const workflow = loadWorkflow('03-sql-injection/sqli-webhook-mysql-raw.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SQLI-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SQLi in form to Postgres INSERT', () => {
		const workflow = loadWorkflow('03-sql-injection/sqli-form-postgres-insert.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SQLI-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SQLi in email to MySQL UPDATE', () => {
		const workflow = loadWorkflow('03-sql-injection/sqli-email-mysql-update.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SQLI-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SQLi in Telegram to Postgres DELETE', () => {
		const workflow = loadWorkflow(
			'03-sql-injection/sqli-telegram-postgres-delete.json',
		);
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SQLI-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SQLi in Slack to MySQL UNION', () => {
		const workflow = loadWorkflow('03-sql-injection/sqli-slack-mysql-union.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SQLI-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect NoSQL injection in Discord to MongoDB', () => {
		const workflow = loadWorkflow('03-sql-injection/sqli-discord-mongodb-nosql.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SQLI-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should detect SQLi in HTTP to MSSQL', () => {
		const workflow = loadWorkflow('03-sql-injection/sqli-http-mssql.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		assertVulnerabilityDetection(findings, 'RV-SQLI-001', 'high', 'medium', testStats);
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect SQLi in parameterized query', () => {
		const workflow = loadWorkflow('03-sql-injection/safe-sql-parameterized.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const sqliFinding = findings.find((f) => f.ruleId === 'RV-SQLI-001');
		expect(sqliFinding).toBeUndefined();
		expect(duration).toBeLessThan(500);
	});

	it('should NOT detect SQLi with trusted source', () => {
		const workflow = loadWorkflow('03-sql-injection/safe-sql-trusted.json');
		const { findings, duration } = analyzeAndGetFindings(workflow);

		const sqliFinding = findings.find((f) => f.ruleId === 'RV-SQLI-001');
		expect(sqliFinding).toBeUndefined();
		expect(duration).toBeLessThan(500);
	});
});
