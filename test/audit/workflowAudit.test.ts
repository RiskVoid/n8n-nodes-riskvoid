/**
 * Comprehensive Workflow Detection Audit
 *
 * Scans ALL 80 vulnerable workflow files and compares expected vs actual results.
 * Generates a detailed report of detection gaps.
 */

import {
	loadWorkflow,
	scanWorkflow,
	setupRules,
	teardownRules,
} from '../helpers/workflowTestUtils';
import type { Finding } from '../../nodes/RiskVoid/rules/types';

// ============================================================================
// Types
// ============================================================================

interface ExpectedResult {
	file: string;
	name: string;
	category: string;
	expectedRuleId: string | null; // null = safe workflow (no findings expected)
	expectedSeverity: string | null;
	expectedConfidence: string | null;
	minFindings: number;
}

interface AuditResult extends ExpectedResult {
	actualFindings: number;
	actualRuleIds: string[];
	actualSeverities: string[];
	detected: boolean;
	status: 'TRUE_POSITIVE' | 'TRUE_NEGATIVE' | 'FALSE_POSITIVE' | 'FALSE_NEGATIVE';
	findings: Finding[];
	error?: string;
	duration: number;
}

// ============================================================================
// Expected Results Registry - ALL 80 workflows
// ============================================================================

const EXPECTED_RESULTS: ExpectedResult[] = [
	// ── 01: Code Injection (RCE) ──────────────────────────────────────
	{ file: '01-code-injection/rce-webhook-eval.json', name: 'RCE via eval()', category: 'Code Injection', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '01-code-injection/rce-form-function-constructor.json', name: 'RCE via Function()', category: 'Code Injection', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '01-code-injection/rce-email-settimeout.json', name: 'RCE via setTimeout', category: 'Code Injection', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '01-code-injection/rce-slack-python-exec.json', name: 'RCE via Python exec()', category: 'Code Injection', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '01-code-injection/rce-telegram-subprocess.json', name: 'RCE via subprocess', category: 'Code Injection', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '01-code-injection/rce-discord-vm-run.json', name: 'RCE via vm.runInNewContext', category: 'Code Injection', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '01-code-injection/rce-rss-os-system.json', name: 'RCE via os.system', category: 'Code Injection', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '01-code-injection/safe-code-trusted-source.json', name: 'SAFE: Trusted source', category: 'Code Injection', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },

	// ── 02: Command Injection ─────────────────────────────────────────
	{ file: '02-command-injection/cmdi-webhook-semicolon.json', name: 'CMDI via semicolon', category: 'Command Injection', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '02-command-injection/cmdi-form-pipe.json', name: 'CMDI via pipe', category: 'Command Injection', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '02-command-injection/cmdi-email-ampersand.json', name: 'CMDI via ampersand', category: 'Command Injection', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '02-command-injection/cmdi-telegram-substitution.json', name: 'CMDI via substitution', category: 'Command Injection', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '02-command-injection/cmdi-discord-backticks.json', name: 'CMDI via backticks', category: 'Command Injection', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '02-command-injection/cmdi-slack-variable-expansion.json', name: 'CMDI via variable expansion', category: 'Command Injection', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '02-command-injection/safe-command-hardcoded.json', name: 'SAFE: Hardcoded command', category: 'Command Injection', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },

	// ── 03: SQL Injection ─────────────────────────────────────────────
	{ file: '03-sql-injection/sqli-webhook-mysql-raw.json', name: 'SQLI to MySQL raw', category: 'SQL Injection', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '03-sql-injection/sqli-form-postgres-insert.json', name: 'SQLI to Postgres INSERT', category: 'SQL Injection', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '03-sql-injection/sqli-email-mysql-update.json', name: 'SQLI to MySQL UPDATE', category: 'SQL Injection', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '03-sql-injection/sqli-telegram-postgres-delete.json', name: 'SQLI to Postgres DELETE', category: 'SQL Injection', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '03-sql-injection/sqli-slack-mysql-union.json', name: 'SQLI UNION attack', category: 'SQL Injection', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '03-sql-injection/sqli-discord-mongodb-nosql.json', name: 'NoSQL Injection to MongoDB', category: 'SQL Injection', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '03-sql-injection/sqli-http-mssql.json', name: 'SQLI to MSSQL', category: 'SQL Injection', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '03-sql-injection/safe-sql-parameterized.json', name: 'SAFE: Parameterized query', category: 'SQL Injection', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },
	{ file: '03-sql-injection/safe-sql-trusted.json', name: 'SAFE: Trusted source', category: 'SQL Injection', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },

	// ── 04: SSRF ──────────────────────────────────────────────────────
	{ file: '04-ssrf/ssrf-webhook-localhost.json', name: 'SSRF to localhost', category: 'SSRF', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '04-ssrf/ssrf-form-private-class-a.json', name: 'SSRF to 10.x (Class A)', category: 'SSRF', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '04-ssrf/ssrf-email-private-class-b.json', name: 'SSRF to 172.16.x (Class B)', category: 'SSRF', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '04-ssrf/ssrf-telegram-private-class-c.json', name: 'SSRF to 192.168.x (Class C)', category: 'SSRF', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '04-ssrf/ssrf-slack-metadata-aws.json', name: 'SSRF to AWS metadata', category: 'SSRF', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '04-ssrf/ssrf-discord-metadata-gcp.json', name: 'SSRF to GCP metadata', category: 'SSRF', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '04-ssrf/ssrf-webhook-file-protocol.json', name: 'SSRF via file:// protocol', category: 'SSRF', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '04-ssrf/safe-ssrf-allowlist.json', name: 'SAFE: Domain allowlist', category: 'SSRF', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },

	// ── 05: Prompt Injection ──────────────────────────────────────────
	{ file: '05-prompt-injection/pi-webhook-openai-direct.json', name: 'PI to OpenAI', category: 'Prompt Injection', expectedRuleId: 'RV-PI-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '05-prompt-injection/pi-form-anthropic-highrisk.json', name: 'PI to Anthropic', category: 'Prompt Injection', expectedRuleId: 'RV-PI-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '05-prompt-injection/pi-email-ollama.json', name: 'PI to Ollama', category: 'Prompt Injection', expectedRuleId: 'RV-PI-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '05-prompt-injection/pi-telegram-azure-openai.json', name: 'PI to Azure OpenAI', category: 'Prompt Injection', expectedRuleId: 'RV-PI-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '05-prompt-injection/pi-slack-google-palm.json', name: 'PI to Google PaLM', category: 'Prompt Injection', expectedRuleId: 'RV-PI-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '05-prompt-injection/pi-discord-mistral.json', name: 'PI to Mistral', category: 'Prompt Injection', expectedRuleId: 'RV-PI-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '05-prompt-injection/pi-rss-groq.json', name: 'PI to Groq', category: 'Prompt Injection', expectedRuleId: 'RV-PI-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '05-prompt-injection/safe-pi-xml-tags.json', name: 'SAFE: XML tag isolation', category: 'Prompt Injection', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },
	{ file: '05-prompt-injection/safe-pi-code-blocks.json', name: 'SAFE: Code block isolation', category: 'Prompt Injection', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },

	// ── 06: Credential Exposure ───────────────────────────────────────
	{ file: '06-credential-exposure/cred-hardcoded-openai.json', name: 'Hardcoded OpenAI key', category: 'Credential Exposure', expectedRuleId: 'RV-CRED-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '06-credential-exposure/cred-hardcoded-github.json', name: 'Hardcoded GitHub PAT', category: 'Credential Exposure', expectedRuleId: 'RV-CRED-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '06-credential-exposure/cred-hardcoded-aws.json', name: 'Hardcoded AWS key', category: 'Credential Exposure', expectedRuleId: 'RV-CRED-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '06-credential-exposure/cred-hardcoded-stripe.json', name: 'Hardcoded Stripe key', category: 'Credential Exposure', expectedRuleId: 'RV-CRED-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '06-credential-exposure/cred-hardcoded-jwt.json', name: 'Hardcoded JWT', category: 'Credential Exposure', expectedRuleId: 'RV-CRED-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '06-credential-exposure/cred-exposure-slack.json', name: 'Creds exposed via Slack', category: 'Credential Exposure', expectedRuleId: 'RV-CRED-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '06-credential-exposure/cred-exposure-webhook-response.json', name: 'Creds in webhook response', category: 'Credential Exposure', expectedRuleId: 'RV-CRED-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },
	{ file: '06-credential-exposure/safe-cred-n8n-credentials.json', name: 'SAFE: n8n credential system', category: 'Credential Exposure', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },

	// ── 07: Multi-Source Coverage ─────────────────────────────────────
	{ file: '07-multi-source-coverage/source-rss-feed.json', name: 'RSS Feed → RCE', category: 'Multi-Source', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '07-multi-source-coverage/source-gmail.json', name: 'Gmail → CMDI', category: 'Multi-Source', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '07-multi-source-coverage/source-email-trigger.json', name: 'Email → SQLI', category: 'Multi-Source', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '07-multi-source-coverage/source-hubspot.json', name: 'HubSpot → SSRF', category: 'Multi-Source', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '07-multi-source-coverage/source-stripe.json', name: 'Stripe → RCE', category: 'Multi-Source', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '07-multi-source-coverage/source-github.json', name: 'GitHub → SQLI', category: 'Multi-Source', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '07-multi-source-coverage/source-http-response.json', name: 'HTTP Response → RCE', category: 'Multi-Source', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },

	// ── 08: Multi-Sink Coverage ───────────────────────────────────────
	{ file: '08-multi-sink-coverage/sink-ssh-command.json', name: 'SSH → CMDI', category: 'Multi-Sink', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '08-multi-sink-coverage/sink-function-node.json', name: 'Function → RCE', category: 'Multi-Sink', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '08-multi-sink-coverage/sink-function-item.json', name: 'FunctionItem → RCE', category: 'Multi-Sink', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '08-multi-sink-coverage/sink-mariadb.json', name: 'MariaDB/MySQL → SQLI', category: 'Multi-Sink', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '08-multi-sink-coverage/sink-oracle.json', name: 'Oracle → SQLI', category: 'Multi-Sink', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },
	{ file: '08-multi-sink-coverage/sink-respond-webhook.json', name: 'Respond → XSS', category: 'Multi-Sink', expectedRuleId: 'RV-XSS-001', expectedSeverity: 'medium', expectedConfidence: 'high', minFindings: 1 },

	// ── 09: Sanitizers ────────────────────────────────────────────────
	{ file: '09-sanitizers/sanitizer-if-regex.json', name: 'IF regex sanitizer', category: 'Sanitizers', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: null, minFindings: 0 },
	{ file: '09-sanitizers/sanitizer-switch-allowlist.json', name: 'Switch allowlist sanitizer', category: 'Sanitizers', expectedRuleId: 'RV-SQLI-001', expectedSeverity: 'critical', expectedConfidence: null, minFindings: 0 },
	{ file: '09-sanitizers/sanitizer-filter-blocks.json', name: 'Filter blocking sanitizer', category: 'Sanitizers', expectedRuleId: 'RV-CMDI-001', expectedSeverity: 'high', expectedConfidence: null, minFindings: 0 },
	{ file: '09-sanitizers/sanitizer-code-validator.json', name: 'Code validator sanitizer', category: 'Sanitizers', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: null, minFindings: 0 },
	{ file: '09-sanitizers/sanitizer-chain-multiple.json', name: 'Chained sanitizers', category: 'Sanitizers', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: null, minFindings: 0 },
	{ file: '09-sanitizers/sanitizer-weak-bypass.json', name: 'Weak/bypassable sanitizer', category: 'Sanitizers', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: null, minFindings: 1 },

	// ── 10: Complex Flows ─────────────────────────────────────────────
	{ file: '10-complex-flows/flow-chain-through-sets.json', name: 'Chain through Set nodes', category: 'Complex Flows', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '10-complex-flows/flow-branching-if-paths.json', name: 'Branching IF paths', category: 'Complex Flows', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 1 },
	{ file: '10-complex-flows/flow-multi-source-convergence.json', name: 'Multi-source convergence', category: 'Complex Flows', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '10-complex-flows/flow-fan-out-multi-sink.json', name: 'Fan-out multi-sink', category: 'Complex Flows', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 2 },
	{ file: '10-complex-flows/flow-nested-expressions.json', name: 'Nested expressions', category: 'Complex Flows', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '10-complex-flows/flow-dual-role-http.json', name: 'HTTP dual-role (source+sink)', category: 'Complex Flows', expectedRuleId: 'RV-SSRF-001', expectedSeverity: 'high', expectedConfidence: 'high', minFindings: 1 },

	// ── 11: Edge Cases ────────────────────────────────────────────────
	{ file: '11-edge-cases/edge-disconnected-vulnerable.json', name: 'Disconnected vulnerable node', category: 'Edge Cases', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },
	{ file: '11-edge-cases/edge-disabled-vulnerable.json', name: 'Disabled vulnerable node', category: 'Edge Cases', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },
	{ file: '11-edge-cases/edge-circular-reference.json', name: 'Circular references', category: 'Edge Cases', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 1 },
	{ file: '11-edge-cases/edge-deep-graph-20-nodes.json', name: 'Deep graph 20+ nodes', category: 'Edge Cases', expectedRuleId: 'RV-RCE-001', expectedSeverity: 'critical', expectedConfidence: 'high', minFindings: 1 },
	{ file: '11-edge-cases/edge-all-vulnerabilities.json', name: 'All vulnerability types', category: 'Edge Cases', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 2 },
	{ file: '11-edge-cases/edge-static-values-only.json', name: 'SAFE: Static values only', category: 'Edge Cases', expectedRuleId: null, expectedSeverity: null, expectedConfidence: null, minFindings: 0 },
];

// ============================================================================
// Helpers
// ============================================================================

function determineStatus(expected: ExpectedResult, findings: Finding[]): AuditResult['status'] {
	const isExpectedSafe = expected.expectedRuleId === null && expected.minFindings === 0;
	const hasFindings = findings.length > 0;
	const hasExpectedRule = expected.expectedRuleId
		? findings.some((f) => f.ruleId === expected.expectedRuleId)
		: true;
	const meetsMinFindings = findings.length >= expected.minFindings;

	if (isExpectedSafe) {
		return hasFindings ? 'FALSE_POSITIVE' : 'TRUE_NEGATIVE';
	}

	// Sanitizer workflows (minFindings: 0, expectedRuleId set):
	// Either detecting the rule OR 0 findings is acceptable
	if (expected.minFindings === 0 && expected.expectedRuleId !== null) {
		if (!hasFindings) return 'TRUE_POSITIVE'; // Sanitizer fully suppressed - OK
		if (hasExpectedRule) return 'TRUE_POSITIVE'; // Rule detected with sanitizer - OK
		return 'FALSE_POSITIVE'; // Wrong rule detected
	}

	if (hasExpectedRule && meetsMinFindings) {
		return 'TRUE_POSITIVE';
	}

	return 'FALSE_NEGATIVE';
}

// ============================================================================
// Test Suite
// ============================================================================

describe('Comprehensive Workflow Detection Audit', () => {
	const results: AuditResult[] = [];

	beforeAll(() => setupRules());

	afterAll(() => {
		teardownRules();

		// ── Print comprehensive report ──────────────────────────────
		const tp = results.filter((r) => r.status === 'TRUE_POSITIVE');
		const tn = results.filter((r) => r.status === 'TRUE_NEGATIVE');
		const fp = results.filter((r) => r.status === 'FALSE_POSITIVE');
		const fn = results.filter((r) => r.status === 'FALSE_NEGATIVE');
		const errors = results.filter((r) => r.error);
		const totalDuration = results.reduce((sum, r) => sum + r.duration, 0);

		// eslint-disable-next-line no-console
		console.log('\n');
		// eslint-disable-next-line no-console
		console.log('╔══════════════════════════════════════════════════════════════════╗');
		// eslint-disable-next-line no-console
		console.log('║           RISKVOID DETECTION AUDIT REPORT                       ║');
		// eslint-disable-next-line no-console
		console.log('╠══════════════════════════════════════════════════════════════════╣');
		// eslint-disable-next-line no-console
		console.log(`║  Total Workflows:    ${results.length.toString().padEnd(44)}║`);
		// eslint-disable-next-line no-console
		console.log(`║  True Positives:     ${tp.length.toString().padEnd(44)}║`);
		// eslint-disable-next-line no-console
		console.log(`║  True Negatives:     ${tn.length.toString().padEnd(44)}║`);
		// eslint-disable-next-line no-console
		console.log(`║  FALSE POSITIVES:    ${fp.length.toString().padEnd(44)}║`);
		// eslint-disable-next-line no-console
		console.log(`║  FALSE NEGATIVES:    ${fn.length.toString().padEnd(44)}║`);
		// eslint-disable-next-line no-console
		console.log(`║  Errors:             ${errors.length.toString().padEnd(44)}║`);
		// eslint-disable-next-line no-console
		console.log(`║  Total Duration:     ${(totalDuration + 'ms').padEnd(44)}║`);

		const accuracy = ((tp.length + tn.length) / results.length * 100).toFixed(1);
		// eslint-disable-next-line no-console
		console.log(`║  Accuracy:           ${(accuracy + '%').padEnd(44)}║`);
		// eslint-disable-next-line no-console
		console.log('╚══════════════════════════════════════════════════════════════════╝');

		// ── FALSE NEGATIVES (missed detections) ─────────────────────
		if (fn.length > 0) {
			// eslint-disable-next-line no-console
			console.log('\n--- FALSE NEGATIVES (Missed Detections) ---');
			for (const r of fn) {
				// eslint-disable-next-line no-console
				console.log(`  MISS: ${r.file}`);
				// eslint-disable-next-line no-console
				console.log(`        Expected: ${r.expectedRuleId || 'any'} (${r.expectedSeverity || 'any'}), min ${r.minFindings} findings`);
				// eslint-disable-next-line no-console
				console.log(`        Actual:   ${r.actualFindings} findings [${r.actualRuleIds.join(', ') || 'none'}]`);
			}
		}

		// ── FALSE POSITIVES ─────────────────────────────────────────
		if (fp.length > 0) {
			// eslint-disable-next-line no-console
			console.log('\n--- FALSE POSITIVES (Incorrect Detections) ---');
			for (const r of fp) {
				// eslint-disable-next-line no-console
				console.log(`  FP:   ${r.file}`);
				// eslint-disable-next-line no-console
				console.log(`        Expected: 0 findings (safe workflow)`);
				// eslint-disable-next-line no-console
				console.log(`        Actual:   ${r.actualFindings} findings [${r.actualRuleIds.join(', ')}]`);
			}
		}

		// ── By category ─────────────────────────────────────────────
		// eslint-disable-next-line no-console
		console.log('\n--- Results by Category ---');
		const categories = [...new Set(results.map((r) => r.category))];
		for (const cat of categories) {
			const catResults = results.filter((r) => r.category === cat);
			const catTp = catResults.filter((r) => r.status === 'TRUE_POSITIVE').length;
			const catTn = catResults.filter((r) => r.status === 'TRUE_NEGATIVE').length;
			const catFp = catResults.filter((r) => r.status === 'FALSE_POSITIVE').length;
			const catFn = catResults.filter((r) => r.status === 'FALSE_NEGATIVE').length;
			const catAcc = (((catTp + catTn) / catResults.length) * 100).toFixed(0);
			// eslint-disable-next-line no-console
			console.log(`  ${cat.padEnd(22)} ${catAcc}%  (TP:${catTp} TN:${catTn} FP:${catFp} FN:${catFn})`);
		}

		// ── Errors ──────────────────────────────────────────────────
		if (errors.length > 0) {
			// eslint-disable-next-line no-console
			console.log('\n--- Errors ---');
			for (const r of errors) {
				// eslint-disable-next-line no-console
				console.log(`  ERR:  ${r.file}: ${r.error}`);
			}
		}
	});

	// Generate one test per workflow
	for (const expected of EXPECTED_RESULTS) {
		it(`[${expected.category}] ${expected.name} (${expected.file})`, () => {
			let findings: Finding[] = [];
			let duration = 0;
			let error: string | undefined;

			try {
				const workflow = loadWorkflow(expected.file);
				const result = scanWorkflow(workflow);
				findings = result.findings;
				duration = result.duration;
			} catch (e) {
				error = e instanceof Error ? e.message : String(e);
			}

			const status = error ? 'FALSE_NEGATIVE' : determineStatus(expected, findings);

			const auditResult: AuditResult = {
				...expected,
				actualFindings: findings.length,
				actualRuleIds: [...new Set(findings.map((f) => f.ruleId))],
				actualSeverities: [...new Set(findings.map((f) => f.severity))],
				detected: findings.length > 0,
				status,
				findings,
				error,
				duration,
			};

			results.push(auditResult);

			// Actual assertions - these make the test fail/pass
			if (error) {
				// Don't fail on file-not-found, just record it
				expect(error).toBeUndefined();
			}
		});
	}
});
