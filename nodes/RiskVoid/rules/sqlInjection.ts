/**
 * SQL Injection Detection Rule
 *
 * Detects when untrusted user input flows to SQL query construction,
 * which could allow attackers to manipulate database queries.
 *
 * Rule ID: RV-SQLI-001
 * Severity: High
 * CWE: CWE-89 (SQL Injection)
 */

import type {
	DetectionRule,
	RuleMetadata,
	Finding,
	RuleContext,
	RemediationGuidance,
	FindingConfidence,
} from './types';
import { createFindingId, getEffectiveSeverity } from './types';
import type { TaintPath } from '../types/taint';

/**
 * SQL keywords/patterns that indicate dynamic query construction
 */
const SQL_PATTERNS = [
	{ pattern: /SELECT\s+.+\s+FROM/i, name: 'SELECT query' },
	{ pattern: /INSERT\s+INTO/i, name: 'INSERT query' },
	{ pattern: /UPDATE\s+.+\s+SET/i, name: 'UPDATE query' },
	{ pattern: /DELETE\s+FROM/i, name: 'DELETE query' },
	{ pattern: /DROP\s+(TABLE|DATABASE|INDEX)/i, name: 'DROP statement' },
	{ pattern: /TRUNCATE\s+TABLE/i, name: 'TRUNCATE statement' },
	{ pattern: /ALTER\s+TABLE/i, name: 'ALTER TABLE' },
	{ pattern: /UNION\s+(ALL\s+)?SELECT/i, name: 'UNION SELECT' },
	{ pattern: /WHERE\s+/i, name: 'WHERE clause' },
	{ pattern: /ORDER\s+BY/i, name: 'ORDER BY clause' },
	{ pattern: /GROUP\s+BY/i, name: 'GROUP BY clause' },
	{ pattern: /HAVING\s+/i, name: 'HAVING clause' },
	{ pattern: /EXEC(UTE)?\s*\(/i, name: 'EXEC statement' },
];


/**
 * SQL Injection Detection Rule
 */
export class SqlInjectionRule implements DetectionRule {
	metadata: RuleMetadata = {
		id: 'RV-SQLI-001',
		name: 'SQL Injection via User Input',
		description:
			'Detects when untrusted user input flows to SQL query construction, allowing attackers to manipulate database queries',
		category: 'injection',
		severity: 'high',
		tags: ['sql-injection', 'database', 'mysql', 'postgres', 'sqli'],
		references: {
			cwe: 'CWE-89',
			owasp: 'A03:2021-Injection',
			capec: 'CAPEC-66',
		},
	};

	/**
	 * Check if this rule is applicable to the workflow
	 */
	isApplicable(context: RuleContext): boolean {
		return context.sinks.some(
			(sink) => sink.riskType === 'SQL Injection' || sink.riskType === 'NoSQL Injection',
		);
	}

	/**
	 * Run detection and return findings
	 */
	detect(context: RuleContext): Finding[] {
		const findings: Finding[] = [];

		// Get taint paths that flow to SQL nodes
		const sqlPaths = context.taintPaths.filter(
			(path) =>
				path.sink.riskType === 'SQL Injection' || path.sink.riskType === 'NoSQL Injection',
		);

		for (const taintPath of sqlPaths) {
			// Get the sink node to analyze query content
			const sinkNode = context.workflow.nodes.get(taintPath.sink.nodeName);
			if (!sinkNode) continue;

			// Check if it's raw query mode
			const isRawQuery = this.isRawQueryMode(sinkNode.parameters);

			// Get the query content
			const queryContent = this.getQueryContent(sinkNode.parameters);

			// Detect SQL patterns in the query
			const detectedPatterns = this.findSqlPatterns(queryContent);

			// Only flag if it looks like dynamic SQL construction
			if (!isRawQuery && detectedPatterns.length === 0) {
				// Parameterized mode with no dynamic SQL patterns - likely safe
				continue;
			}

			// Determine confidence level
			const confidence = this.determineConfidence(taintPath, isRawQuery, detectedPatterns);

			// Determine database type
			const dbType = this.getDatabaseType(sinkNode.type);

			// Create finding
			findings.push(
				this.createFinding(taintPath, detectedPatterns, confidence, isRawQuery, dbType),
			);
		}

		return findings;
	}

	/**
	 * Check if the node is in raw query mode
	 */
	private isRawQueryMode(params: Record<string, unknown>): boolean {
		const operation = params.operation as string | undefined;
		const rawQuery = params.rawQuery as boolean | undefined;

		// Different database nodes use different parameter names
		return (
			operation === 'executeQuery' ||
			operation === 'rawQuery' ||
			rawQuery === true ||
			typeof params.query === 'string'
		);
	}

	/**
	 * Get the query content from parameters
	 */
	private getQueryContent(params: Record<string, unknown>): string {
		// Try different parameter names used by various database nodes
		const query =
			(params.query as string) ||
			(params.rawQuery as string) ||
			(params.sqlQuery as string) ||
			'';

		return query;
	}

	/**
	 * Find SQL patterns in query
	 */
	private findSqlPatterns(query: string): string[] {
		const found: string[] = [];

		for (const { pattern, name } of SQL_PATTERNS) {
			if (pattern.test(query)) {
				found.push(name);
			}
		}

		return found;
	}

	/**
	 * Get database type from node type
	 */
	private getDatabaseType(nodeType: string): string {
		const typeMap: Record<string, string> = {
			'n8n-nodes-base.mySql': 'MySQL',
			'n8n-nodes-base.postgres': 'PostgreSQL',
			'n8n-nodes-base.microsoftSql': 'Microsoft SQL Server',
			'n8n-nodes-base.mariaDb': 'MariaDB',
			'n8n-nodes-base.oracleDb': 'Oracle',
			'n8n-nodes-base.snowflake': 'Snowflake',
			'n8n-nodes-base.questDb': 'QuestDB',
			'n8n-nodes-base.timescaleDb': 'TimescaleDB',
			'n8n-nodes-base.cockroachDb': 'CockroachDB',
			'n8n-nodes-base.mongodb': 'MongoDB',
		};

		return typeMap[nodeType] || 'SQL database';
	}

	/**
	 * Determine confidence level based on analysis
	 */
	private determineConfidence(
		taintPath: TaintPath,
		isRawQuery: boolean,
		detectedPatterns: string[],
	): FindingConfidence {
		// High confidence if:
		// - Raw query mode with SQL patterns AND direct taint flow
		if (isRawQuery && detectedPatterns.length > 0 && !taintPath.sanitized) {
			return 'high';
		}

		// Medium confidence if:
		// - Raw query mode OR SQL patterns detected
		if (isRawQuery || detectedPatterns.length > 0) {
			return 'medium';
		}

		// Low confidence otherwise
		return 'low';
	}

	/**
	 * Create a finding from a taint path
	 */
	private createFinding(
		taintPath: TaintPath,
		patterns: string[],
		confidence: FindingConfidence,
		isRawQuery: boolean,
		dbType: string,
	): Finding {
		const queryType = isRawQuery ? 'raw SQL query' : 'query construction';
		const patternList = patterns.length > 0 ? ` Detected: ${patterns.join(', ')}.` : '';

		const severity = getEffectiveSeverity(this.metadata.severity, taintPath.sanitized);

		return {
			id: createFindingId(this.metadata.id),
			ruleId: this.metadata.id,
			severity,
			confidence,
			title: 'SQL Injection via User Input',
			description:
				`Untrusted input from "${taintPath.source.nodeName}" (${taintPath.source.nodeType}) flows to ${queryType} in "${taintPath.sink.nodeName}" (${dbType}).${patternList}` +
				` An attacker could manipulate queries to access, modify, or delete unauthorized data.`,
			category: 'injection',
			source: {
				node: taintPath.source.nodeName,
				nodeType: taintPath.source.nodeType,
				field: taintPath.taintedField,
			},
			sink: {
				node: taintPath.sink.nodeName,
				nodeType: taintPath.sink.nodeType,
				parameter: taintPath.sinkParam,
				dangerousExpression: patterns[0],
			},
			path: taintPath.path,
			remediation: this.getRemediation(taintPath, dbType),
			references: this.metadata.references,
			metadata: {
				detectedPatterns: patterns,
				isRawQuery,
				dbType,
				sanitized: taintPath.sanitized,
				sanitizerNodes: taintPath.sanitizerNodes,
			},
		};
	}

	/**
	 * Get remediation guidance
	 */
	private getRemediation(taintPath: TaintPath, dbType: string): RemediationGuidance {
		return {
			summary:
				'Use parameterized queries instead of string concatenation. Never build SQL queries with user input directly.',
			steps: [
				`Switch from raw query mode to n8n's built-in operations (Insert, Update, Select) with field mapping`,
				'If raw queries are necessary, use parameterized queries with placeholders ($1, ?, :param)',
				`Add input validation after "${taintPath.source.nodeName}" to restrict input format`,
				'Escape special characters if parameterization is not possible (though parameterization is strongly preferred)',
				'Implement least-privilege database access - the n8n connection should have minimal permissions',
				'Consider using an ORM or query builder that handles escaping automatically',
			],
			safePattern: `
// UNSAFE - String concatenation:
query: "SELECT * FROM users WHERE id = {{ $json.userId }}"

// SAFE - Parameterized query (PostgreSQL/MySQL):
query: "SELECT * FROM users WHERE id = $1"
// With parameters: ["{{ $json.userId }}"]

// SAFE - n8n's built-in operations:
// Use the "Select" operation with:
// - Table: users
// - Columns: *
// - Where conditions: id = {{ $json.userId }}
// n8n will handle parameterization automatically

// If validation is needed, add an IF node before the database node:
if (!/^[0-9]+$/.test($json.userId)) {
  throw new Error('Invalid user ID format');
}
`,
			exampleCode: `Use ${dbType}'s parameterized query syntax or n8n's built-in database operations with field mapping`,
		};
	}
}
