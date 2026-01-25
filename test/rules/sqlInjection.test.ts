/**
 * Tests for SQL Injection Detection Rule
 */

import { SqlInjectionRule } from '../../nodes/RiskVoid/rules/sqlInjection';
import type { RuleContext } from '../../nodes/RiskVoid/rules/types';
import type { TaintPath, SecuritySink } from '../../nodes/RiskVoid/types/taint';
import type { ParsedWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import type { WorkflowGraph } from '../../nodes/RiskVoid/types/graph';
import type { N8nNode } from '../../nodes/RiskVoid/types/workflow';

describe('SqlInjectionRule', () => {
	let rule: SqlInjectionRule;

	beforeEach(() => {
		rule = new SqlInjectionRule();
	});

	// Helper to create mock workflow
	function createMockWorkflow(nodes: N8nNode[]): ParsedWorkflow {
		const nodeMap = new Map<string, N8nNode>();
		const nodesByType = new Map<string, N8nNode[]>();

		for (const node of nodes) {
			nodeMap.set(node.name, node);
			const list = nodesByType.get(node.type) ?? [];
			list.push(node);
			nodesByType.set(node.type, list);
		}

		return {
			id: 'test-workflow',
			name: 'Test Workflow',
			nodes: nodeMap,
			nodesByType,
			connections: {},
			nodeCount: nodes.length,
			connectionCount: 0,
			metadata: {
				hasTriggers: true,
				triggerTypes: [],
				nodeTypes: nodes.map((n) => n.type),
				usesCredentials: false,
				credentialTypes: [],
			},
			raw: {
				name: 'Test Workflow',
				active: false,
				nodes,
				connections: {},
			},
		};
	}

	// Helper to create mock context
	function createMockContext(
		nodes: N8nNode[],
		taintPaths: TaintPath[],
		sinks: SecuritySink[] = [],
	): RuleContext {
		const workflow = createMockWorkflow(nodes);

		return {
			workflow,
			graph: {
				nodes: new Map(),
				edges: [],
				entryPoints: [],
				exitPoints: [],
				hasCycles: false,
			} as WorkflowGraph,
			sources: [],
			sinks,
			taintPaths,
		};
	}

	// Helper to create MySQL node
	function createMySqlNode(name: string, query: string, operation = 'executeQuery'): N8nNode {
		return {
			id: `node-${name}`,
			name,
			type: 'n8n-nodes-base.mySql',
			typeVersion: 1,
			position: [0, 0],
			parameters: {
				operation,
				query,
			},
		};
	}

	// Helper to create Postgres node
	function createPostgresNode(name: string, query: string, operation = 'executeQuery'): N8nNode {
		return {
			id: `node-${name}`,
			name,
			type: 'n8n-nodes-base.postgres',
			typeVersion: 1,
			position: [0, 0],
			parameters: {
				operation,
				query,
			},
		};
	}

	// Helper to create a taint path to SQL node
	function createTaintPath(
		sourceName: string,
		sinkName: string,
		sinkType = 'n8n-nodes-base.mySql',
		sanitized = false,
	): TaintPath {
		return {
			id: `path-${sourceName}-${sinkName}`,
			source: {
				nodeName: sourceName,
				nodeType: 'n8n-nodes-base.webhook',
				trustLevel: 'untrusted',
				taintedFields: ['body'],
				classification: {
					role: 'source',
					trustLevel: 'untrusted',
					taintedFields: ['body'],
					description: 'Webhook receives untrusted input',
				},
			},
			sink: {
				nodeName: sinkName,
				nodeType: sinkType,
				severity: 'high',
				riskType: 'SQL Injection',
				dangerousParams: [{ paramPath: 'query', value: '', hasExpressions: true, expressions: [] }],
				classification: {
					role: 'sink',
					severity: 'high',
					riskType: 'SQL Injection',
					dangerousParams: ['query'],
					description: 'SQL query execution',
				},
			},
			path: [sourceName, sinkName],
			taintedField: 'body',
			sinkParam: 'query',
			severity: 'high',
			sanitized,
			sanitizerNodes: sanitized ? ['IF Node'] : [],
			confidence: 'high',
		};
	}

	// Helper to create SQL Injection sink
	function createSqlSink(nodeName: string, nodeType = 'n8n-nodes-base.mySql'): SecuritySink {
		return {
			nodeName,
			nodeType,
			severity: 'high',
			riskType: 'SQL Injection',
			dangerousParams: [],
			classification: {
				role: 'sink',
				severity: 'high',
				riskType: 'SQL Injection',
				dangerousParams: ['query'],
				description: 'SQL execution',
			},
		};
	}

	describe('metadata', () => {
		it('should have correct rule ID', () => {
			expect(rule.metadata.id).toBe('RV-SQLI-001');
		});

		it('should have high severity', () => {
			expect(rule.metadata.severity).toBe('high');
		});

		it('should have correct category', () => {
			expect(rule.metadata.category).toBe('injection');
		});

		it('should have CWE reference', () => {
			expect(rule.metadata.references.cwe).toBe('CWE-89');
		});
	});

	describe('isApplicable', () => {
		it('should return true when SQL Injection sinks exist', () => {
			const context = createMockContext(
				[createMySqlNode('MySQL', 'SELECT * FROM users')],
				[],
				[createSqlSink('MySQL')],
			);

			expect(rule.isApplicable(context)).toBe(true);
		});

		it('should return true when NoSQL Injection sinks exist', () => {
			const context = createMockContext(
				[],
				[],
				[
					{
						...createSqlSink('MongoDB'),
						riskType: 'NoSQL Injection',
						nodeType: 'n8n-nodes-base.mongodb',
					},
				],
			);

			expect(rule.isApplicable(context)).toBe(true);
		});

		it('should return false when no SQL injection sinks exist', () => {
			const context = createMockContext([], [], []);
			expect(rule.isApplicable(context)).toBe(false);
		});
	});

	describe('detect', () => {
		it('should detect taint flow to MySQL raw query', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				"SELECT * FROM users WHERE id = {{ $json.userId }}",
				'executeQuery',
			);
			const taintPath = createTaintPath('Webhook', 'MySQL');
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('high');
			expect(findings[0].metadata.isRawQuery).toBe(true);
			expect(findings[0].metadata.dbType).toBe('MySQL');
		});

		it('should detect SELECT query pattern', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				"SELECT * FROM users WHERE name = '{{ $json.name }}'",
			);
			const taintPath = createTaintPath('Webhook', 'MySQL');
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('SELECT query');
			expect(findings[0].metadata.detectedPatterns).toContain('WHERE clause');
		});

		it('should detect INSERT query pattern', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				"INSERT INTO users (name) VALUES ('{{ $json.name }}')",
			);
			const taintPath = createTaintPath('Webhook', 'MySQL');
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('INSERT query');
		});

		it('should detect UPDATE query pattern', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				"UPDATE users SET name = '{{ $json.name }}' WHERE id = {{ $json.id }}",
			);
			const taintPath = createTaintPath('Webhook', 'MySQL');
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('UPDATE query');
		});

		it('should detect DELETE query pattern', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				'DELETE FROM users WHERE id = {{ $json.id }}',
			);
			const taintPath = createTaintPath('Webhook', 'MySQL');
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('DELETE query');
		});

		it('should detect UNION SELECT pattern (SQL injection indicator)', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				'SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords',
			);
			const taintPath = createTaintPath('Webhook', 'MySQL');
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.detectedPatterns).toContain('UNION SELECT');
		});

		it('should work with PostgreSQL nodes', () => {
			const pgNode = createPostgresNode(
				'Postgres',
				"SELECT * FROM users WHERE id = {{ $json.id }}",
			);
			const taintPath = createTaintPath('Webhook', 'Postgres', 'n8n-nodes-base.postgres');
			const context = createMockContext(
				[pgNode],
				[taintPath],
				[createSqlSink('Postgres', 'n8n-nodes-base.postgres')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].metadata.dbType).toBe('PostgreSQL');
		});

		it('should reduce severity when sanitizers are present', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				"SELECT * FROM users WHERE id = {{ $json.id }}",
			);
			const taintPath = createTaintPath('Webhook', 'MySQL', 'n8n-nodes-base.mySql', true);
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('medium'); // reduced from high
		});

		it('should have high confidence for raw query with SQL patterns', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				"SELECT * FROM users WHERE id = {{ $json.id }}",
				'executeQuery',
			);
			const taintPath = createTaintPath('Webhook', 'MySQL');
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings[0].confidence).toBe('high');
		});

		it('should include remediation guidance', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				"SELECT * FROM users WHERE id = {{ $json.id }}",
			);
			const taintPath = createTaintPath('Webhook', 'MySQL');
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings[0].remediation.summary).toContain('parameterized');
			expect(findings[0].remediation.steps.length).toBeGreaterThan(0);
			expect(findings[0].remediation.safePattern).toContain('$1');
		});

		it('should return empty array when no taint paths to SQL nodes', () => {
			const mysqlNode = createMySqlNode('MySQL', 'SELECT * FROM users');
			const context = createMockContext([mysqlNode], [], [createSqlSink('MySQL')]);

			const findings = rule.detect(context);

			expect(findings).toHaveLength(0);
		});

		it('should track the path from source to sink', () => {
			const mysqlNode = createMySqlNode(
				'MySQL',
				"SELECT * FROM users WHERE id = {{ $json.id }}",
			);
			const taintPath: TaintPath = {
				...createTaintPath('Webhook', 'MySQL'),
				path: ['Webhook', 'Set', 'MySQL'],
			};
			const context = createMockContext(
				[mysqlNode],
				[taintPath],
				[createSqlSink('MySQL')],
			);

			const findings = rule.detect(context);

			expect(findings[0].path).toEqual(['Webhook', 'Set', 'MySQL']);
		});
	});
});
