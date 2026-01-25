/**
 * Tests for Report Formatters - HTML, Slack Blocks, SARIF, Mermaid
 */

import {
	formatAsHtml,
	formatAsSlackBlocks,
	formatAsSarif,
	generateMermaidDiagram,
} from '../../nodes/RiskVoid/analysis/reportFormatters';
import type { SecurityReport } from '../../nodes/RiskVoid/analysis/findingsReporter';
import type { Finding } from '../../nodes/RiskVoid/rules/types';

describe('reportFormatters', () => {
	// Helper to create mock finding
	function createMockFinding(overrides: Partial<Finding> = {}): Finding {
		return {
			id: 'RV-RCE-001-test123',
			ruleId: 'RV-RCE-001',
			severity: 'critical',
			confidence: 'high',
			title: 'Remote Code Execution via User Input',
			description: 'Untrusted data from Webhook flows to Code node without sanitization',
			category: 'injection',
			source: {
				node: 'Webhook',
				nodeType: 'n8n-nodes-base.webhook',
				field: 'body.cmd',
			},
			sink: {
				node: 'Code',
				nodeType: 'n8n-nodes-base.code',
				parameter: 'jsCode',
			},
			path: ['Webhook', 'Set Fields', 'Code'],
			remediation: {
				summary: 'Validate and sanitize user input before code execution',
				steps: [
					'Add IF node to validate input format',
					'Use allowlist validation for expected values',
					'Consider using parameterized operations',
				],
			},
			references: {
				cwe: 'CWE-94',
				owasp: 'A03:2021-Injection',
			},
			metadata: {},
			...overrides,
		};
	}

	// Helper to create mock security report
	function createMockReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
		const findings = overrides.findings || [createMockFinding()];
		return {
			metadata: {
				generatedAt: '2024-01-15T10:30:00.000Z',
				version: '1.0.0',
				duration: 150,
			},
			workflow: {
				id: 'test-workflow-123',
				name: 'My Test Workflow',
				nodeCount: 5,
				connectionCount: 4,
				hasCycles: false,
			},
			summary: {
				totalFindings: findings.length,
				bySeverity: {
					critical: findings.filter((f) => f.severity === 'critical').length,
					high: findings.filter((f) => f.severity === 'high').length,
					medium: findings.filter((f) => f.severity === 'medium').length,
					low: findings.filter((f) => f.severity === 'low').length,
					info: findings.filter((f) => f.severity === 'info').length,
				},
				byCategory: {},
				affectedNodes: 3,
				uniqueSources: 1,
				uniqueSinks: 1,
			},
			risk: {
				score: findings.length > 0 ? 85 : 0,
				level: findings.length > 0 ? 'critical' : 'none',
				factors: findings.length > 0 ? ['1 critical severity finding(s)'] : [],
				recommendations: findings.length > 0 ? ['Validate user input'] : [],
			},
			findings,
			findingsByCategory: [],
			findingsBySeverity: [],
			nodeAssessments: findings.length > 0
				? [
						{
							name: 'Webhook',
							type: 'n8n-nodes-base.webhook',
							role: 'source' as const,
							findingCount: 1,
							maxSeverity: 'critical' as const,
							findingIds: ['RV-RCE-001-test123'],
						},
						{
							name: 'Code',
							type: 'n8n-nodes-base.code',
							role: 'sink' as const,
							findingCount: 1,
							maxSeverity: 'critical' as const,
							findingIds: ['RV-RCE-001-test123'],
						},
					]
				: [],
			recommendations: findings.length > 0
				? ['Add input validation before code execution']
				: ['No security actions required'],
			warnings: [],
			ruleStats: {
				rulesRun: 6,
				rulesSkipped: 0,
				errors: [],
			},
			...overrides,
		};
	}

	describe('formatAsHtml', () => {
		it('should generate valid HTML document', () => {
			const report = createMockReport();
			const html = formatAsHtml(report);

			expect(html).toContain('<!DOCTYPE html>');
			expect(html).toContain('<html');
			expect(html).toContain('</html>');
			expect(html).toContain('<head>');
			expect(html).toContain('<body>');
		});

		it('should include workflow name in title and header', () => {
			const report = createMockReport();
			const html = formatAsHtml(report);

			expect(html).toContain('<title>Security Report: My Test Workflow</title>');
			expect(html).toContain('My Test Workflow');
		});

		it('should include risk score and level', () => {
			const report = createMockReport();
			const html = formatAsHtml(report);

			expect(html).toContain('85');
			expect(html).toContain('/100');
			expect(html).toContain('CRITICAL');
		});

		it('should include findings table with severity badges', () => {
			const report = createMockReport();
			const html = formatAsHtml(report);

			expect(html).toContain('Remote Code Execution via User Input');
			expect(html).toContain('severity-critical');
			expect(html).toContain('Webhook');
			expect(html).toContain('Code');
		});

		it('should include remediation steps', () => {
			const report = createMockReport();
			const html = formatAsHtml(report);

			expect(html).toContain('Validate and sanitize user input');
			expect(html).toContain('Add IF node to validate input format');
		});

		it('should include Mermaid diagram when provided', () => {
			const report = createMockReport();
			const mermaid = 'graph LR\n    A --> B';
			const html = formatAsHtml(report, mermaid);

			expect(html).toContain('Workflow Diagram');
			expect(html).toContain('mermaid-code');
			expect(html).toContain('graph LR');
		});

		it('should show no findings message when empty', () => {
			const report = createMockReport({ findings: [] });
			const html = formatAsHtml(report);

			expect(html).toContain('No security vulnerabilities detected');
		});

		it('should escape HTML entities in user content', () => {
			const finding = createMockFinding({
				title: 'XSS via <script> tag',
				description: 'User can inject <script>alert("xss")</script>',
			});
			const report = createMockReport({ findings: [finding] });
			const html = formatAsHtml(report);

			expect(html).toContain('&lt;script&gt;');
			expect(html).not.toContain('<script>alert');
		});

		it('should include inline CSS styles', () => {
			const report = createMockReport();
			const html = formatAsHtml(report);

			expect(html).toContain('<style>');
			expect(html).toContain('.container');
			expect(html).toContain('.risk-score');
		});

		it('should include severity summary counts', () => {
			const findings = [
				createMockFinding({ severity: 'critical' }),
				createMockFinding({ id: 'f2', severity: 'high' }),
				createMockFinding({ id: 'f3', severity: 'medium' }),
			];
			const report = createMockReport({
				findings,
				summary: {
					totalFindings: 3,
					bySeverity: { critical: 1, high: 1, medium: 1, low: 0, info: 0 },
					byCategory: {},
					affectedNodes: 3,
					uniqueSources: 1,
					uniqueSinks: 1,
				},
			});
			const html = formatAsHtml(report);

			expect(html).toContain('Critical');
			expect(html).toContain('High');
			expect(html).toContain('Medium');
		});
	});

	describe('formatAsSlackBlocks', () => {
		it('should return array of Slack blocks', () => {
			const report = createMockReport();
			const blocks = formatAsSlackBlocks(report);

			expect(Array.isArray(blocks)).toBe(true);
			expect(blocks.length).toBeGreaterThan(0);
		});

		it('should include header block with workflow name', () => {
			const report = createMockReport();
			const blocks = formatAsSlackBlocks(report);

			const headerBlock = blocks.find((b) => b.type === 'header');
			expect(headerBlock).toBeDefined();
			expect(headerBlock?.text).toMatchObject({
				type: 'plain_text',
				text: expect.stringContaining('My Test Workflow'),
			});
		});

		it('should include risk score and level in section', () => {
			const report = createMockReport();
			const blocks = formatAsSlackBlocks(report);

			const sectionBlocks = blocks.filter((b) => b.type === 'section');
			const fieldsBlock = sectionBlocks.find((b) => b.fields);

			expect(fieldsBlock).toBeDefined();
			expect(fieldsBlock?.fields).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ text: expect.stringContaining('85/100') }),
					expect.objectContaining({ text: expect.stringContaining('CRITICAL') }),
				]),
			);
		});

		it('should include severity emojis', () => {
			const report = createMockReport();
			const blocks = formatAsSlackBlocks(report);

			const blocksJson = JSON.stringify(blocks);
			expect(blocksJson).toContain('Critical:');
			expect(blocksJson).toContain('High:');
		});

		it('should include findings with severity emoji', () => {
			const report = createMockReport();
			const blocks = formatAsSlackBlocks(report);

			// Check that some block contains the finding title
			const blocksJson = JSON.stringify(blocks);
			expect(blocksJson).toContain('Remote Code Execution');
		});

		it('should limit findings to 5 and show count of remaining', () => {
			const findings = Array.from({ length: 8 }, (_, i) =>
				createMockFinding({
					id: `finding-${i}`,
					title: `Finding ${i}`,
				}),
			);
			const report = createMockReport({ findings });
			const blocks = formatAsSlackBlocks(report);

			const contextBlocks = blocks.filter((b) => b.type === 'context');
			const moreBlock = contextBlocks.find((b) =>
				JSON.stringify(b).includes('more findings'),
			);

			expect(moreBlock).toBeDefined();
			expect(JSON.stringify(moreBlock)).toContain('3 more findings');
		});

		it('should include recommendations', () => {
			const report = createMockReport();
			const blocks = formatAsSlackBlocks(report);

			const blocksJson = JSON.stringify(blocks);
			expect(blocksJson).toContain('Recommendations');
		});

		it('should include dividers between sections', () => {
			const report = createMockReport();
			const blocks = formatAsSlackBlocks(report);

			const dividers = blocks.filter((b) => b.type === 'divider');
			expect(dividers.length).toBeGreaterThan(0);
		});

		it('should include footer context with version', () => {
			const report = createMockReport();
			const blocks = formatAsSlackBlocks(report);

			const contextBlocks = blocks.filter((b) => b.type === 'context');
			const footerBlock = contextBlocks.find((b) =>
				JSON.stringify(b).includes('RiskVoid v'),
			);

			expect(footerBlock).toBeDefined();
		});
	});

	describe('formatAsSarif', () => {
		it('should return valid SARIF 2.1.0 structure', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			expect(sarif.$schema).toContain('sarif-schema-2.1.0');
			expect(sarif.version).toBe('2.1.0');
			expect(Array.isArray(sarif.runs)).toBe(true);
			expect(sarif.runs.length).toBe(1);
		});

		it('should include tool information', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			const driver = sarif.runs[0].tool.driver;
			expect(driver.name).toBe('RiskVoid');
			expect(driver.version).toBe('1.0.0');
		});

		it('should include rules array', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			const rules = sarif.runs[0].tool.driver.rules;
			expect(Array.isArray(rules)).toBe(true);
			expect(rules.length).toBeGreaterThan(0);
			expect(rules[0].id).toBe('RV-RCE-001');
		});

		it('should map severity to SARIF level correctly', () => {
			const findings = [
				createMockFinding({ id: 'f1', severity: 'critical' }),
				createMockFinding({ id: 'f2', severity: 'high' }),
				createMockFinding({ id: 'f3', severity: 'medium' }),
				createMockFinding({ id: 'f4', severity: 'low' }),
				createMockFinding({ id: 'f5', severity: 'info' }),
			];
			const report = createMockReport({ findings });
			const sarif = formatAsSarif(report);

			const results = sarif.runs[0].results;
			expect(results[0].level).toBe('error'); // critical
			expect(results[1].level).toBe('error'); // high
			expect(results[2].level).toBe('warning'); // medium
			expect(results[3].level).toBe('note'); // low
			expect(results[4].level).toBe('note'); // info
		});

		it('should include results for each finding', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			const results = sarif.runs[0].results;
			expect(results.length).toBe(1);
			expect(results[0].ruleId).toBe('RV-RCE-001');
			expect(results[0].message.text).toContain('Remote Code Execution');
		});

		it('should include locations for sink node', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			const result = sarif.runs[0].results[0];
			expect(result.locations).toBeDefined();
			expect(result.locations?.[0].logicalLocations?.[0].name).toBe('Code');
		});

		it('should include related locations for source node', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			const result = sarif.runs[0].results[0];
			expect(result.relatedLocations).toBeDefined();
			expect(result.relatedLocations?.[0].logicalLocations?.[0].name).toBe('Webhook');
		});

		it('should include fixes when remediation steps exist', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			const result = sarif.runs[0].results[0];
			expect(result.fixes).toBeDefined();
			expect(result.fixes?.[0].description.text).toContain('Validate');
		});

		it('should include invocation with timestamp', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			const invocations = sarif.runs[0].invocations;
			expect(invocations).toBeDefined();
			expect(invocations?.[0].executionSuccessful).toBe(true);
			expect(invocations?.[0].startTimeUtc).toBe('2024-01-15T10:30:00.000Z');
		});

		it('should include CWE and OWASP references in rule properties', () => {
			const report = createMockReport();
			const sarif = formatAsSarif(report);

			const rule = sarif.runs[0].tool.driver.rules[0];
			expect(rule.properties?.cwe).toBe('CWE-94');
			expect(rule.properties?.owasp).toBe('A03:2021-Injection');
		});

		it('should handle multiple findings with same rule', () => {
			const findings = [
				createMockFinding({ id: 'f1' }),
				createMockFinding({ id: 'f2', source: { ...createMockFinding().source, node: 'Webhook2' } }),
			];
			const report = createMockReport({ findings });
			const sarif = formatAsSarif(report);

			// Should only have one rule
			expect(sarif.runs[0].tool.driver.rules.length).toBe(1);
			// But two results
			expect(sarif.runs[0].results.length).toBe(2);
		});
	});

	describe('generateMermaidDiagram', () => {
		it('should start with graph directive', () => {
			const report = createMockReport();
			const diagram = generateMermaidDiagram(report);

			expect(diagram).toMatch(/^graph (LR|TB|RL|BT)/);
		});

		it('should include subgraph for workflow', () => {
			const report = createMockReport();
			const diagram = generateMermaidDiagram(report);

			expect(diagram).toContain('subgraph Workflow');
			expect(diagram).toContain('end');
		});

		it('should include source and sink nodes with icons', () => {
			const report = createMockReport();
			const diagram = generateMermaidDiagram(report);

			// Source nodes should have yellow icon
			expect(diagram).toContain('Webhook');
			// Sink nodes should have red icon
			expect(diagram).toContain('Code');
		});

		it('should include edges between path nodes', () => {
			const report = createMockReport();
			const diagram = generateMermaidDiagram(report);

			expect(diagram).toContain('-->');
		});

		it('should include tainted labels on edges when enabled', () => {
			const report = createMockReport();
			const diagram = generateMermaidDiagram(report, { showTaintedPaths: true });

			expect(diagram).toContain('|"');
		});

		it('should include styling section', () => {
			const report = createMockReport();
			const diagram = generateMermaidDiagram(report);

			expect(diagram).toContain('%% Styling');
			expect(diagram).toContain('style');
		});

		it('should apply yellow style to source nodes', () => {
			const report = createMockReport();
			const diagram = generateMermaidDiagram(report);

			expect(diagram).toContain('#fff3cd'); // Yellow background
			expect(diagram).toContain('#ffc107'); // Yellow border
		});

		it('should apply red style to sink nodes', () => {
			const report = createMockReport();
			const diagram = generateMermaidDiagram(report);

			expect(diagram).toContain('#f8d7da'); // Red background
			expect(diagram).toContain('#dc3545'); // Red border
		});

		it('should show no findings message when empty', () => {
			const report = createMockReport({ findings: [], nodeAssessments: [] });
			const diagram = generateMermaidDiagram(report);

			expect(diagram).toContain('No vulnerabilities detected');
		});

		it('should respect direction option', () => {
			const report = createMockReport();
			const diagramLR = generateMermaidDiagram(report, { direction: 'LR' });
			const diagramTB = generateMermaidDiagram(report, { direction: 'TB' });

			expect(diagramLR).toContain('graph LR');
			expect(diagramTB).toContain('graph TB');
		});

		it('should sanitize node names for valid Mermaid IDs', () => {
			const finding = createMockFinding({
				source: { ...createMockFinding().source, node: 'My Node (v2)' },
				path: ['My Node (v2)', 'Code'],
			});
			const report = createMockReport({ findings: [finding] });
			const diagram = generateMermaidDiagram(report);

			// Should replace special characters with underscores
			expect(diagram).toContain('My_Node__v2_');
		});

		it('should handle multiple findings and not duplicate edges', () => {
			const findings = [
				createMockFinding({ id: 'f1', path: ['Webhook', 'Set', 'Code'] }),
				createMockFinding({
					id: 'f2',
					path: ['Webhook', 'Set', 'Code'],
					source: { ...createMockFinding().source, field: 'body.other' },
				}),
			];
			const report = createMockReport({ findings });
			const diagram = generateMermaidDiagram(report);

			// Count occurrences of Webhook --> Set
			const matches = diagram.match(/Webhook.*-->.*Set/g);
			expect(matches?.length).toBe(1);
		});

		it('should escape quotes in node names', () => {
			const finding = createMockFinding({
				source: { ...createMockFinding().source, node: 'Node "Test"' },
				path: ['Node "Test"', 'Code'],
			});
			const report = createMockReport({ findings: [finding] });
			const diagram = generateMermaidDiagram(report);

			// Should replace quotes
			expect(diagram).not.toContain('Node "Test"');
		});
	});

	describe('integration scenarios', () => {
		it('should handle report with no findings for all formats', () => {
			const report = createMockReport({ findings: [], nodeAssessments: [] });

			const html = formatAsHtml(report);
			const slack = formatAsSlackBlocks(report);
			const sarif = formatAsSarif(report);
			const mermaid = generateMermaidDiagram(report);

			expect(html).toContain('No security vulnerabilities detected');
			expect(slack.length).toBeGreaterThan(0);
			expect(sarif.runs[0].results.length).toBe(0);
			expect(mermaid).toContain('No vulnerabilities detected');
		});

		it('should handle report with multiple severity levels', () => {
			const findings = [
				createMockFinding({ id: 'f1', severity: 'critical', title: 'Critical Bug' }),
				createMockFinding({ id: 'f2', severity: 'high', title: 'High Bug' }),
				createMockFinding({ id: 'f3', severity: 'medium', title: 'Medium Bug' }),
				createMockFinding({ id: 'f4', severity: 'low', title: 'Low Bug' }),
			];
			const report = createMockReport({
				findings,
				summary: {
					totalFindings: 4,
					bySeverity: { critical: 1, high: 1, medium: 1, low: 1, info: 0 },
					byCategory: {},
					affectedNodes: 4,
					uniqueSources: 1,
					uniqueSinks: 1,
				},
			});

			const html = formatAsHtml(report);
			const sarif = formatAsSarif(report);

			expect(html).toContain('Critical Bug');
			expect(html).toContain('High Bug');
			expect(html).toContain('Medium Bug');
			expect(html).toContain('Low Bug');

			expect(sarif.runs[0].results.length).toBe(4);
		});

		it('should handle complex workflow paths', () => {
			const finding = createMockFinding({
				path: ['Webhook', 'IF', 'Set 1', 'Merge', 'Code'],
			});
			const report = createMockReport({ findings: [finding] });

			const mermaid = generateMermaidDiagram(report);
			const html = formatAsHtml(report);

			expect(mermaid).toContain('IF');
			expect(mermaid).toContain('Set_1');
			expect(mermaid).toContain('Merge');
			expect(html).toContain('Webhook → IF → Set 1 → Merge → Code');
		});
	});
});
