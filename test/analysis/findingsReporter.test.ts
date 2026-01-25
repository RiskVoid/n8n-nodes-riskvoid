/**
 * Tests for Findings Reporter
 */

import {
	generateReport,
	calculateRiskScore,
	getRiskLevel,
	formatFinding,
	generateReportSummary,
	taintPathsToFindings,
} from '../../nodes/RiskVoid/analysis/findingsReporter';
import type { ReportOptions } from '../../nodes/RiskVoid/analysis/findingsReporter';
import type { Finding, RulesResult } from '../../nodes/RiskVoid/rules/types';
import type { AnalysisResult, TaintPath, TaintSource, SecuritySink } from '../../nodes/RiskVoid/types/taint';

describe('findingsReporter', () => {
	// Helper to create mock findings
	function createMockFinding(overrides: Partial<Finding> = {}): Finding {
		return {
			id: 'test-finding-001',
			ruleId: 'RV-TEST-001',
			severity: 'high',
			confidence: 'high',
			title: 'Test Vulnerability',
			description: 'Test description',
			category: 'injection',
			source: {
				node: 'Webhook',
				nodeType: 'n8n-nodes-base.webhook',
				field: 'body',
			},
			sink: {
				node: 'Code',
				nodeType: 'n8n-nodes-base.code',
				parameter: 'jsCode',
			},
			path: ['Webhook', 'Set', 'Code'],
			remediation: {
				summary: 'Test remediation',
				steps: ['Step 1', 'Step 2'],
			},
			references: {
				cwe: 'CWE-94',
			},
			metadata: {},
			...overrides,
		};
	}

	// Helper to create mock analysis result
	function createMockAnalysisResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
		return {
			success: true,
			workflow: {
				id: 'test-workflow',
				name: 'Test Workflow',
				nodeCount: 5,
				connectionCount: 4,
				hasCycles: false,
			},
			analysis: {
				sources: [],
				sinks: [],
				vulnerablePaths: [],
				entryPoints: ['Webhook'],
				exitPoints: ['HTTP Request'],
				duration: 50,
			},
			errors: [],
			warnings: [],
			...overrides,
		};
	}

	// Helper to create mock rules result
	function createMockRulesResult(findings: Finding[] = []): RulesResult {
		return {
			findings,
			rulesRun: 6,
			rulesSkipped: 0,
			errors: [],
			duration: 10,
		};
	}

	describe('generateReport', () => {
		it('should generate a complete report with no findings', () => {
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult();

			const report = generateReport(analysisResult, rulesResult);

			expect(report.metadata.version).toBe('1.0.0');
			expect(report.workflow.name).toBe('Test Workflow');
			expect(report.summary.totalFindings).toBe(0);
			expect(report.risk.score).toBe(0);
			expect(report.risk.level).toBe('none');
			expect(report.findings).toEqual([]);
		});

		it('should generate a report with findings sorted by severity', () => {
			const findings = [
				createMockFinding({ id: '1', severity: 'low' }),
				createMockFinding({ id: '2', severity: 'critical' }),
				createMockFinding({ id: '3', severity: 'high' }),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.findings[0].severity).toBe('critical');
			expect(report.findings[1].severity).toBe('high');
			expect(report.findings[2].severity).toBe('low');
		});

		it('should calculate correct summary statistics', () => {
			const findings = [
				createMockFinding({ id: '1', severity: 'critical', category: 'injection' }),
				createMockFinding({ id: '2', severity: 'high', category: 'injection' }),
				createMockFinding({ id: '3', severity: 'medium', category: 'ssrf' }),
				createMockFinding({
					id: '4',
					severity: 'low',
					category: 'credential-exposure',
					source: { node: 'Slack', nodeType: 'n8n-nodes-base.slack', field: 'text' },
				}),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.summary.totalFindings).toBe(4);
			expect(report.summary.bySeverity.critical).toBe(1);
			expect(report.summary.bySeverity.high).toBe(1);
			expect(report.summary.bySeverity.medium).toBe(1);
			expect(report.summary.bySeverity.low).toBe(1);
			expect(report.summary.byCategory['injection']).toBe(2);
			expect(report.summary.byCategory['ssrf']).toBe(1);
			expect(report.summary.uniqueSources).toBe(2); // Webhook and Slack
		});

		it('should group findings by category', () => {
			const findings = [
				createMockFinding({ id: '1', category: 'injection' }),
				createMockFinding({ id: '2', category: 'injection' }),
				createMockFinding({ id: '3', category: 'ssrf' }),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.findingsByCategory.length).toBe(2);
			const injectionGroup = report.findingsByCategory.find((g) => g.key === 'injection');
			const ssrfGroup = report.findingsByCategory.find((g) => g.key === 'ssrf');

			expect(injectionGroup?.count).toBe(2);
			expect(ssrfGroup?.count).toBe(1);
		});

		it('should group findings by severity', () => {
			const findings = [
				createMockFinding({ id: '1', severity: 'critical' }),
				createMockFinding({ id: '2', severity: 'high' }),
				createMockFinding({ id: '3', severity: 'high' }),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.findingsBySeverity.length).toBe(2);
			const criticalGroup = report.findingsBySeverity.find((g) => g.key === 'critical');
			const highGroup = report.findingsBySeverity.find((g) => g.key === 'high');

			expect(criticalGroup?.count).toBe(1);
			expect(highGroup?.count).toBe(2);
		});

		it('should generate node assessments', () => {
			const findings = [
				createMockFinding({
					id: '1',
					source: { node: 'Webhook', nodeType: 'n8n-nodes-base.webhook', field: 'body' },
					sink: { node: 'Code', nodeType: 'n8n-nodes-base.code', parameter: 'jsCode' },
					path: ['Webhook', 'Set', 'Code'],
					severity: 'critical',
				}),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.nodeAssessments.length).toBe(3); // Webhook, Set, Code

			const webhookAssessment = report.nodeAssessments.find((n) => n.name === 'Webhook');
			expect(webhookAssessment?.role).toBe('source');

			const codeAssessment = report.nodeAssessments.find((n) => n.name === 'Code');
			expect(codeAssessment?.role).toBe('sink');

			const setAssessment = report.nodeAssessments.find((n) => n.name === 'Set');
			expect(setAssessment?.role).toBe('path');
		});

		it('should respect includeNodeAssessments option', () => {
			const findings = [createMockFinding()];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);
			const options: ReportOptions = { includeNodeAssessments: false };

			const report = generateReport(analysisResult, rulesResult, options);

			expect(report.nodeAssessments).toEqual([]);
		});

		it('should include rule execution statistics', () => {
			const analysisResult = createMockAnalysisResult();
			const rulesResult: RulesResult = {
				findings: [],
				rulesRun: 5,
				rulesSkipped: 1,
				errors: [{ ruleId: 'RV-TEST-001', message: 'Test error' }],
				duration: 10,
			};

			const report = generateReport(analysisResult, rulesResult);

			expect(report.ruleStats.rulesRun).toBe(5);
			expect(report.ruleStats.rulesSkipped).toBe(1);
			expect(report.ruleStats.errors).toContain('RV-TEST-001: Test error');
		});

		it('should include warnings from analysis', () => {
			const analysisResult = createMockAnalysisResult({
				warnings: ['Test warning 1', 'Test warning 2'],
			});
			const rulesResult = createMockRulesResult();

			const report = generateReport(analysisResult, rulesResult);

			expect(report.warnings).toEqual(['Test warning 1', 'Test warning 2']);
		});

		it('should generate recommendations based on findings', () => {
			const findings = [
				createMockFinding({ category: 'injection' }),
				createMockFinding({ category: 'ssrf' }),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.recommendations.length).toBeGreaterThan(0);
			expect(report.recommendations.some((r) => r.toLowerCase().includes('input') || r.toLowerCase().includes('validation'))).toBe(true);
		});
	});

	describe('calculateRiskScore', () => {
		it('should return 0 for no findings', () => {
			expect(calculateRiskScore([])).toBe(0);
		});

		it('should calculate score based on severity', () => {
			const criticalFinding = createMockFinding({ severity: 'critical', confidence: 'high' });
			const score = calculateRiskScore([criticalFinding]);

			expect(score).toBe(50); // Critical base score
		});

		it('should apply confidence multipliers', () => {
			const lowConfidenceFinding = createMockFinding({ severity: 'critical', confidence: 'low' });
			const score = calculateRiskScore([lowConfidenceFinding]);

			expect(score).toBe(30); // 50 * 0.6
		});

		it('should accumulate scores from multiple findings', () => {
			const findings = [
				createMockFinding({ severity: 'high', confidence: 'high' }), // 35
				createMockFinding({ severity: 'medium', confidence: 'high' }), // 20
			];
			const score = calculateRiskScore(findings);

			expect(score).toBe(55); // 35 + 20
		});

		it('should cap score at 100', () => {
			const findings = [
				createMockFinding({ severity: 'critical', confidence: 'high' }), // 50
				createMockFinding({ severity: 'critical', confidence: 'high' }), // 50
				createMockFinding({ severity: 'critical', confidence: 'high' }), // 50
			];
			const score = calculateRiskScore(findings);

			expect(score).toBe(100);
		});
	});

	describe('getRiskLevel', () => {
		it('should return none for score 0', () => {
			expect(getRiskLevel(0)).toBe('none');
		});

		it('should return low for score 1-19', () => {
			expect(getRiskLevel(1)).toBe('low');
			expect(getRiskLevel(19)).toBe('low');
		});

		it('should return medium for score 20-39', () => {
			expect(getRiskLevel(20)).toBe('medium');
			expect(getRiskLevel(39)).toBe('medium');
		});

		it('should return high for score 40-69', () => {
			expect(getRiskLevel(40)).toBe('high');
			expect(getRiskLevel(69)).toBe('high');
		});

		it('should return critical for score 70+', () => {
			expect(getRiskLevel(70)).toBe('critical');
			expect(getRiskLevel(100)).toBe('critical');
		});
	});

	describe('formatFinding', () => {
		it('should format a finding as text', () => {
			const finding = createMockFinding();
			const formatted = formatFinding(finding);

			expect(formatted).toContain('[HIGH]');
			expect(formatted).toContain('Test Vulnerability');
			expect(formatted).toContain('Webhook');
			expect(formatted).toContain('Code');
			expect(formatted).toContain('Test remediation');
			expect(formatted).toContain('CWE-94');
		});

		it('should handle findings without CWE', () => {
			const finding = createMockFinding({ references: {} });
			const formatted = formatFinding(finding);

			expect(formatted).not.toContain('Reference:');
		});
	});

	describe('generateReportSummary', () => {
		it('should generate a text summary', () => {
			const findings = [
				createMockFinding({ severity: 'critical' }),
				createMockFinding({ severity: 'high' }),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);
			const report = generateReport(analysisResult, rulesResult);

			const summary = generateReportSummary(report);

			expect(summary).toContain('Test Workflow');
			expect(summary).toContain('Risk Score:');
			expect(summary).toContain('Total Findings: 2');
			expect(summary).toContain('Critical: 1');
			expect(summary).toContain('High: 1');
		});
	});

	describe('taintPathsToFindings', () => {
		it('should convert taint paths to findings', () => {
			const taintPaths: TaintPath[] = [
				{
					id: 'path-1',
					source: {
						nodeName: 'Webhook',
						nodeType: 'n8n-nodes-base.webhook',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						classification: {} as TaintSource['classification'],
					},
					sink: {
						nodeName: 'Code',
						nodeType: 'n8n-nodes-base.code',
						severity: 'critical',
						riskType: 'RCE',
						dangerousParams: [],
						classification: {} as SecuritySink['classification'],
					},
					path: ['Webhook', 'Set', 'Code'],
					taintedField: 'body',
					sinkParam: 'jsCode',
					severity: 'critical',
					sanitized: false,
					sanitizerNodes: [],
					confidence: 'high',
				},
			];

			const findings = taintPathsToFindings(taintPaths);

			expect(findings.length).toBe(1);
			expect(findings[0].severity).toBe('critical');
			expect(findings[0].title).toContain('RCE');
			expect(findings[0].source.node).toBe('Webhook');
			expect(findings[0].sink.node).toBe('Code');
			expect(findings[0].category).toBe('injection');
		});

		it('should handle different risk types', () => {
			const taintPaths: TaintPath[] = [
				{
					id: 'path-1',
					source: {
						nodeName: 'Webhook',
						nodeType: 'n8n-nodes-base.webhook',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						classification: {} as TaintSource['classification'],
					},
					sink: {
						nodeName: 'HTTP Request',
						nodeType: 'n8n-nodes-base.httpRequest',
						severity: 'high',
						riskType: 'SSRF',
						dangerousParams: [],
						classification: {} as SecuritySink['classification'],
					},
					path: ['Webhook', 'HTTP Request'],
					taintedField: 'body',
					sinkParam: 'url',
					severity: 'high',
					sanitized: false,
					sanitizerNodes: [],
					confidence: 'high',
				},
			];

			const findings = taintPathsToFindings(taintPaths);

			expect(findings[0].category).toBe('ssrf');
		});

		it('should preserve sanitizer information in metadata', () => {
			const taintPaths: TaintPath[] = [
				{
					id: 'path-1',
					source: {
						nodeName: 'Webhook',
						nodeType: 'n8n-nodes-base.webhook',
						trustLevel: 'untrusted',
						taintedFields: ['body'],
						classification: {} as TaintSource['classification'],
					},
					sink: {
						nodeName: 'Code',
						nodeType: 'n8n-nodes-base.code',
						severity: 'critical',
						riskType: 'RCE',
						dangerousParams: [],
						classification: {} as SecuritySink['classification'],
					},
					path: ['Webhook', 'IF', 'Code'],
					taintedField: 'body',
					sinkParam: 'jsCode',
					severity: 'high', // Reduced from critical
					sanitized: true,
					sanitizerNodes: ['IF'],
					confidence: 'medium',
				},
			];

			const findings = taintPathsToFindings(taintPaths);

			expect(findings[0].metadata.sanitized).toBe(true);
			expect(findings[0].metadata.sanitizerNodes).toEqual(['IF']);
		});
	});

	describe('risk assessment', () => {
		it('should identify risk factors', () => {
			const findings = [
				createMockFinding({ severity: 'critical' }),
				createMockFinding({
					severity: 'high',
					source: { node: 'Slack', nodeType: 'n8n-nodes-base.slack', field: 'text' },
				}),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.risk.factors.some((f) => f.includes('critical'))).toBe(true);
			expect(report.risk.factors.some((f) => f.includes('Multiple') || f.includes('source'))).toBe(true);
		});

		it('should note workflow cycles as a risk factor', () => {
			const findings = [createMockFinding()];
			const analysisResult = createMockAnalysisResult({
				workflow: {
					id: 'test',
					name: 'Test',
					nodeCount: 5,
					connectionCount: 5,
					hasCycles: true,
				},
			});
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.risk.factors.some((f) => f.toLowerCase().includes('cycle'))).toBe(true);
		});

		it('should generate top recommendations', () => {
			const findings = [
				createMockFinding({ severity: 'critical', category: 'injection' }),
			];
			const analysisResult = createMockAnalysisResult();
			const rulesResult = createMockRulesResult(findings);

			const report = generateReport(analysisResult, rulesResult);

			expect(report.risk.recommendations.length).toBeGreaterThan(0);
		});
	});
});
