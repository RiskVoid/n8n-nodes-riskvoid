/**
 * End-to-End Integration Tests
 *
 * Tests the complete analysis pipeline from workflow JSON input to security report output.
 * Verifies that the full system correctly identifies vulnerabilities across all categories.
 */

import {
	analyzeWorkflow,
	parseWorkflow,
	buildGraph,
	generateReport,
} from '../../nodes/RiskVoid/analysis';
import { findTaintSources, findSecuritySinks, analyzeTaintFlows } from '../../nodes/RiskVoid/analysis/taintAnalyzer';
import {
	initializeBuiltInRules,
	runAllRules,
	clearAllRules,
} from '../../nodes/RiskVoid/rules';
import type { RuleContext } from '../../nodes/RiskVoid/rules/types';
import type { SecurityReport } from '../../nodes/RiskVoid/analysis/findingsReporter';
import {
	vulnerableCodeInjectionWorkflow,
	vulnerableCommandInjectionWorkflow,
	vulnerableSqlInjectionWorkflow,
	vulnerableSsrfWorkflow,
	vulnerablePromptInjectionWorkflow,
	vulnerableCredentialExposureWorkflow,
	complexVulnerableWorkflow,
	safeWorkflow,
	safeCodeWorkflow,
	safeSqlWorkflow,
	emptyWorkflow,
	allVulnerableWorkflows,
	allSafeWorkflows,
} from '../fixtures/workflows';

describe('End-to-End Integration Tests', () => {
	beforeAll(() => {
		clearAllRules();
		initializeBuiltInRules();
	});

	afterAll(() => {
		clearAllRules();
	});

	/**
	 * Helper to run the full analysis pipeline
	 */
	function runFullAnalysis(workflowJson: unknown): SecurityReport {
		// Step 1: Taint analysis
		const analysisResult = analyzeWorkflow(workflowJson);
		expect(analysisResult.success).toBe(true);

		// Step 2: Build rule context
		const parseResult = parseWorkflow(workflowJson);
		expect(parseResult.success).toBe(true);

		const graph = buildGraph(parseResult.workflow!);
		const sources = findTaintSources(parseResult.workflow!, graph);
		const sinks = findSecuritySinks(parseResult.workflow!, graph);
		const taintPaths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

		const ruleContext: RuleContext = {
			workflow: parseResult.workflow!,
			graph,
			sources,
			sinks,
			taintPaths,
		};

		// Step 3: Run detection rules
		const rulesResult = runAllRules(ruleContext);

		// Step 4: Generate report
		return generateReport(analysisResult, rulesResult);
	}

	describe('Code Injection Detection', () => {
		it('should detect code injection vulnerability', () => {
			const report = runFullAnalysis(vulnerableCodeInjectionWorkflow);

			expect(report.summary.totalFindings).toBeGreaterThan(0);
			expect(report.findings.some((f) => f.ruleId === 'RV-RCE-001')).toBe(true);
			expect(report.risk.level).not.toBe('none');
		});

		it('should not flag safe code workflows', () => {
			const report = runFullAnalysis(safeCodeWorkflow);

			const codeInjectionFindings = report.findings.filter((f) => f.ruleId === 'RV-RCE-001');
			expect(codeInjectionFindings.length).toBe(0);
		});
	});

	describe('Command Injection Detection', () => {
		it('should detect command injection vulnerability', () => {
			const report = runFullAnalysis(vulnerableCommandInjectionWorkflow);

			expect(report.summary.totalFindings).toBeGreaterThan(0);
			expect(report.findings.some((f) => f.ruleId === 'RV-CMDI-001')).toBe(true);
		});
	});

	describe('SQL Injection Detection', () => {
		it('should detect SQL injection vulnerability', () => {
			const report = runFullAnalysis(vulnerableSqlInjectionWorkflow);

			expect(report.summary.totalFindings).toBeGreaterThan(0);
			expect(report.findings.some((f) => f.ruleId === 'RV-SQLI-001')).toBe(true);
		});

		it('should not flag parameterized queries', () => {
			const report = runFullAnalysis(safeSqlWorkflow);

			const sqlInjectionFindings = report.findings.filter((f) => f.ruleId === 'RV-SQLI-001');
			expect(sqlInjectionFindings.length).toBe(0);
		});
	});

	describe('SSRF Detection', () => {
		it('should detect SSRF vulnerability', () => {
			const report = runFullAnalysis(vulnerableSsrfWorkflow);

			expect(report.summary.totalFindings).toBeGreaterThan(0);
			expect(report.findings.some((f) => f.ruleId === 'RV-SSRF-001')).toBe(true);
		});
	});

	describe('Prompt Injection Detection', () => {
		it('should detect prompt injection vulnerability', () => {
			const report = runFullAnalysis(vulnerablePromptInjectionWorkflow);

			expect(report.summary.totalFindings).toBeGreaterThan(0);
			expect(report.findings.some((f) => f.ruleId === 'RV-PI-001')).toBe(true);
		});
	});

	describe('Credential Exposure Detection', () => {
		it('should detect hardcoded credentials', () => {
			const report = runFullAnalysis(vulnerableCredentialExposureWorkflow);

			expect(report.summary.totalFindings).toBeGreaterThan(0);
			expect(report.findings.some((f) => f.ruleId === 'RV-CRED-001')).toBe(true);
		});
	});

	describe('Complex Workflow Analysis', () => {
		it('should detect multiple vulnerabilities in complex workflow', () => {
			const report = runFullAnalysis(complexVulnerableWorkflow);

			// Should find multiple vulnerability types
			expect(report.summary.totalFindings).toBeGreaterThan(1);

			// Should have high risk score due to multiple vulnerabilities
			expect(report.risk.score).toBeGreaterThan(20);
		});

		it('should generate appropriate recommendations for multiple vulnerabilities', () => {
			const report = runFullAnalysis(complexVulnerableWorkflow);

			expect(report.recommendations.length).toBeGreaterThan(0);
		});
	});

	describe('Safe Workflow Verification', () => {
		it('should report no/low risk for safe workflows', () => {
			const report = runFullAnalysis(safeWorkflow);

			expect(report.risk.level).toBe('none');
			expect(report.risk.score).toBe(0);
		});

		it('should handle empty workflows gracefully', () => {
			// Empty workflows may fail analysis - that's expected
			const analysisResult = analyzeWorkflow(emptyWorkflow);

			// Either it succeeds with no findings, or it fails gracefully
			if (analysisResult.success) {
				const parseResult = parseWorkflow(emptyWorkflow);
				if (parseResult.success && parseResult.workflow) {
					const graph = buildGraph(parseResult.workflow);
					const sources = findTaintSources(parseResult.workflow, graph);
					const sinks = findSecuritySinks(parseResult.workflow, graph);
					const taintPaths = analyzeTaintFlows(parseResult.workflow, graph, sources, sinks);

					const ruleContext: RuleContext = {
						workflow: parseResult.workflow,
						graph,
						sources,
						sinks,
						taintPaths,
					};

					const rulesResult = runAllRules(ruleContext);
					const report = generateReport(analysisResult, rulesResult);

					expect(report.summary.totalFindings).toBe(0);
					expect(report.risk.level).toBe('none');
				}
			} else {
				// Empty workflow failing to parse is acceptable
				expect(analysisResult.errors.length).toBeGreaterThan(0);
			}
		});
	});

	describe('Report Structure', () => {
		it('should generate complete report with all sections', () => {
			const report = runFullAnalysis(vulnerableCodeInjectionWorkflow);

			// Metadata
			expect(report.metadata.version).toBeDefined();
			expect(report.metadata.generatedAt).toBeDefined();

			// Workflow info
			expect(report.workflow.name).toBeDefined();
			expect(report.workflow.nodeCount).toBeGreaterThan(0);

			// Summary
			expect(report.summary.totalFindings).toBeDefined();
			expect(report.summary.bySeverity).toBeDefined();
			expect(report.summary.byCategory).toBeDefined();

			// Risk assessment
			expect(report.risk.score).toBeDefined();
			expect(report.risk.level).toBeDefined();
			expect(report.risk.factors).toBeDefined();
			expect(report.risk.recommendations).toBeDefined();

			// Findings
			expect(Array.isArray(report.findings)).toBe(true);

			// Grouped findings
			expect(Array.isArray(report.findingsByCategory)).toBe(true);
			expect(Array.isArray(report.findingsBySeverity)).toBe(true);

			// Recommendations
			expect(Array.isArray(report.recommendations)).toBe(true);
		});

		it('should include remediation guidance in findings', () => {
			const report = runFullAnalysis(vulnerableCodeInjectionWorkflow);

			for (const finding of report.findings) {
				expect(finding.remediation).toBeDefined();
				expect(finding.remediation.summary).toBeDefined();
				expect(Array.isArray(finding.remediation.steps)).toBe(true);
			}
		});

		it('should include security references in findings', () => {
			const report = runFullAnalysis(vulnerableCodeInjectionWorkflow);

			for (const finding of report.findings) {
				expect(finding.references).toBeDefined();
				// Most findings should have CWE reference
				if (finding.ruleId.startsWith('RV-')) {
					expect(finding.references.cwe || finding.references.owasp).toBeDefined();
				}
			}
		});
	});

	describe('Batch Processing', () => {
		it('should detect vulnerabilities in all vulnerable workflows', () => {
			const failedWorkflows: string[] = [];
			for (const workflow of allVulnerableWorkflows) {
				const report = runFullAnalysis(workflow);
				if (report.summary.totalFindings === 0) {
					failedWorkflows.push(workflow.name || 'unknown');
				}
			}
			if (failedWorkflows.length > 0) {
				throw new Error(`No findings detected in: ${failedWorkflows.join(', ')}`);
			}
		});

		it('should report low/no risk for all safe workflows', () => {
			for (const workflow of allSafeWorkflows) {
				const report = runFullAnalysis(workflow);
				// Safe workflows should have no critical or high findings from taint analysis
				// (may have some credential-related findings if they use credentials)
				const criticalHighFindings = report.findings.filter(
					(f) => f.severity === 'critical' || f.severity === 'high',
				);
				expect(criticalHighFindings.length).toBeLessThanOrEqual(1);
			}
		});
	});

	describe('Performance', () => {
		it('should complete analysis in under 500ms for standard workflow', () => {
			const startTime = Date.now();
			runFullAnalysis(complexVulnerableWorkflow);
			const duration = Date.now() - startTime;

			expect(duration).toBeLessThan(500);
		});

		it('should complete batch analysis in reasonable time', () => {
			const startTime = Date.now();

			for (const workflow of allVulnerableWorkflows) {
				runFullAnalysis(workflow);
			}

			const duration = Date.now() - startTime;
			const avgPerWorkflow = duration / allVulnerableWorkflows.length;

			// Average should be under 100ms per workflow
			expect(avgPerWorkflow).toBeLessThan(100);
		});
	});

	describe('Node Assessment', () => {
		it('should correctly identify source and sink nodes', () => {
			const report = runFullAnalysis(vulnerableCodeInjectionWorkflow);

			const sourceNodes = report.nodeAssessments.filter((n) => n.role === 'source');
			const sinkNodes = report.nodeAssessments.filter((n) => n.role === 'sink');

			expect(sourceNodes.length).toBeGreaterThan(0);
			expect(sinkNodes.length).toBeGreaterThan(0);
		});

		it('should track finding counts per node', () => {
			const report = runFullAnalysis(complexVulnerableWorkflow);

			for (const assessment of report.nodeAssessments) {
				expect(assessment.findingCount).toBeGreaterThanOrEqual(0);
				expect(assessment.findingIds.length).toBe(assessment.findingCount);
			}
		});
	});

	describe('Severity Filtering', () => {
		it('should filter findings by minimum severity', () => {
			// First get all findings
			const fullReport = runFullAnalysis(complexVulnerableWorkflow);

			// Now get with severity filter
			const analysisResult = analyzeWorkflow(complexVulnerableWorkflow);
			const parseResult = parseWorkflow(complexVulnerableWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);
			const taintPaths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

			const ruleContext: RuleContext = {
				workflow: parseResult.workflow!,
				graph,
				sources,
				sinks,
				taintPaths,
			};

			const rulesResult = runAllRules(ruleContext, { minSeverity: 'high' });
			const filteredReport = generateReport(analysisResult, rulesResult);

			// Filtered report should have fewer or equal findings
			expect(filteredReport.summary.totalFindings).toBeLessThanOrEqual(
				fullReport.summary.totalFindings,
			);

			// All findings should be high or critical
			for (const finding of filteredReport.findings) {
				expect(['critical', 'high']).toContain(finding.severity);
			}
		});
	});

	describe('Category Filtering', () => {
		it('should filter findings by category', () => {
			const analysisResult = analyzeWorkflow(complexVulnerableWorkflow);
			const parseResult = parseWorkflow(complexVulnerableWorkflow);
			const graph = buildGraph(parseResult.workflow!);
			const sources = findTaintSources(parseResult.workflow!, graph);
			const sinks = findSecuritySinks(parseResult.workflow!, graph);
			const taintPaths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

			const ruleContext: RuleContext = {
				workflow: parseResult.workflow!,
				graph,
				sources,
				sinks,
				taintPaths,
			};

			const rulesResult = runAllRules(ruleContext, { categories: ['injection'] });
			const filteredReport = generateReport(analysisResult, rulesResult);

			// All findings should be in injection category
			for (const finding of filteredReport.findings) {
				expect(finding.category).toBe('injection');
			}
		});
	});
});
