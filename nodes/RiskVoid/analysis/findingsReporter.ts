/**
 * Findings Reporter - Generates structured security reports
 *
 * This module takes raw analysis results and rule findings, then produces
 * a comprehensive security report with risk scoring, recommendations,
 * and actionable remediation guidance.
 */

import type {
	Finding,
	FindingSeverity,
	RulesResult,
	FindingCategory,
} from '../rules/types';
import type { AnalysisResult, TaintPath } from '../types/taint';
import { SEVERITY_ORDER } from '../rules/types';

/**
 * Summary statistics for a security report
 */
export interface ReportSummary {
	/** Total number of findings */
	totalFindings: number;
	/** Breakdown by severity */
	bySeverity: Record<FindingSeverity, number>;
	/** Breakdown by category */
	byCategory: Record<string, number>;
	/** Number of unique affected nodes */
	affectedNodes: number;
	/** Number of unique source nodes */
	uniqueSources: number;
	/** Number of unique sink nodes */
	uniqueSinks: number;
}

/**
 * Overall risk assessment
 */
export interface RiskAssessment {
	/** Risk score from 0-100 */
	score: number;
	/** Risk level: none, low, medium, high, critical */
	level: 'none' | 'low' | 'medium' | 'high' | 'critical';
	/** Factors contributing to the score */
	factors: string[];
	/** Top recommendations */
	recommendations: string[];
}

/**
 * A grouped set of findings for display
 */
export interface FindingGroup {
	/** Group key (e.g., category or severity) */
	key: string;
	/** Display label */
	label: string;
	/** Findings in this group */
	findings: Finding[];
	/** Count of findings */
	count: number;
}

/**
 * Node-level security assessment
 */
export interface NodeAssessment {
	/** Node name */
	name: string;
	/** Node type */
	type: string;
	/** Role in vulnerabilities (source, sink, path) */
	role: 'source' | 'sink' | 'path' | 'both';
	/** Number of findings involving this node */
	findingCount: number;
	/** Highest severity of findings involving this node */
	maxSeverity: FindingSeverity;
	/** Related finding IDs */
	findingIds: string[];
}

/**
 * Complete security report
 */
export interface SecurityReport {
	/** Report metadata */
	metadata: {
		/** Timestamp when report was generated */
		generatedAt: string;
		/** RiskVoid version */
		version: string;
		/** Analysis duration in ms */
		duration: number;
	};
	/** Workflow information */
	workflow: {
		id: string;
		name: string;
		nodeCount: number;
		connectionCount: number;
		hasCycles: boolean;
	};
	/** Summary statistics */
	summary: ReportSummary;
	/** Risk assessment */
	risk: RiskAssessment;
	/** All findings, sorted by severity */
	findings: Finding[];
	/** Findings grouped by category */
	findingsByCategory: FindingGroup[];
	/** Findings grouped by severity */
	findingsBySeverity: FindingGroup[];
	/** Per-node security assessment */
	nodeAssessments: NodeAssessment[];
	/** Top recommendations */
	recommendations: string[];
	/** Any warnings from analysis */
	warnings: string[];
	/** Rule execution statistics */
	ruleStats: {
		rulesRun: number;
		rulesSkipped: number;
		errors: string[];
	};
}

/**
 * Options for report generation
 */
export interface ReportOptions {
	/** Include node assessments (default: true) */
	includeNodeAssessments?: boolean;
	/** Maximum findings per category in grouped view (default: unlimited) */
	maxFindingsPerGroup?: number;
	/** Include remediation details (default: true) */
	includeRemediation?: boolean;
}

/**
 * Category display labels
 */
const CATEGORY_LABELS: Record<FindingCategory, string> = {
	injection: 'Code/Command Injection',
	ssrf: 'Server-Side Request Forgery',
	'credential-exposure': 'Credential Exposure',
	'prompt-injection': 'Prompt Injection',
	configuration: 'Security Misconfiguration',
	'information-disclosure': 'Information Disclosure',
};

/**
 * Severity display labels
 */
const SEVERITY_LABELS: Record<FindingSeverity, string> = {
	critical: 'Critical',
	high: 'High',
	medium: 'Medium',
	low: 'Low',
	info: 'Informational',
};

/**
 * Generate a complete security report from analysis results and rule findings
 */
export function generateReport(
	analysisResult: AnalysisResult,
	rulesResult: RulesResult,
	options: ReportOptions = {},
): SecurityReport {
	const {
		includeNodeAssessments = true,
		includeRemediation = true,
	} = options;

	// Sort findings by severity
	const sortedFindings = sortFindingsBySeverity(rulesResult.findings);

	// Optionally strip remediation details
	const findings = includeRemediation
		? sortedFindings
		: sortedFindings.map((f) => ({
				...f,
				remediation: { summary: f.remediation.summary, steps: [] },
			}));

	// Calculate summary
	const summary = calculateSummary(findings);

	// Calculate risk assessment
	const risk = calculateRiskAssessment(findings, analysisResult);

	// Group findings
	const findingsByCategory = groupFindingsByCategory(findings, options.maxFindingsPerGroup);
	const findingsBySeverity = groupFindingsBySeverity(findings, options.maxFindingsPerGroup);

	// Generate node assessments
	const nodeAssessments = includeNodeAssessments
		? generateNodeAssessments(findings)
		: [];

	// Generate recommendations
	const recommendations = generateRecommendations(findings, analysisResult);

	return {
		metadata: {
			generatedAt: new Date().toISOString(),
			version: '1.0.0',
			duration: (analysisResult.analysis?.duration || 0) + rulesResult.duration,
		},
		workflow: analysisResult.workflow || {
			id: 'unknown',
			name: 'Unknown Workflow',
			nodeCount: 0,
			connectionCount: 0,
			hasCycles: false,
		},
		summary,
		risk,
		findings,
		findingsByCategory,
		findingsBySeverity,
		nodeAssessments,
		recommendations,
		warnings: analysisResult.warnings,
		ruleStats: {
			rulesRun: rulesResult.rulesRun,
			rulesSkipped: rulesResult.rulesSkipped,
			errors: rulesResult.errors.map((e) => `${e.ruleId}: ${e.message}`),
		},
	};
}

/**
 * Sort findings by severity (most severe first)
 */
function sortFindingsBySeverity(findings: Finding[]): Finding[] {
	return [...findings].sort(
		(a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
	);
}

/**
 * Calculate summary statistics
 */
function calculateSummary(findings: Finding[]): ReportSummary {
	const bySeverity: Record<FindingSeverity, number> = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0,
	};

	const byCategory: Record<string, number> = {};
	const affectedNodesSet = new Set<string>();
	const sourcesSet = new Set<string>();
	const sinksSet = new Set<string>();

	for (const finding of findings) {
		bySeverity[finding.severity]++;
		byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;

		// Track affected nodes
		affectedNodesSet.add(finding.source.node);
		affectedNodesSet.add(finding.sink.node);
		for (const node of finding.path) {
			affectedNodesSet.add(node);
		}

		sourcesSet.add(finding.source.node);
		sinksSet.add(finding.sink.node);
	}

	return {
		totalFindings: findings.length,
		bySeverity,
		byCategory,
		affectedNodes: affectedNodesSet.size,
		uniqueSources: sourcesSet.size,
		uniqueSinks: sinksSet.size,
	};
}

/**
 * Calculate overall risk assessment
 */
function calculateRiskAssessment(
	findings: Finding[],
	analysisResult: AnalysisResult,
): RiskAssessment {
	const factors: string[] = [];
	let score = 0;

	// Severity-based scoring - adjusted for realistic risk levels
	const severityScores: Record<FindingSeverity, number> = {
		critical: 50,
		high: 35,
		medium: 20,
		low: 8,
		info: 2,
	};

	const confidenceMultipliers: Record<string, number> = {
		high: 1.0,
		medium: 0.8,
		low: 0.6,
	};

	for (const finding of findings) {
		const baseScore = severityScores[finding.severity];
		const multiplier = confidenceMultipliers[finding.confidence] || 0.7;
		score += baseScore * multiplier;
	}

	// Cap score at 100
	score = Math.min(100, Math.round(score));

	// Determine factors
	const summary = calculateSummary(findings);

	if (summary.bySeverity.critical > 0) {
		factors.push(`${summary.bySeverity.critical} critical severity finding(s)`);
	}
	if (summary.bySeverity.high > 0) {
		factors.push(`${summary.bySeverity.high} high severity finding(s)`);
	}
	if (summary.uniqueSources > 1) {
		factors.push(`Multiple untrusted data sources (${summary.uniqueSources})`);
	}
	if (summary.uniqueSinks > 3) {
		factors.push(`Many security-sensitive operations (${summary.uniqueSinks})`);
	}
	if (analysisResult.workflow?.hasCycles) {
		factors.push('Workflow contains cycles (may indicate complex data flow)');
	}

	// Determine risk level - minimum level based on highest severity finding
	let level: RiskAssessment['level'];

	// First, set minimum level based on finding severities
	// A critical finding = at least high risk level
	// A high finding = at least medium risk level
	let minLevel: RiskAssessment['level'] = 'none';
	if (summary.bySeverity.critical > 0) {
		minLevel = 'high'; // Critical findings guarantee at least high risk
	} else if (summary.bySeverity.high > 0) {
		minLevel = 'medium'; // High findings guarantee at least medium risk
	} else if (summary.bySeverity.medium > 0) {
		minLevel = 'low'; // Medium findings guarantee at least low risk
	}

	// Then determine level from score
	if (score >= 70) {
		level = 'critical';
	} else if (score >= 40) {
		level = 'high';
	} else if (score >= 20) {
		level = 'medium';
	} else if (score > 0) {
		level = 'low';
	} else {
		level = 'none';
	}

	// Apply minimum level based on finding severity
	const levelOrder: Record<RiskAssessment['level'], number> = {
		none: 0,
		low: 1,
		medium: 2,
		high: 3,
		critical: 4,
	};
	if (levelOrder[minLevel] > levelOrder[level]) {
		level = minLevel;
	}

	// Generate recommendations based on findings
	const recommendations = generateTopRecommendations(findings);

	return {
		score,
		level,
		factors: factors.length > 0 ? factors : ['No significant risk factors detected'],
		recommendations,
	};
}

/**
 * Generate top-level recommendations
 */
function generateTopRecommendations(findings: Finding[]): string[] {
	const recommendations: string[] = [];
	const seenCategories = new Set<string>();

	// Get unique categories by severity
	const sortedFindings = sortFindingsBySeverity(findings);

	for (const finding of sortedFindings) {
		if (seenCategories.has(finding.category)) {
			continue;
		}
		seenCategories.add(finding.category);

		// Add the remediation summary for the first finding of each category
		recommendations.push(
			`[${CATEGORY_LABELS[finding.category] || finding.category}] ${finding.remediation.summary}`,
		);

		// Limit to top 5 recommendations
		if (recommendations.length >= 5) {
			break;
		}
	}

	if (recommendations.length === 0) {
		recommendations.push('No immediate security actions required');
	}

	return recommendations;
}

/**
 * Group findings by category
 */
function groupFindingsByCategory(
	findings: Finding[],
	maxPerGroup?: number,
): FindingGroup[] {
	const groups = new Map<string, Finding[]>();

	for (const finding of findings) {
		const category = finding.category;
		if (!groups.has(category)) {
			groups.set(category, []);
		}
		groups.get(category)!.push(finding);
	}

	return Array.from(groups.entries())
		.map(([key, groupFindings]) => ({
			key,
			label: CATEGORY_LABELS[key as FindingCategory] || key,
			findings: maxPerGroup ? groupFindings.slice(0, maxPerGroup) : groupFindings,
			count: groupFindings.length,
		}))
		.sort((a, b) => {
			// Sort by highest severity in group
			const aMaxSev = Math.min(...a.findings.map((f) => SEVERITY_ORDER[f.severity]));
			const bMaxSev = Math.min(...b.findings.map((f) => SEVERITY_ORDER[f.severity]));
			return aMaxSev - bMaxSev;
		});
}

/**
 * Group findings by severity
 */
function groupFindingsBySeverity(
	findings: Finding[],
	maxPerGroup?: number,
): FindingGroup[] {
	const severities: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
	const groups: FindingGroup[] = [];

	for (const severity of severities) {
		const groupFindings = findings.filter((f) => f.severity === severity);
		if (groupFindings.length > 0) {
			groups.push({
				key: severity,
				label: SEVERITY_LABELS[severity],
				findings: maxPerGroup ? groupFindings.slice(0, maxPerGroup) : groupFindings,
				count: groupFindings.length,
			});
		}
	}

	return groups;
}

/**
 * Generate per-node security assessments
 */
function generateNodeAssessments(findings: Finding[]): NodeAssessment[] {
	const nodeMap = new Map<
		string,
		{
			type: string;
			isSource: boolean;
			isSink: boolean;
			isPath: boolean;
			findingIds: string[];
			severities: FindingSeverity[];
		}
	>();

	for (const finding of findings) {
		// Track source
		const sourceKey = finding.source.node;
		if (!nodeMap.has(sourceKey)) {
			nodeMap.set(sourceKey, {
				type: finding.source.nodeType,
				isSource: false,
				isSink: false,
				isPath: false,
				findingIds: [],
				severities: [],
			});
		}
		const sourceNode = nodeMap.get(sourceKey)!;
		sourceNode.isSource = true;
		sourceNode.findingIds.push(finding.id);
		sourceNode.severities.push(finding.severity);

		// Track sink
		const sinkKey = finding.sink.node;
		if (!nodeMap.has(sinkKey)) {
			nodeMap.set(sinkKey, {
				type: finding.sink.nodeType,
				isSource: false,
				isSink: false,
				isPath: false,
				findingIds: [],
				severities: [],
			});
		}
		const sinkNode = nodeMap.get(sinkKey)!;
		sinkNode.isSink = true;
		if (!sinkNode.findingIds.includes(finding.id)) {
			sinkNode.findingIds.push(finding.id);
			sinkNode.severities.push(finding.severity);
		}

		// Track path nodes
		for (const pathNode of finding.path) {
			if (pathNode === sourceKey || pathNode === sinkKey) continue;

			if (!nodeMap.has(pathNode)) {
				nodeMap.set(pathNode, {
					type: 'unknown',
					isSource: false,
					isSink: false,
					isPath: false,
					findingIds: [],
					severities: [],
				});
			}
			const node = nodeMap.get(pathNode)!;
			node.isPath = true;
			if (!node.findingIds.includes(finding.id)) {
				node.findingIds.push(finding.id);
				node.severities.push(finding.severity);
			}
		}
	}

	// Convert to assessments
	const assessments: NodeAssessment[] = [];

	for (const [name, data] of nodeMap) {
		let role: NodeAssessment['role'];
		if (data.isSource && data.isSink) {
			role = 'both';
		} else if (data.isSource) {
			role = 'source';
		} else if (data.isSink) {
			role = 'sink';
		} else {
			role = 'path';
		}

		// Find max severity
		const maxSeverity = data.severities.reduce((max, sev) => {
			return SEVERITY_ORDER[sev] < SEVERITY_ORDER[max] ? sev : max;
		}, 'info' as FindingSeverity);

		assessments.push({
			name,
			type: data.type,
			role,
			findingCount: data.findingIds.length,
			maxSeverity,
			findingIds: [...new Set(data.findingIds)],
		});
	}

	// Sort by severity then by finding count
	return assessments.sort((a, b) => {
		const sevDiff = SEVERITY_ORDER[a.maxSeverity] - SEVERITY_ORDER[b.maxSeverity];
		if (sevDiff !== 0) return sevDiff;
		return b.findingCount - a.findingCount;
	});
}

/**
 * Generate workflow-level recommendations
 */
function generateRecommendations(
	findings: Finding[],
	analysisResult: AnalysisResult,
): string[] {
	const recommendations: string[] = [];

	if (findings.length === 0) {
		recommendations.push(
			'No security vulnerabilities detected. Continue following security best practices.',
		);
		return recommendations;
	}

	// Category-specific recommendations
	const categories = new Set(findings.map((f) => f.category));

	if (categories.has('injection')) {
		recommendations.push(
			'Add input validation nodes before code execution or command nodes. Consider using allowlist validation for expected input patterns.',
		);
	}

	if (categories.has('ssrf')) {
		recommendations.push(
			'Implement URL validation to restrict HTTP requests to approved domains. Block internal IP ranges and cloud metadata endpoints.',
		);
	}

	if (categories.has('credential-exposure')) {
		recommendations.push(
			'Use n8n credential management instead of hardcoded secrets. Review external outputs to ensure credentials are not leaked.',
		);
	}

	if (categories.has('prompt-injection')) {
		recommendations.push(
			'Use structured prompts with clear delimiters between system instructions and user input. Consider input sanitization for LLM prompts.',
		);
	}

	// Severity-based recommendations
	const summary = calculateSummary(findings);
	if (summary.bySeverity.critical > 0) {
		recommendations.push(
			'URGENT: Address critical vulnerabilities immediately before deploying this workflow to production.',
		);
	}

	// Source-based recommendations
	if (summary.uniqueSources > 2) {
		recommendations.push(
			'Multiple untrusted data sources detected. Consider consolidating input validation logic to a central point.',
		);
	}

	// Cycle warning
	if (analysisResult.workflow?.hasCycles) {
		recommendations.push(
			'Workflow contains cycles. Verify that loop exit conditions are properly validated to prevent infinite loops with malicious input.',
		);
	}

	return recommendations;
}

/**
 * Calculate risk score from findings (0-100)
 */
export function calculateRiskScore(findings: Finding[]): number {
	if (findings.length === 0) return 0;

	const severityScores: Record<FindingSeverity, number> = {
		critical: 50,
		high: 35,
		medium: 20,
		low: 8,
		info: 2,
	};

	const confidenceMultipliers: Record<string, number> = {
		high: 1.0,
		medium: 0.8,
		low: 0.6,
	};

	let score = 0;

	for (const finding of findings) {
		const baseScore = severityScores[finding.severity];
		const multiplier = confidenceMultipliers[finding.confidence] || 0.7;
		score += baseScore * multiplier;
	}

	return Math.min(100, Math.round(score));
}

/**
 * Get risk level from score
 */
export function getRiskLevel(score: number): 'none' | 'low' | 'medium' | 'high' | 'critical' {
	if (score >= 70) return 'critical';
	if (score >= 40) return 'high';
	if (score >= 20) return 'medium';
	if (score > 0) return 'low';
	return 'none';
}

/**
 * Format a finding for display
 */
export function formatFinding(finding: Finding): string {
	const lines: string[] = [
		`[${finding.severity.toUpperCase()}] ${finding.title}`,
		`  ID: ${finding.id}`,
		`  Path: ${finding.source.node} → ${finding.path.length > 2 ? '...' : ''} → ${finding.sink.node}`,
		`  ${finding.description}`,
		`  Remediation: ${finding.remediation.summary}`,
	];

	if (finding.references.cwe) {
		lines.push(`  Reference: ${finding.references.cwe}`);
	}

	return lines.join('\n');
}

/**
 * Generate a summary text for the report
 */
export function generateReportSummary(report: SecurityReport): string {
	const lines: string[] = [
		`Security Report for "${report.workflow.name}"`,
		`Generated: ${report.metadata.generatedAt}`,
		'',
		`Risk Score: ${report.risk.score}/100 (${report.risk.level.toUpperCase()})`,
		'',
		'Summary:',
		`  Total Findings: ${report.summary.totalFindings}`,
		`  Critical: ${report.summary.bySeverity.critical}`,
		`  High: ${report.summary.bySeverity.high}`,
		`  Medium: ${report.summary.bySeverity.medium}`,
		`  Low: ${report.summary.bySeverity.low}`,
		'',
		'Risk Factors:',
		...report.risk.factors.map((f) => `  - ${f}`),
		'',
		'Top Recommendations:',
		...report.recommendations.slice(0, 3).map((r, i) => `  ${i + 1}. ${r}`),
	];

	return lines.join('\n');
}

/**
 * Convert taint paths from analysis to findings format (for legacy compatibility)
 */
export function taintPathsToFindings(taintPaths: TaintPath[]): Finding[] {
	return taintPaths.map((path, index) => ({
		id: path.id || `legacy-${index}`,
		ruleId: 'legacy-taint-analysis',
		severity: path.severity as FindingSeverity,
		confidence: path.confidence,
		title: `${path.sink.riskType} via ${path.source.nodeName}`,
		description: `Untrusted data from "${path.source.nodeName}" flows to "${path.sink.nodeName}" (${path.sinkParam})`,
		category: mapRiskTypeToCategory(path.sink.riskType),
		source: {
			node: path.source.nodeName,
			nodeType: path.source.nodeType,
			field: path.taintedField,
		},
		sink: {
			node: path.sink.nodeName,
			nodeType: path.sink.nodeType,
			parameter: path.sinkParam,
		},
		path: path.path,
		remediation: {
			summary: `Validate and sanitize input before ${path.sink.riskType.toLowerCase()} operations`,
			steps: [
				'Add input validation before the sink node',
				'Use allowlist validation where possible',
				'Consider using parameterized operations',
			],
		},
		references: {},
		metadata: {
			sanitized: path.sanitized,
			sanitizerNodes: path.sanitizerNodes,
		},
	}));
}

/**
 * Map risk type to finding category
 */
function mapRiskTypeToCategory(riskType: string): FindingCategory {
	const mapping: Record<string, FindingCategory> = {
		RCE: 'injection',
		'Command Injection': 'injection',
		'SQL Injection': 'injection',
		'NoSQL Injection': 'injection',
		SSRF: 'ssrf',
		'Prompt Injection': 'prompt-injection',
		'Credential Exposure': 'credential-exposure',
		XSS: 'information-disclosure',
		'Path Traversal': 'information-disclosure',
	};

	return mapping[riskType] || 'configuration';
}
