/**
 * Report Formatters - Export security reports in multiple formats
 *
 * Supports: HTML Report, Slack Blocks, SARIF 2.1.0, and Mermaid.js diagrams
 */

import type { SecurityReport } from './findingsReporter';
import type { Finding, FindingSeverity, FindingCategory } from '../rules/types';

// ============================================================================
// Types
// ============================================================================

/**
 * Slack Block Kit message structure
 */
export interface SlackBlock {
	type: string;
	text?: SlackTextObject | string;
	fields?: SlackTextObject[];
	elements?: (SlackElement | SlackContextElement)[];
	block_id?: string;
	accessory?: SlackElement;
}

interface SlackTextObject {
	type: 'plain_text' | 'mrkdwn';
	text: string;
	emoji?: boolean;
}

interface SlackElement {
	type: string;
	text?: SlackTextObject | string;
	url?: string;
	action_id?: string;
}

/**
 * Slack context element (mrkdwn or plain_text)
 */
interface SlackContextElement {
	type: 'mrkdwn' | 'plain_text' | 'image';
	text?: string;
	image_url?: string;
	alt_text?: string;
}

/**
 * SARIF 2.1.0 Log structure
 */
export interface SarifLog {
	$schema: string;
	version: '2.1.0';
	runs: SarifRun[];
}

interface SarifRun {
	tool: SarifTool;
	results: SarifResult[];
	invocations?: SarifInvocation[];
}

interface SarifTool {
	driver: SarifToolComponent;
}

interface SarifToolComponent {
	name: string;
	version: string;
	informationUri?: string;
	rules: SarifReportingDescriptor[];
}

interface SarifReportingDescriptor {
	id: string;
	name: string;
	shortDescription: { text: string };
	fullDescription?: { text: string };
	helpUri?: string;
	defaultConfiguration?: {
		level: 'error' | 'warning' | 'note' | 'none';
	};
	properties?: Record<string, unknown>;
}

interface SarifResult {
	ruleId: string;
	ruleIndex?: number;
	level: 'error' | 'warning' | 'note' | 'none';
	message: { text: string };
	locations?: SarifLocation[];
	relatedLocations?: SarifLocation[];
	fixes?: SarifFix[];
	properties?: Record<string, unknown>;
}

interface SarifLocation {
	physicalLocation?: {
		artifactLocation?: { uri: string };
		region?: { startLine?: number; startColumn?: number };
	};
	logicalLocations?: Array<{
		name: string;
		kind?: string;
		fullyQualifiedName?: string;
	}>;
	message?: { text: string };
}

interface SarifFix {
	description: { text: string };
	artifactChanges?: Array<{
		artifactLocation: { uri: string };
		replacements?: Array<{
			deletedRegion: { startLine: number };
			insertedContent: { text: string };
		}>;
	}>;
}

interface SarifInvocation {
	executionSuccessful: boolean;
	startTimeUtc?: string;
	endTimeUtc?: string;
}

/**
 * Mermaid diagram options
 */
export interface MermaidOptions {
	direction?: 'LR' | 'TB' | 'RL' | 'BT';
	showTaintedPaths?: boolean;
	includeAllNodes?: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const SEVERITY_EMOJI: Record<FindingSeverity, string> = {
	critical: '🔴',
	high: '🟠',
	medium: '🟡',
	low: '🟢',
	info: 'ℹ️',
};

const SEVERITY_TO_SARIF_LEVEL: Record<FindingSeverity, 'error' | 'warning' | 'note'> = {
	critical: 'error',
	high: 'error',
	medium: 'warning',
	low: 'note',
	info: 'note',
};

const CATEGORY_LABELS: Record<FindingCategory, string> = {
	injection: 'Code/Command Injection',
	ssrf: 'Server-Side Request Forgery',
	'credential-exposure': 'Credential Exposure',
	'prompt-injection': 'Prompt Injection',
	configuration: 'Security Misconfiguration',
	'information-disclosure': 'Information Disclosure',
};

// ============================================================================
// HTML Report Formatter
// ============================================================================

/**
 * Generate a self-contained HTML security report
 */
export function formatAsHtml(report: SecurityReport, mermaidDiagram?: string): string {
	const styles = getHtmlStyles();
	const riskGauge = generateRiskGaugeSvg(report.risk.score, report.risk.level);
	const findingsHtml = generateFindingsHtml(report.findings);
	const recommendationsHtml = generateRecommendationsHtml(report.recommendations);
	const summaryHtml = generateSummaryHtml(report);
	const diagramHtml = mermaidDiagram ? generateDiagramSection(mermaidDiagram) : '';

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security Report: ${escapeHtml(report.workflow.name)}</title>
	<style>${styles}</style>
</head>
<body>
	<div class="container">
		<header class="report-header">
			<h1>🛡️ Security Scan Report</h1>
			<div class="workflow-info">
				<h2>${escapeHtml(report.workflow.name)}</h2>
				<div class="metadata">
					<span>ID: ${escapeHtml(report.workflow.id)}</span>
					<span>Nodes: ${report.workflow.nodeCount}</span>
					<span>Generated: ${new Date(report.metadata.generatedAt).toLocaleString()}</span>
				</div>
			</div>
		</header>

		<section class="risk-section">
			<h3>Risk Assessment</h3>
			<div class="risk-container">
				<div class="risk-gauge">
					${riskGauge}
				</div>
				<div class="risk-details">
					<div class="risk-score">
						<span class="score-value">${report.risk.score}</span>
						<span class="score-max">/100</span>
					</div>
					<div class="risk-level risk-${report.risk.level}">${report.risk.level.toUpperCase()}</div>
					<div class="risk-factors">
						<h4>Risk Factors:</h4>
						<ul>
							${report.risk.factors.map((f) => `<li>${escapeHtml(f)}</li>`).join('\n')}
						</ul>
					</div>
				</div>
			</div>
		</section>

		${summaryHtml}

		${diagramHtml}

		<section class="findings-section">
			<h3>Security Findings (${report.summary.totalFindings})</h3>
			${findingsHtml}
		</section>

		${recommendationsHtml}

		<footer class="report-footer">
			<p>Generated by RiskVoid v${report.metadata.version} | Analysis completed in ${report.metadata.duration}ms</p>
		</footer>
	</div>
</body>
</html>`;
}

function getHtmlStyles(): string {
	return `
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
			line-height: 1.6;
			color: #333;
			background: #f5f5f5;
		}
		.container {
			max-width: 1200px;
			margin: 0 auto;
			padding: 20px;
		}
		.report-header {
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			color: white;
			padding: 30px;
			border-radius: 12px;
			margin-bottom: 20px;
		}
		.report-header h1 { font-size: 1.8em; margin-bottom: 15px; }
		.report-header h2 { font-size: 1.4em; font-weight: normal; margin-bottom: 10px; }
		.metadata { display: flex; gap: 20px; font-size: 0.9em; opacity: 0.9; flex-wrap: wrap; }

		section {
			background: white;
			border-radius: 12px;
			padding: 25px;
			margin-bottom: 20px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
		}
		section h3 {
			font-size: 1.3em;
			margin-bottom: 20px;
			padding-bottom: 10px;
			border-bottom: 2px solid #eee;
		}

		.risk-container { display: flex; gap: 30px; align-items: center; flex-wrap: wrap; }
		.risk-gauge { flex: 0 0 180px; }
		.risk-details { flex: 1; min-width: 250px; }
		.risk-score { font-size: 2.5em; font-weight: bold; }
		.score-value { color: #333; }
		.score-max { color: #999; font-weight: normal; }
		.risk-level {
			display: inline-block;
			padding: 5px 15px;
			border-radius: 20px;
			font-weight: bold;
			text-transform: uppercase;
			margin: 10px 0;
		}
		.risk-none { background: #d4edda; color: #155724; }
		.risk-low { background: #d4edda; color: #155724; }
		.risk-medium { background: #fff3cd; color: #856404; }
		.risk-high { background: #ffe5d0; color: #c45600; }
		.risk-critical { background: #f8d7da; color: #721c24; }
		.risk-factors h4 { margin: 15px 0 10px; font-size: 0.95em; color: #666; }
		.risk-factors ul { padding-left: 20px; }
		.risk-factors li { margin: 5px 0; }

		.summary-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
			gap: 15px;
		}
		.summary-item {
			background: #f8f9fa;
			padding: 15px;
			border-radius: 8px;
			text-align: center;
		}
		.summary-item .value { font-size: 2em; font-weight: bold; }
		.summary-item .label { color: #666; font-size: 0.9em; }
		.summary-item.critical .value { color: #dc3545; }
		.summary-item.high .value { color: #fd7e14; }
		.summary-item.medium .value { color: #ffc107; }
		.summary-item.low .value { color: #28a745; }

		.diagram-section { overflow-x: auto; }
		.mermaid-container {
			background: #fafafa;
			padding: 20px;
			border-radius: 8px;
			overflow-x: auto;
		}
		.mermaid-code {
			font-family: 'Monaco', 'Menlo', monospace;
			font-size: 0.85em;
			white-space: pre-wrap;
			background: #f0f0f0;
			padding: 15px;
			border-radius: 6px;
			overflow-x: auto;
		}

		.findings-table {
			width: 100%;
			border-collapse: collapse;
		}
		.findings-table th {
			background: #f8f9fa;
			padding: 12px;
			text-align: left;
			font-weight: 600;
			border-bottom: 2px solid #dee2e6;
		}
		.findings-table td {
			padding: 12px;
			border-bottom: 1px solid #eee;
			vertical-align: top;
		}
		.findings-table tr:hover { background: #f8f9fa; }
		.severity-badge {
			display: inline-block;
			padding: 4px 10px;
			border-radius: 12px;
			font-size: 0.8em;
			font-weight: bold;
			text-transform: uppercase;
		}
		.severity-critical { background: #f8d7da; color: #721c24; }
		.severity-high { background: #ffe5d0; color: #c45600; }
		.severity-medium { background: #fff3cd; color: #856404; }
		.severity-low { background: #d4edda; color: #155724; }
		.severity-info { background: #d1ecf1; color: #0c5460; }

		.finding-path {
			font-family: monospace;
			font-size: 0.85em;
			color: #666;
			word-break: break-all;
		}
		.finding-details {
			padding: 10px 0;
		}
		.finding-details summary {
			cursor: pointer;
			color: #667eea;
			font-weight: 500;
		}
		.finding-details-content {
			padding: 10px;
			background: #f8f9fa;
			border-radius: 6px;
			margin-top: 10px;
		}
		.remediation-steps {
			padding-left: 20px;
			margin-top: 10px;
		}
		.remediation-steps li { margin: 5px 0; }

		.recommendations-list {
			list-style: none;
			padding: 0;
		}
		.recommendations-list li {
			padding: 15px;
			margin: 10px 0;
			background: #f8f9fa;
			border-radius: 8px;
			border-left: 4px solid #667eea;
		}

		.no-findings {
			text-align: center;
			padding: 40px;
			color: #28a745;
		}
		.no-findings-icon { font-size: 3em; margin-bottom: 10px; }

		.report-footer {
			text-align: center;
			color: #666;
			padding: 20px;
			font-size: 0.9em;
		}

		@media (max-width: 768px) {
			.risk-container { flex-direction: column; }
			.risk-gauge { flex: none; }
		}
	`;
}

function generateRiskGaugeSvg(score: number, level: string): string {
	const angle = (score / 100) * 180;
	const radians = (angle - 90) * (Math.PI / 180);
	const endX = 90 + 70 * Math.cos(radians);
	const endY = 90 + 70 * Math.sin(radians);

	const levelColors: Record<string, string> = {
		none: '#28a745',
		low: '#28a745',
		medium: '#ffc107',
		high: '#fd7e14',
		critical: '#dc3545',
	};
	const color = levelColors[level] || '#999';

	return `
		<svg viewBox="0 0 180 110" width="180" height="110">
			<!-- Background arc -->
			<path d="M 20 90 A 70 70 0 0 1 160 90" fill="none" stroke="#e0e0e0" stroke-width="12" stroke-linecap="round"/>
			<!-- Score arc -->
			<path d="M 20 90 A 70 70 0 ${angle > 90 ? '0' : '0'} 1 ${endX} ${endY}" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"/>
			<!-- Score labels -->
			<text x="20" y="105" font-size="10" fill="#999">0</text>
			<text x="155" y="105" font-size="10" fill="#999">100</text>
		</svg>
	`;
}

function generateSummaryHtml(report: SecurityReport): string {
	const { bySeverity } = report.summary;

	return `
		<section class="summary-section">
			<h3>Summary</h3>
			<div class="summary-grid">
				<div class="summary-item">
					<div class="value">${report.summary.totalFindings}</div>
					<div class="label">Total Findings</div>
				</div>
				<div class="summary-item critical">
					<div class="value">${bySeverity.critical}</div>
					<div class="label">🔴 Critical</div>
				</div>
				<div class="summary-item high">
					<div class="value">${bySeverity.high}</div>
					<div class="label">🟠 High</div>
				</div>
				<div class="summary-item medium">
					<div class="value">${bySeverity.medium}</div>
					<div class="label">🟡 Medium</div>
				</div>
				<div class="summary-item low">
					<div class="value">${bySeverity.low + bySeverity.info}</div>
					<div class="label">🟢 Low/Info</div>
				</div>
			</div>
		</section>
	`;
}

function generateDiagramSection(mermaidDiagram: string): string {
	return `
		<section class="diagram-section">
			<h3>Workflow Diagram</h3>
			<div class="mermaid-container">
				<p><em>Copy the code below to <a href="https://mermaid.live" target="_blank">Mermaid Live Editor</a> to visualize:</em></p>
				<pre class="mermaid-code">${escapeHtml(mermaidDiagram)}</pre>
			</div>
		</section>
	`;
}

function generateFindingsHtml(findings: Finding[]): string {
	if (findings.length === 0) {
		return `
			<div class="no-findings">
				<div class="no-findings-icon">✅</div>
				<div>No security vulnerabilities detected</div>
			</div>
		`;
	}

	const rows = findings
		.map(
			(f) => `
		<tr>
			<td><span class="severity-badge severity-${f.severity}">${SEVERITY_EMOJI[f.severity]} ${f.severity}</span></td>
			<td>
				<strong>${escapeHtml(f.title)}</strong>
				<div class="finding-path">${escapeHtml(f.path.join(' → '))}</div>
				<details class="finding-details">
					<summary>View Details</summary>
					<div class="finding-details-content">
						<p><strong>Description:</strong> ${escapeHtml(f.description)}</p>
						<p><strong>Source:</strong> ${escapeHtml(f.source.node)} (${escapeHtml(f.source.field)})</p>
						<p><strong>Sink:</strong> ${escapeHtml(f.sink.node)} (${escapeHtml(f.sink.parameter)})</p>
						<p><strong>Remediation:</strong> ${escapeHtml(f.remediation.summary)}</p>
						${
							f.remediation.steps.length > 0
								? `
						<ul class="remediation-steps">
							${f.remediation.steps.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}
						</ul>
						`
								: ''
						}
						${f.references.cwe ? `<p><strong>Reference:</strong> ${escapeHtml(f.references.cwe)}</p>` : ''}
					</div>
				</details>
			</td>
			<td>${escapeHtml(CATEGORY_LABELS[f.category] || f.category)}</td>
			<td><code>${escapeHtml(f.id)}</code></td>
		</tr>
	`,
		)
		.join('');

	return `
		<table class="findings-table">
			<thead>
				<tr>
					<th style="width: 100px;">Severity</th>
					<th>Finding</th>
					<th style="width: 180px;">Category</th>
					<th style="width: 200px;">ID</th>
				</tr>
			</thead>
			<tbody>
				${rows}
			</tbody>
		</table>
	`;
}

function generateRecommendationsHtml(recommendations: string[]): string {
	if (recommendations.length === 0) return '';

	return `
		<section class="recommendations-section">
			<h3>Recommendations</h3>
			<ul class="recommendations-list">
				${recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}
			</ul>
		</section>
	`;
}

// ============================================================================
// Slack Blocks Formatter
// ============================================================================

/**
 * Generate Slack Block Kit message blocks
 */
export function formatAsSlackBlocks(report: SecurityReport): SlackBlock[] {
	const blocks: SlackBlock[] = [];

	// Header
	blocks.push({
		type: 'header',
		text: {
			type: 'plain_text',
			text: `🛡️ Security Scan: ${report.workflow.name}`,
			emoji: true,
		},
	});

	// Risk summary section
	blocks.push({
		type: 'section',
		fields: [
			{
				type: 'mrkdwn',
				text: `*Risk Score:* ${report.risk.score}/100`,
			},
			{
				type: 'mrkdwn',
				text: `*Risk Level:* ${getRiskEmoji(report.risk.level)} ${report.risk.level.toUpperCase()}`,
			},
		],
	});

	// Summary counts
	const { bySeverity } = report.summary;
	blocks.push({
		type: 'section',
		text: {
			type: 'mrkdwn',
			text: `*Findings:* ${report.summary.totalFindings} total\n${SEVERITY_EMOJI.critical} Critical: ${bySeverity.critical} | ${SEVERITY_EMOJI.high} High: ${bySeverity.high} | ${SEVERITY_EMOJI.medium} Medium: ${bySeverity.medium} | ${SEVERITY_EMOJI.low} Low: ${bySeverity.low}`,
		},
	});

	// Divider before findings
	if (report.findings.length > 0) {
		blocks.push({ type: 'divider' });

		// Add up to 5 most severe findings
		const topFindings = report.findings.slice(0, 5);
		for (const finding of topFindings) {
			blocks.push({
				type: 'section',
				text: {
					type: 'mrkdwn',
					text: `${SEVERITY_EMOJI[finding.severity]} *${finding.title}*\n${finding.description}\n_Path: ${finding.path.join(' → ')}_`,
				},
			});
		}

		if (report.findings.length > 5) {
			blocks.push({
				type: 'context',
				elements: [
					{
						type: 'mrkdwn',
						text: `_+ ${report.findings.length - 5} more findings not shown_`,
					},
				],
			});
		}
	}

	// Divider before recommendations
	if (report.recommendations.length > 0) {
		blocks.push({ type: 'divider' });
		blocks.push({
			type: 'section',
			text: {
				type: 'mrkdwn',
				text: `*Top Recommendations:*\n${report.recommendations.slice(0, 3).map((r, i) => `${i + 1}. ${r}`).join('\n')}`,
			},
		});
	}

	// Footer context
	blocks.push({
		type: 'context',
		elements: [
			{
				type: 'mrkdwn',
				text: `Scanned by RiskVoid v${report.metadata.version} | ${new Date(report.metadata.generatedAt).toLocaleString()}`,
			},
		],
	});

	return blocks;
}

function getRiskEmoji(level: string): string {
	const emojis: Record<string, string> = {
		none: '✅',
		low: '🟢',
		medium: '🟡',
		high: '🟠',
		critical: '🔴',
	};
	return emojis[level] || '⚪';
}

// ============================================================================
// SARIF 2.1.0 Formatter
// ============================================================================

/**
 * Generate SARIF 2.1.0 compliant log
 */
export function formatAsSarif(report: SecurityReport): SarifLog {
	// Build unique rules from findings
	const rulesMap = new Map<string, SarifReportingDescriptor>();

	for (const finding of report.findings) {
		if (!rulesMap.has(finding.ruleId)) {
			rulesMap.set(finding.ruleId, {
				id: finding.ruleId,
				name: finding.title,
				shortDescription: { text: finding.description },
				defaultConfiguration: {
					level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
				},
				helpUri: finding.references.documentation,
				properties: {
					category: finding.category,
					cwe: finding.references.cwe,
					owasp: finding.references.owasp,
				},
			});
		}
	}

	const rules = Array.from(rulesMap.values());
	const ruleIndexMap = new Map<string, number>();
	rules.forEach((rule, index) => ruleIndexMap.set(rule.id, index));

	// Build results from findings
	const results: SarifResult[] = report.findings.map((finding) => ({
		ruleId: finding.ruleId,
		ruleIndex: ruleIndexMap.get(finding.ruleId),
		level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
		message: { text: `${finding.title}: ${finding.description}` },
		locations: [
			{
				logicalLocations: [
					{
						name: finding.sink.node,
						kind: 'node',
						fullyQualifiedName: `${report.workflow.name}/${finding.sink.node}`,
					},
				],
				message: { text: `Sink: ${finding.sink.parameter}` },
			},
		],
		relatedLocations: [
			{
				logicalLocations: [
					{
						name: finding.source.node,
						kind: 'node',
						fullyQualifiedName: `${report.workflow.name}/${finding.source.node}`,
					},
				],
				message: { text: `Source: ${finding.source.field}` },
			},
		],
		fixes:
			finding.remediation.steps.length > 0
				? [
						{
							description: { text: finding.remediation.summary },
						},
					]
				: undefined,
		properties: {
			findingId: finding.id,
			confidence: finding.confidence,
			path: finding.path,
			category: finding.category,
		},
	}));

	return {
		$schema:
			'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
		version: '2.1.0',
		runs: [
			{
				tool: {
					driver: {
						name: 'RiskVoid',
						version: report.metadata.version,
						informationUri: 'https://github.com/riskvoid/n8n-nodes-riskvoid',
						rules,
					},
				},
				results,
				invocations: [
					{
						executionSuccessful: true,
						startTimeUtc: report.metadata.generatedAt,
					},
				],
			},
		],
	};
}

// ============================================================================
// Mermaid.js Diagram Generator
// ============================================================================

/**
 * Generate Mermaid.js flowchart diagram showing workflow and taint paths
 */
export function generateMermaidDiagram(
	report: SecurityReport,
	options: MermaidOptions = {},
): string {
	const { direction = 'LR', showTaintedPaths = true } = options;

	const lines: string[] = [];
	lines.push(`graph ${direction}`);

	// Collect all unique nodes from findings
	const sourceNodes = new Set<string>();
	const sinkNodes = new Set<string>();
	const pathNodes = new Set<string>();
	const taintedEdges = new Set<string>(); // "source->target" format

	// Build node sets from findings
	for (const finding of report.findings) {
		sourceNodes.add(finding.source.node);
		sinkNodes.add(finding.sink.node);

		// Track path nodes and edges
		for (let i = 0; i < finding.path.length; i++) {
			const node = finding.path[i];
			if (!sourceNodes.has(node) && !sinkNodes.has(node)) {
				pathNodes.add(node);
			}
			if (i > 0) {
				taintedEdges.add(`${finding.path[i - 1]}|${finding.path[i]}`);
			}
		}
	}

	// Also include nodes from node assessments for a more complete picture
	const allNodes = new Set<string>();
	for (const assessment of report.nodeAssessments) {
		allNodes.add(assessment.name);
	}
	// Add nodes from findings
	sourceNodes.forEach((n) => allNodes.add(n));
	sinkNodes.forEach((n) => allNodes.add(n));
	pathNodes.forEach((n) => allNodes.add(n));

	// If no findings, show a simple message
	if (report.findings.length === 0) {
		lines.push('    NoFindings["✅ No vulnerabilities detected"]');
		return lines.join('\n');
	}

	// Generate node definitions with appropriate shapes and icons
	lines.push('    subgraph Workflow');

	for (const node of allNodes) {
		const safeId = sanitizeMermaidId(node);
		const isSource = sourceNodes.has(node);
		const isSink = sinkNodes.has(node);

		let nodeShape: string;
		let icon = '';

		if (isSource && isSink) {
			// Both source and sink
			icon = '⚠️ ';
			nodeShape = `${safeId}[/"${icon}${escapeMermaid(node)}"/]`;
		} else if (isSource) {
			// Source node (taint origin)
			icon = '🟡 ';
			nodeShape = `${safeId}[/"${icon}${escapeMermaid(node)}"/]`;
		} else if (isSink) {
			// Sink node (dangerous operation)
			icon = '🔴 ';
			nodeShape = `${safeId}[/"${icon}${escapeMermaid(node)}"/]`;
		} else {
			// Regular node
			nodeShape = `${safeId}["${escapeMermaid(node)}"]`;
		}

		lines.push(`        ${nodeShape}`);
	}

	lines.push('    end');
	lines.push('');

	// Generate edges
	const addedEdges = new Set<string>();

	for (const finding of report.findings) {
		for (let i = 0; i < finding.path.length - 1; i++) {
			const from = finding.path[i];
			const to = finding.path[i + 1];
			const edgeKey = `${from}|${to}`;

			if (addedEdges.has(edgeKey)) continue;
			addedEdges.add(edgeKey);

			const fromId = sanitizeMermaidId(from);
			const toId = sanitizeMermaidId(to);

			if (showTaintedPaths && taintedEdges.has(edgeKey)) {
				// Tainted edge - use label if it's the first edge (shows tainted field)
				if (i === 0) {
					const label = finding.source.field ? finding.source.field : 'tainted';
					lines.push(`    ${fromId} -->|"${escapeMermaid(label)}"| ${toId}`);
				} else {
					lines.push(`    ${fromId} -->|"tainted"| ${toId}`);
				}
			} else {
				lines.push(`    ${fromId} --> ${toId}`);
			}
		}
	}

	lines.push('');

	// Add styling
	lines.push('    %% Styling');

	// Style source nodes (yellow)
	if (sourceNodes.size > 0) {
		const sourceIds = Array.from(sourceNodes).map(sanitizeMermaidId).join(',');
		lines.push(`    style ${sourceIds} fill:#fff3cd,stroke:#ffc107,stroke-width:2px`);
	}

	// Style sink nodes (red)
	if (sinkNodes.size > 0) {
		const sinkIds = Array.from(sinkNodes).map(sanitizeMermaidId).join(',');
		lines.push(`    style ${sinkIds} fill:#f8d7da,stroke:#dc3545,stroke-width:2px`);
	}

	return lines.join('\n');
}

// ============================================================================
// Utility Functions
// ============================================================================

function escapeHtml(text: string): string {
	const htmlEntities: Record<string, string> = {
		'&': '&amp;',
		'<': '&lt;',
		'>': '&gt;',
		'"': '&quot;',
		"'": '&#39;',
	};
	return text.replace(/[&<>"']/g, (char) => htmlEntities[char] || char);
}

function escapeMermaid(text: string): string {
	// Escape characters that have special meaning in Mermaid
	return text.replace(/["]/g, "'").replace(/[<>]/g, '');
}

function sanitizeMermaidId(name: string): string {
	// Create a valid Mermaid node ID from a node name
	return name.replace(/[^a-zA-Z0-9_]/g, '_');
}
