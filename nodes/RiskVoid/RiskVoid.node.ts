import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	IHttpRequestMethods,
	IDataObject,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import { analyzeWorkflow, generateReport, parseWorkflow, buildGraph } from './analysis';
import type { AnalysisOptions, SinkSeverity } from './types';
import {
	initializeBuiltInRules,
	runAllRules,
	getAllRuleMetadata,
} from './rules';
import type { RuleContext, FindingSeverity, FindingCategory } from './rules/types';
import { findTaintSources, findSecuritySinks, analyzeTaintFlows } from './analysis/taintAnalyzer';
import {
	formatAsHtml,
	formatAsSlackBlocks,
	formatAsSarif,
	generateMermaidDiagram,
} from './analysis/reportFormatters';

// Initialize rules on module load
initializeBuiltInRules();

/**
 * Fetch a workflow by ID via n8n API
 */
async function fetchWorkflowById(
	executeFunctions: IExecuteFunctions,
	workflowId: string,
): Promise<unknown> {
	const credentials = await executeFunctions.getCredentials('n8nApi');

	// Determine base URL
	let baseUrl = credentials.baseUrl as string;
	if (!baseUrl) {
		// Default to localhost if no base URL is configured
		baseUrl = 'http://localhost:5678';
	}

	// Remove trailing slash
	baseUrl = baseUrl.replace(/\/$/, '');

	const apiKey = credentials.apiKey as string;
	if (!apiKey) {
		throw new NodeOperationError(
			executeFunctions.getNode(),
			'n8n API key is required',
		);
	}

	// Fetch workflow from n8n API
	const response = await executeFunctions.helpers.httpRequest({
		method: 'GET' as IHttpRequestMethods,
		url: `${baseUrl}/api/v1/workflows/${workflowId}`,
		headers: {
			'X-N8N-API-KEY': apiKey,
		},
		json: true,
	});

	return response;
}

/**
 * Fetch the current workflow via n8n API
 */
async function fetchCurrentWorkflow(
	executeFunctions: IExecuteFunctions,
): Promise<unknown> {
	const workflowInfo = executeFunctions.getWorkflow();
	const workflowId = workflowInfo.id;

	if (!workflowId) {
		throw new NodeOperationError(
			executeFunctions.getNode(),
			'Cannot determine workflow ID. This workflow may not be saved yet.',
		);
	}

	return fetchWorkflowById(executeFunctions, workflowId);
}

export class RiskVoid implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'RiskVoid Security',
		name: 'riskVoid',
		icon: 'file:riskvoid-logo.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Your ultimate n8n workflow security scanner. Detect code injection, SSRF, SQL injection, and other vulnerabilities before they reach production.',
		defaults: {
			name: 'RiskVoid Security',
		},
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		usableAsTool: true,
		credentials: [
			{
				name: 'riskVoidN8nApi',
				required: true,
				displayOptions: {
					show: {
						operation: ['scanCurrent', 'scanById'],
					},
				},
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Scan Current Workflow',
						value: 'scanCurrent',
						description: 'Scan the workflow this node is part of',
						action: 'Scan current workflow',
					},
					{
						name: 'Scan Workflow by ID',
						value: 'scanById',
						description: 'Scan a workflow by its ID (fetches via n8n API)',
						action: 'Scan workflow by ID',
					},
					{
						name: 'Scan Workflow JSON (Base64)',
						value: 'scanJson',
						description: 'Scan from base64-encoded workflow JSON',
						action: 'Scan workflow from JSON',
					},
				],
				default: 'scanCurrent',
			},
			{
				displayName: 'Workflow ID',
				name: 'workflowId',
				type: 'string',
				default: '',
				required: true,
				displayOptions: {
					show: {
						operation: ['scanById'],
					},
				},
				description: 'The ID of the workflow to scan (found in the workflow URL)',
			},
			{
				displayName: 'Workflow JSON (Base64)',
				name: 'workflowJsonBase64',
				type: 'string',
				typeOptions: {
					rows: 10,
				},
				default: '',
				required: true,
				noDataExpression: true,
				displayOptions: {
					show: {
						operation: ['scanJson'],
					},
				},
				hint: 'Paste base64-encoded workflow JSON. Use browser console: btoa(JSON.stringify(workflow))',
				description: 'Base64-encoded workflow JSON. Required because n8n evaluates {{ }} expressions in regular text fields, which would strip the expressions we need to analyze.',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Categories',
						name: 'categories',
						type: 'multiOptions',
						options: [
							{ name: 'Code/Command Injection', value: 'injection' },
							{ name: 'Credential Exposure', value: 'credential-exposure' },
							{ name: 'Information Disclosure', value: 'information-disclosure' },
							{ name: 'Prompt Injection', value: 'prompt-injection' },
							{ name: 'Security Misconfiguration', value: 'configuration' },
							{ name: 'SSRF', value: 'ssrf' },
						],
						default: [],
						description: 'Filter by vulnerability categories (empty = all)',
					},
					{
						displayName: 'Export Format',
						name: 'exportFormat',
						type: 'options',
						options: [
							{
								name: 'JSON (Default)',
								value: 'json',
								description: 'Standard JSON output',
							},
							{
								name: 'HTML Report',
								value: 'html',
								description: 'Self-contained HTML report with visualizations',
							},
							{
								name: 'Slack Blocks',
								value: 'slack',
								description: 'Slack Block Kit JSON for posting to Slack channels',
							},
							{
								name: 'SARIF 2.1.0',
								value: 'sarif',
								description: 'Static Analysis Results Interchange Format for CI/CD tools',
							},
						],
						default: 'json',
						description: 'Output format for the security report',
					},
					{
						displayName: 'Include Mermaid Diagram',
						name: 'includeMermaid',
						type: 'boolean',
						default: false,
						description: 'Whether to include a Mermaid.js workflow diagram in the output',
						displayOptions: {
							show: {
								exportFormat: ['json', 'html'],
							},
						},
					},
					{
						displayName: 'Include Remediation',
						name: 'includeRemediation',
						type: 'boolean',
						default: true,
						description: 'Whether to include detailed remediation guidance',
					},
					{
						displayName: 'Minimum Severity',
						name: 'minSeverity',
						type: 'options',
						options: [
							{ name: 'All (Including Info)', value: 'info' },
							{ name: 'Critical Only', value: 'critical' },
							{ name: 'High and Above', value: 'high' },
							{ name: 'Low and Above', value: 'low' },
							{ name: 'Medium and Above', value: 'medium' },
						],
						default: 'medium',
						description: 'Minimum severity level to report',
					},
					{
						displayName: 'Output Format',
						name: 'outputFormat',
						type: 'options',
						options: [
							{
								name: 'Full Report',
								value: 'full',
								description: 'Complete security report with all details',
							},
							{
								name: 'Summary',
								value: 'summary',
								description: 'Risk score and summary statistics only',
							},
							{
								name: 'Findings Only',
								value: 'findings',
								description: 'Just the list of findings',
							},
						],
						default: 'full',
						description: 'Level of detail in the output',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const operation = this.getNodeParameter('operation', itemIndex) as string;
				const options = this.getNodeParameter('options', itemIndex, {}) as {
					minSeverity?: string;
					categories?: string[];
					outputFormat?: string;
					includeRemediation?: boolean;
					exportFormat?: string;
					includeMermaid?: boolean;
				};

				let workflowJson: unknown;

				if (operation === 'scanCurrent') {
					// Fetch current workflow via n8n API
					workflowJson = await fetchCurrentWorkflow(this);
				} else if (operation === 'scanById') {
					// Fetch workflow by ID via n8n API
					const workflowId = this.getNodeParameter('workflowId', itemIndex) as string;
					workflowJson = await fetchWorkflowById(this, workflowId);
				} else {
					// Decode base64 workflow JSON
					const base64String = this.getNodeParameter('workflowJsonBase64', itemIndex) as string;
					let jsonString: string;

					try {
						jsonString = Buffer.from(base64String, 'base64').toString('utf-8');
					} catch (decodeError) {
						throw new NodeOperationError(
							this.getNode(),
							`Invalid Base64: ${decodeError instanceof Error ? decodeError.message : 'Decode error'}. Use btoa(JSON.stringify(workflow)) in browser console to encode.`,
							{ itemIndex },
						);
					}

					try {
						workflowJson = JSON.parse(jsonString);
					} catch (parseError) {
						throw new NodeOperationError(
							this.getNode(),
							`Invalid JSON after base64 decode: ${parseError instanceof Error ? parseError.message : 'Parse error'}`,
							{ itemIndex },
						);
					}
				}

				// Build analysis options
				const analysisOptions: AnalysisOptions = {
					minSeverity: (options.minSeverity as SinkSeverity | 'all') || 'all',
					includeSanitized: true,
				};

				// Run taint analysis first
				const analysisResult = analyzeWorkflow(workflowJson, analysisOptions);

				if (!analysisResult.success) {
					throw new NodeOperationError(
						this.getNode(),
						`Analysis failed: ${analysisResult.errors.map((e) => e.message).join(', ')}`,
						{ itemIndex },
					);
				}

				// Build rule context for detection rules
				const parseResult = parseWorkflow(workflowJson);
				if (!parseResult.success || !parseResult.workflow) {
					throw new NodeOperationError(
						this.getNode(),
						'Failed to parse workflow for rule analysis',
						{ itemIndex },
					);
				}

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

				// Run detection rules
				const rulesResult = runAllRules(ruleContext, {
					minSeverity: options.minSeverity as FindingSeverity | undefined,
					categories: (options.categories as FindingCategory[]) || undefined,
				});

				// Generate the security report
				const report = generateReport(analysisResult, rulesResult, {
					includeNodeAssessments: options.outputFormat === 'full',
					includeRemediation: options.includeRemediation !== false,
				});

				// Build output based on export format
				const exportFormat = options.exportFormat || 'json';
				let output: IDataObject;

				// Generate Mermaid diagram if requested or needed for HTML
				const mermaidDiagram =
					options.includeMermaid || exportFormat === 'html'
						? generateMermaidDiagram(report)
						: undefined;

				switch (exportFormat) {
					case 'html': {
						const htmlContent = formatAsHtml(report, mermaidDiagram);
						output = {
							html: htmlContent,
							mermaid: mermaidDiagram,
							riskScore: report.risk.score,
							riskLevel: report.risk.level,
							findingsCount: report.summary.totalFindings,
						};
						break;
					}

					case 'slack': {
						const blocks = formatAsSlackBlocks(report);
						const textFallback = `Security Scan: ${report.workflow.name} - Risk Score: ${report.risk.score}/100 (${report.risk.level.toUpperCase()}) - ${report.summary.totalFindings} findings`;

						// n8n Slack node requires {"blocks": [...]} wrapped format
						// See: https://community.n8n.io/t/slack-node-blocks-are-ignored-only-text-is-displayed-despite-successful-api-call/154767
						output = {
							// USE THIS in Slack node Blocks field: {{ JSON.stringify($json.slackMessage) }}
							slackMessage: {
								blocks,
							},
							// Plain text for Notification Text field: {{ $json.text }}
							text: textFallback,
							// Metadata for conditional logic
							riskScore: report.risk.score,
							riskLevel: report.risk.level,
							findingsCount: report.summary.totalFindings,
						};
						break;
					}

					case 'sarif': {
						const sarifLog = formatAsSarif(report);
						output = sarifLog as unknown as IDataObject;
						break;
					}

					case 'json':
					default:
						// Standard JSON output - use outputFormat for detail level
						switch (options.outputFormat) {
							case 'summary':
								output = {
									workflow: {
										id: report.workflow.id,
										name: report.workflow.name,
										nodeCount: report.workflow.nodeCount,
									},
									riskScore: report.risk.score,
									riskLevel: report.risk.level,
									summary: {
										totalFindings: report.summary.totalFindings,
										bySeverity: report.summary.bySeverity,
										byCategory: report.summary.byCategory,
									},
									recommendations: report.recommendations.slice(0, 3),
								};
								break;

							case 'findings':
								output = {
									riskScore: report.risk.score,
									riskLevel: report.risk.level,
									findings: report.findings.map((f) => ({
										id: f.id,
										ruleId: f.ruleId,
										severity: f.severity,
										confidence: f.confidence,
										title: f.title,
										description: f.description,
										category: f.category,
										source: f.source.node,
										sink: f.sink.node,
										path: f.path,
										remediation: options.includeRemediation !== false ? f.remediation : undefined,
										references: f.references,
									})),
								};
								break;

							case 'full':
							default:
								output = {
									metadata: report.metadata,
									workflow: report.workflow,
									risk: report.risk,
									summary: report.summary,
									findings: report.findings.map((f) => ({
										id: f.id,
										ruleId: f.ruleId,
										severity: f.severity,
										confidence: f.confidence,
										title: f.title,
										description: f.description,
										category: f.category,
										source: f.source,
										sink: f.sink,
										path: f.path,
										remediation: f.remediation,
										references: f.references,
									})),
									findingsByCategory: report.findingsByCategory.map((g) => ({
										category: g.key,
										label: g.label,
										count: g.count,
										findings: g.findings.map((f) => f.id),
									})),
									findingsBySeverity: report.findingsBySeverity.map((g) => ({
										severity: g.key,
										label: g.label,
										count: g.count,
										findings: g.findings.map((f) => f.id),
									})),
									nodeAssessments: report.nodeAssessments,
									recommendations: report.recommendations,
									warnings: report.warnings,
									ruleStats: report.ruleStats,
								};
								break;
						}
						// Add Mermaid diagram to JSON output if requested
						if (mermaidDiagram) {
							output.mermaid = mermaidDiagram;
						}
						break;
				}

				returnData.push({
					json: output,
					pairedItem: itemIndex,
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error instanceof Error ? error.message : 'Unknown error',
						},
						pairedItem: itemIndex,
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}

/**
 * Get all available rule metadata (useful for documentation)
 */
export function getAvailableRules() {
	return getAllRuleMetadata();
}
