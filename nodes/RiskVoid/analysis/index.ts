/**
 * Analysis module exports
 */

export * from './workflowParser';
export * from './graphBuilder';
export {
	classifyNode,
	getSourceTypes,
	getSinkTypes,
	getSanitizerTypes,
	getSourceClassification,
	getSinkClassification,
	isDualRoleNode,
	getSinkSeverity,
	getSourceTrustLevel,
	// Note: isTriggerNode is exported from workflowParser, not here
} from './nodeClassifier';
export * from './expressionTracer';
export * from './taintAnalyzer';
export * from './findingsReporter';
export * from './reportFormatters';

// Re-export types needed for analysis
import type { AnalysisResult, AnalysisOptions } from '../types/taint';
import type { SinkSeverity } from '../types/classification';
import type { WorkflowGraph } from '../types/graph';
import { parseWorkflow } from './workflowParser';
import type { ParsedWorkflow } from './workflowParser';
import { buildGraph } from './graphBuilder';
import { findTaintSources, findSecuritySinks, analyzeTaintFlows } from './taintAnalyzer';

export type { AnalysisResult, AnalysisOptions };

/**
 * Main analysis entry point - orchestrates the full analysis pipeline
 */
export function analyzeWorkflow(
	workflowInput: unknown,
	options: AnalysisOptions = {},
): AnalysisResult {
	const startTime = Date.now();
	const warnings: string[] = [];

	// Phase 1: Parse workflow
	let workflow: ParsedWorkflow;

	try {
		const parseResult = parseWorkflow(workflowInput);

		if (!parseResult.success || !parseResult.workflow) {
			return {
				success: false,
				workflow: null,
				analysis: null,
				errors: parseResult.errors.map((e) => ({
					code: e.code,
					message: e.message,
					phase: 'parse' as const,
				})),
				warnings: parseResult.warnings.map((w) => w.message),
			};
		}

		workflow = parseResult.workflow;
		warnings.push(...parseResult.warnings.map((w) => w.message));
	} catch (error) {
		return {
			success: false,
			workflow: null,
			analysis: null,
			errors: [
				{
					code: 'PARSE_ERROR',
					message: error instanceof Error ? error.message : 'Unknown parse error',
					phase: 'parse',
				},
			],
			warnings: [],
		};
	}

	// Phase 2: Build graph
	let graph: WorkflowGraph;

	try {
		graph = buildGraph(workflow);

		if (graph.hasCycles) {
			warnings.push('Workflow contains cycles - analysis may be incomplete');
		}
	} catch (error) {
		return {
			success: false,
			workflow: {
				id: workflow.id,
				name: workflow.name,
				nodeCount: workflow.nodeCount,
				connectionCount: workflow.connectionCount,
				hasCycles: false,
			},
			analysis: null,
			errors: [
				{
					code: 'GRAPH_ERROR',
					message: error instanceof Error ? error.message : 'Unknown graph error',
					phase: 'graph',
				},
			],
			warnings,
		};
	}

	// Phase 3: Taint analysis
	try {
		const sources = findTaintSources(workflow, graph);
		const sinks = findSecuritySinks(workflow, graph);

		let vulnerablePaths = analyzeTaintFlows(workflow, graph, sources, sinks, {
			maxPathsPerPair: options.maxPathsPerPair,
			maxPathDepth: options.maxPathDepth,
			includeSanitized: options.includeSanitized,
		});

		// Filter by severity if specified
		if (options.minSeverity && options.minSeverity !== 'all') {
			const severityOrder: Record<SinkSeverity, number> = {
				critical: 0,
				high: 1,
				medium: 2,
				low: 3,
			};
			const minLevel = severityOrder[options.minSeverity as SinkSeverity];

			vulnerablePaths = vulnerablePaths.filter((p) => severityOrder[p.severity] <= minLevel);
		}

		// Filter by categories if specified
		if (options.categories && options.categories.length > 0) {
			const categoryToRiskType: Record<string, string[]> = {
				rce: ['RCE'],
				cmdi: ['Command Injection'],
				sqli: ['SQL Injection', 'NoSQL Injection'],
				ssrf: ['SSRF'],
				prompt: ['Prompt Injection'],
				creds: ['Credential Exposure'],
				xss: ['XSS'],
				path: ['Path Traversal'],
			};

			const allowedRiskTypes = new Set(
				options.categories.flatMap((c) => categoryToRiskType[c] || []),
			);

			vulnerablePaths = vulnerablePaths.filter((p) => allowedRiskTypes.has(p.sink.riskType));
		}

		const duration = Date.now() - startTime;

		return {
			success: true,
			workflow: {
				id: workflow.id,
				name: workflow.name,
				nodeCount: workflow.nodeCount,
				connectionCount: workflow.connectionCount,
				hasCycles: graph.hasCycles,
			},
			analysis: {
				sources,
				sinks,
				vulnerablePaths,
				entryPoints: graph.entryPoints,
				exitPoints: graph.exitPoints,
				duration,
			},
			errors: [],
			warnings,
		};
	} catch (error) {
		return {
			success: false,
			workflow: {
				id: workflow.id,
				name: workflow.name,
				nodeCount: workflow.nodeCount,
				connectionCount: workflow.connectionCount,
				hasCycles: graph.hasCycles,
			},
			analysis: null,
			errors: [
				{
					code: 'TAINT_ERROR',
					message: error instanceof Error ? error.message : 'Unknown taint analysis error',
					phase: 'taint',
				},
			],
			warnings,
		};
	}
}
