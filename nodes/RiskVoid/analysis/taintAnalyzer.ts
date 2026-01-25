/**
 * Taint Analyzer - Traces data flow from sources to sinks
 *
 * Implements:
 * - findTaintSources: Find all taint source nodes
 * - findSecuritySinks: Find all security sink nodes with expressions
 * - analyzeTaintFlows: Find vulnerable paths from sources to sinks
 */

import type { ParsedWorkflow } from './workflowParser';
import type { WorkflowGraph } from '../types/graph';
import type {
	TaintSource,
	SecuritySink,
	DangerousParameter,
	TaintPath,
	TaintAnalysisOptions,
	TaintFlowCheckResult,
	SanitizerCheckResult,
	TraceBackResult,
} from '../types/taint';
import type { SinkSeverity } from '../types/classification';
import { classifyNode, getSinkClassification, isDualRoleNode } from './nodeClassifier';
import { parseExpressions, resolveReferenceSource } from './expressionTracer';
import { findAllPaths } from './graphBuilder';

/**
 * Default options for taint analysis
 */
const DEFAULT_OPTIONS: TaintAnalysisOptions = {
	maxPathsPerPair: 50,
	maxPathDepth: 15,
	includeSanitized: true,
};

/**
 * Find all taint sources in the workflow
 */
export function findTaintSources(
	workflow: ParsedWorkflow,
	_graph: WorkflowGraph, // Reserved for future graph-based source detection
): TaintSource[] {
	void _graph; // Suppress unused variable warning
	const sources: TaintSource[] = [];

	for (const [nodeName, node] of workflow.nodes) {
		const classification = classifyNode(node);

		if (classification.role === 'source') {
			// Only include untrusted or semi-trusted sources
			if (classification.trustLevel !== 'trusted') {
				sources.push({
					nodeName,
					nodeType: node.type,
					trustLevel: classification.trustLevel,
					taintedFields: classification.taintedFields,
					classification,
				});
			}
		}
	}

	return sources;
}

/**
 * Source types that output their tainted data directly as $json
 * (rather than nested under a specific field)
 */
const DIRECT_OUTPUT_SOURCES = [
	'n8n-nodes-base.webhook',
	'n8n-nodes-base.formTrigger',
	'n8n-nodes-base.slackTrigger',
	'n8n-nodes-base.telegramTrigger',
	'n8n-nodes-base.emailReadImap',
	'n8n-nodes-base.discordTrigger',
	'n8n-nodes-base.twitterTrigger',
];

/**
 * Check if a specific field is tainted
 * Handles wildcard (*) for "all fields tainted"
 */
export function isFieldTainted(source: TaintSource, fieldPath: string[]): boolean {
	// Wildcard means all fields are tainted
	if (source.taintedFields.includes('*')) {
		return true;
	}

	// Empty field path means entire output is accessed
	if (fieldPath.length === 0) {
		return true;
	}

	// For direct-output sources (like webhook), the $json IS the tainted data
	// So any field access like $json.code means accessing data within the untrusted body
	// This is a conservative approach - we assume all fields from untrusted sources are tainted
	if (DIRECT_OUTPUT_SOURCES.includes(source.nodeType)) {
		// If the source outputs untrusted data directly (e.g., body, headers, query, params for webhook)
		// then any field access from that source is potentially tainted
		// For example: $json.code from a webhook is tainted because it's user-controlled body content
		return true;
	}

	// Check if the field or any parent is in tainted list
	const fieldPathStr = fieldPath.join('.');

	for (const taintedField of source.taintedFields) {
		// Exact match
		if (taintedField === fieldPathStr) {
			return true;
		}

		// Field is child of tainted field
		if (fieldPathStr.startsWith(taintedField + '.')) {
			return true;
		}

		// Tainted field is child of accessed field (accessing parent exposes taint)
		if (taintedField.startsWith(fieldPathStr + '.')) {
			return true;
		}

		// First field matches
		if (fieldPath[0] === taintedField) {
			return true;
		}
	}

	return false;
}

/**
 * Get nested value from object using dot notation path
 */
function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
	const parts = path.split('.');
	let current: unknown = obj;

	for (const part of parts) {
		if (current === null || current === undefined) {
			return undefined;
		}

		if (typeof current === 'object') {
			current = (current as Record<string, unknown>)[part];
		} else {
			return undefined;
		}
	}

	return current;
}

/**
 * Analyze parameters to find dangerous ones with expressions
 */
function analyzeDangerousParams(
	parameters: Record<string, unknown>,
	dangerousParamPaths: string[],
): DangerousParameter[] {
	const results: DangerousParameter[] = [];

	for (const paramPath of dangerousParamPaths) {
		const value = getNestedValue(parameters, paramPath);

		if (value !== undefined) {
			const parseResult = parseExpressions(value);

			results.push({
				paramPath,
				value,
				hasExpressions: parseResult.hasExpressions,
				expressions: parseResult.references,
			});
		}
	}

	return results;
}

/**
 * Find all security sinks in the workflow
 * Only includes sinks that have expressions in dangerous parameters
 */
export function findSecuritySinks(
	workflow: ParsedWorkflow,
	_graph: WorkflowGraph, // Reserved for future graph-based sink detection
): SecuritySink[] {
	void _graph; // Suppress unused variable warning
	const sinks: SecuritySink[] = [];

	for (const [nodeName, node] of workflow.nodes) {
		// For dual-role nodes, get sink classification directly
		const classification = isDualRoleNode(node.type)
			? getSinkClassification(node.type)
			: classifyNode(node);

		if (classification && classification.role === 'sink') {
			const dangerousParams = analyzeDangerousParams(
				node.parameters,
				classification.dangerousParams,
			);

			// Only include as sink if dangerous params have expressions
			// (static values are not vulnerable to injection)
			const hasVulnerableParams = dangerousParams.some((p) => p.hasExpressions);

			if (hasVulnerableParams) {
				sinks.push({
					nodeName,
					nodeType: node.type,
					severity: classification.severity,
					riskType: classification.riskType,
					dangerousParams,
					classification,
				});
			}
		}
	}

	return sinks;
}

/**
 * Find potential sanitizer nodes in a path
 */
function findSanitizersInPath(workflow: ParsedWorkflow, path: string[]): SanitizerCheckResult {
	const sanitizerNodes: string[] = [];

	// Don't include first (source) and last (sink) nodes
	for (let i = 1; i < path.length - 1; i++) {
		const nodeName = path[i];
		const node = workflow.nodes.get(nodeName);
		if (!node) continue;

		const classification = classifyNode(node);
		if (classification.role === 'sanitizer') {
			sanitizerNodes.push(nodeName);
		}

		// Also check Code nodes for validation patterns
		if (node.type === 'n8n-nodes-base.code') {
			if (containsValidationPattern(node.parameters)) {
				sanitizerNodes.push(nodeName);
			}
		}
	}

	return {
		hasSanitizer: sanitizerNodes.length > 0,
		sanitizerNodes,
	};
}

/**
 * Check if code contains validation/sanitization patterns
 */
function containsValidationPattern(params: Record<string, unknown>): boolean {
	const code = String(params.jsCode || params.pythonCode || '');

	const validationPatterns = [
		/if\s*\(/, // Conditional check
		/typeof\s+\w+\s*[!=]==?/, // Type checking
		/\.match\s*\(/, // Regex matching
		/\.test\s*\(/, // Regex test
		/parseInt|parseFloat/, // Type conversion
		/sanitize|validate|check/i, // Named functions
		/allowlist|whitelist/i, // Allowlist patterns
		/throw\s+|reject\s*\(/, // Error throwing
	];

	return validationPatterns.some((pattern) => pattern.test(code));
}

/**
 * Reduce severity by one level if sanitizer is present
 */
function reduceSeverity(severity: SinkSeverity): SinkSeverity {
	const reductionMap: Record<SinkSeverity, SinkSeverity> = {
		critical: 'high',
		high: 'medium',
		medium: 'low',
		low: 'low',
	};

	return reductionMap[severity];
}

/**
 * Calculate confidence level for the finding
 */
function calculateConfidence(
	flowResult: TaintFlowCheckResult,
	sanitizerCheck: SanitizerCheckResult,
): 'high' | 'medium' | 'low' {
	// High confidence if direct reference and no sanitizers
	if (flowResult.traceChain.length <= 2 && !sanitizerCheck.hasSanitizer) {
		return 'high';
	}

	// Medium confidence if longer chain or has sanitizers
	if (flowResult.traceChain.length <= 4) {
		return 'medium';
	}

	// Low confidence for very long chains
	return 'low';
}

/**
 * Trace an expression reference back through the path to see if it reaches source
 *
 * For the MVP, we use a permissive approach:
 * - If the expression directly references the source node and a tainted field, HIGH confidence
 * - If the expression references a node in the path between source and sink, MEDIUM confidence
 *   (assumes taint propagates through transform nodes even if field names change)
 */
function traceBackToSource(
	workflow: ParsedWorkflow,
	graph: WorkflowGraph,
	path: string[],
	startNode: string | null,
	source: TaintSource,
	fieldPath: string[],
): TraceBackResult {
	const result: TraceBackResult = {
		reachesSource: false,
		sourceField: '',
		chain: [],
	};

	if (!startNode) return result;

	// Simple case: expression directly references source node
	if (startNode === source.nodeName) {
		if (isFieldTainted(source, fieldPath)) {
			result.reachesSource = true;
			result.sourceField = fieldPath.join('.') || '*';
			result.chain = [startNode];
		}
		return result;
	}

	// Check if startNode is in our path between source and sink
	const startIndex = path.indexOf(startNode);
	const sourceIndex = path.indexOf(source.nodeName);

	if (startIndex === -1 || sourceIndex === -1 || sourceIndex >= startIndex) {
		// Referenced node is not between source and sink in path
		return result;
	}

	// MVP approach: If there's a path from an untrusted source to a sink with dynamic expressions,
	// assume taint can propagate through transform nodes even if field names change.
	// This may produce some false positives but catches real vulnerabilities.
	//
	// The chain goes: source -> ... -> startNode (referenced by sink) -> ... -> sink
	// Since startNode is in the path and comes after source, data could flow through.
	result.reachesSource = true;
	result.sourceField = source.taintedFields.includes('*') ? '*' : source.taintedFields[0] || '*';
	result.chain = path.slice(sourceIndex, startIndex + 1);

	return result;
}

/**
 * Check if taint from source actually flows to sink's dangerous parameter
 */
function checkTaintFlow(
	workflow: ParsedWorkflow,
	graph: WorkflowGraph,
	path: string[],
	source: TaintSource,
	sink: SecuritySink,
): TaintFlowCheckResult {
	const result: TaintFlowCheckResult = {
		flowsToSink: false,
		taintedField: '',
		sinkParam: '',
		traceChain: [],
	};

	// For each dangerous parameter in the sink
	for (const dangerousParam of sink.dangerousParams) {
		if (!dangerousParam.hasExpressions) continue;

		// Check each expression in the parameter
		for (const expr of dangerousParam.expressions) {
			// Resolve which node this expression references
			const sinkNode = graph.nodes.get(sink.nodeName);
			if (!sinkNode) continue;

			const referencedNode = resolveReferenceSource(
				expr,
				sink.nodeName,
				sinkNode.predecessors,
			);

			// Trace back through the path to see if it reaches our source
			const traceResult = traceBackToSource(
				workflow,
				graph,
				path,
				referencedNode,
				source,
				expr.fieldPath,
			);

			if (traceResult.reachesSource) {
				result.flowsToSink = true;
				result.taintedField = traceResult.sourceField;
				result.sinkParam = dangerousParam.paramPath;
				result.traceChain = traceResult.chain;
				return result;
			}
		}
	}

	return result;
}

/**
 * Main taint flow analysis function
 * Finds all vulnerable paths from sources to sinks
 */
export function analyzeTaintFlows(
	workflow: ParsedWorkflow,
	graph: WorkflowGraph,
	sources: TaintSource[],
	sinks: SecuritySink[],
	options: Partial<TaintAnalysisOptions> = {},
): TaintPath[] {
	const opts = { ...DEFAULT_OPTIONS, ...options };
	const vulnerablePaths: TaintPath[] = [];
	let pathId = 0;

	for (const source of sources) {
		for (const sink of sinks) {
			// Skip if source and sink are the same node
			if (source.nodeName === sink.nodeName) {
				continue;
			}

			// Find all paths from source to sink
			const paths = findAllPaths(
				graph,
				source.nodeName,
				sink.nodeName,
				opts.maxPathsPerPair,
				opts.maxPathDepth,
			);

			for (const path of paths) {
				// Check if taint actually flows through this path to sink
				const taintFlowResult = checkTaintFlow(workflow, graph, path, source, sink);

				if (taintFlowResult.flowsToSink) {
					// Check for sanitizers
					const sanitizerCheck = findSanitizersInPath(workflow, path);

					// Calculate final severity
					const finalSeverity = sanitizerCheck.hasSanitizer
						? reduceSeverity(sink.severity)
						: sink.severity;

					// Skip sanitized paths if not included
					if (sanitizerCheck.hasSanitizer && !opts.includeSanitized) {
						continue;
					}

					vulnerablePaths.push({
						id: `TAINT-${++pathId}`,
						source,
						sink,
						path,
						taintedField: taintFlowResult.taintedField,
						sinkParam: taintFlowResult.sinkParam,
						severity: finalSeverity,
						sanitized: sanitizerCheck.hasSanitizer,
						sanitizerNodes: sanitizerCheck.sanitizerNodes,
						confidence: calculateConfidence(taintFlowResult, sanitizerCheck),
					});
				}
			}
		}
	}

	// Sort by severity (critical first)
	return vulnerablePaths.sort((a, b) => {
		const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
		return severityOrder[a.severity] - severityOrder[b.severity];
	});
}
