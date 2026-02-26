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
	'n8n-nodes-base.httpRequest',
	'n8n-nodes-base.gmail',
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
	_graph: WorkflowGraph,
): SecuritySink[] {
	const sinks: SecuritySink[] = [];

	for (const [nodeName, node] of workflow.nodes) {
		// Skip nodes not in the graph (disabled or disconnected)
		if (!_graph.nodes.has(nodeName)) continue;

		// Skip sink nodes that have no predecessors and are not source nodes (truly disconnected)
		const graphNode = _graph.nodes.get(nodeName);
		if (graphNode && graphNode.predecessors.length === 0) continue;

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
 * Find potential sanitizer nodes in a path that match the target risk
 */
function findSanitizersInPath(
	workflow: ParsedWorkflow,
	path: string[],
	targetRiskType: string,
): SanitizerCheckResult {
	const sanitizerNodes: string[] = [];

	// Don't include first (source) and last (sink) nodes
	for (let i = 1; i < path.length - 1; i++) {
		const nodeName = path[i];
		const node = workflow.nodes.get(nodeName);
		if (!node) continue;

		const classification = classifyNode(node);
		if (classification.role === 'sanitizer') {
			// Check if this sanitizer handles the specific risk
			const validatesAgainst = classification.validatesAgainst || ['*'];
			if (validatesAgainst.includes('*') || validatesAgainst.includes(targetRiskType)) {
				sanitizerNodes.push(nodeName);
			}
		}

		// Also check Code nodes for validation patterns
		// For Code nodes, we assume they can validate anything if they have validation code
		// ideally we would parse the code to see WHAT it validates, but that's advanced.
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
 * Implements data dependency tracking through Transform nodes
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

	// Verify path order
	const startIndex = path.indexOf(startNode);
	const sourceIndex = path.indexOf(source.nodeName);

	if (startIndex === -1 || sourceIndex === -1 || sourceIndex >= startIndex) {
		return result;
	}

	// Data Dependency Tracking
	// Start with the source's tainted fields
	// If source is direct output (e.g. webhook), it's essentially '*' or specific fields
	let currentTaintedFields = [...source.taintedFields];

	// Traverse the path from Source to StartNode (exclusive)
	for (let i = sourceIndex + 1; i <= startIndex; i++) {
		const nodeName = path[i];
		const prevNodeName = path[i - 1]; // Node feeding into this one

		// Propagate taint through this node
		const node = workflow.nodes.get(nodeName);
		if (!node) continue;

		// Handle Set Node (Transformation)
		if (node.type === 'n8n-nodes-base.set') {
			const options = node.parameters.options as Record<string, boolean> | undefined;
			const keepOnlySet = options?.keepOnlySet === true;

			// If keepOnlySet, start with empty list. Otherwise copy previous.
			let nextTaintedFields = keepOnlySet ? [] : [...currentTaintedFields];

			const values = node.parameters.values as Record<string, unknown> | undefined;
			if (values) {
				// v2 format: Iterate over all assignments (string, number, boolean, etc)
				const assignments: { name: string; value: string }[] = [];
				if (Array.isArray(values.string)) assignments.push(...(values.string as { name: string; value: string }[]));
				if (Array.isArray(values.number)) assignments.push(...(values.number as { name: string; value: string }[]));
				if (Array.isArray(values.boolean)) assignments.push(...(values.boolean as { name: string; value: string }[]));

				for (const assign of assignments) {
					const targetName = assign.name;
					const expression = String(assign.value);

					// Check if expression references any currently tainted field
					const parsed = parseExpressions(expression);
					let isTainted = false;

					// If input is wildcard '*', ANY reference to input is tainted
					// Except references to non-input things like $env (but safer to assume tainted)
					// Helper: Check dependencies
					if (parsed.hasExpressions) {
						for (const ref of parsed.references) {
							// Check if this reference resolves to the previous node (prevNodeName)
							const refSource = resolveReferenceSource(ref, nodeName, [prevNodeName]);

							// If it refers to our tainted stream matching prevNodeName
							if (refSource === prevNodeName) {
								if (currentTaintedFields.includes('*')) {
									isTainted = true;
									break;
								}
								// For DIRECT_OUTPUT_SOURCES, all field accesses are tainted
								const prevNodeType = workflow.nodes.get(prevNodeName)?.type || '';
								if (DIRECT_OUTPUT_SOURCES.includes(prevNodeType)) {
									isTainted = true;
									break;
								}
								// Check if referenced field is tainted
								// ref.fieldPath
								const refField = ref.fieldPath.join('.');
								if (isFieldInList(refField, currentTaintedFields)) {
									isTainted = true;
									break;
								}
							}

							// Also handle references to Source Node directly (skipping chain)
							// If Set matches `{{ $('Webhook').body }}`, it picks up taint directly from Source
							if (refSource === source.nodeName) {
								// For DIRECT_OUTPUT_SOURCES, all field accesses are tainted
								if (DIRECT_OUTPUT_SOURCES.includes(source.nodeType)) {
									isTainted = true;
									break;
								}
								const refField = ref.fieldPath.join('.');
								if (isFieldInList(refField, source.taintedFields)) {
									isTainted = true;
									break;
								}
							}
						}
					}

					if (isTainted) {
						// Add to tainted fields
						if (!nextTaintedFields.includes(targetName)) {
							nextTaintedFields.push(targetName);
						}
					} else {
						// It's a clean assignment (static or safe source).
						// Remove from tainted fields if it was there (overwriting)
						// Be careful with partial overwrites (object properties), but for MVP assume root overwrite
						nextTaintedFields = nextTaintedFields.filter(f => f !== targetName && !f.startsWith(targetName + '.'));
					}
				}
			}

			// v3.4 format: assignments.assignments[{ name, value, type }]
			const assignmentsObj = node.parameters.assignments as Record<string, unknown> | undefined;
			if (assignmentsObj && Array.isArray(assignmentsObj.assignments)) {
				const v34Assignments = assignmentsObj.assignments as { name: string; value: string; type?: string }[];

				for (const assign of v34Assignments) {
					const targetName = assign.name;
					const expression = String(assign.value);

					const parsed = parseExpressions(expression);
					let isTainted = false;

					if (parsed.hasExpressions) {
						for (const ref of parsed.references) {
							const refSource = resolveReferenceSource(ref, nodeName, [prevNodeName]);

							if (refSource === prevNodeName) {
								if (currentTaintedFields.includes('*')) {
									isTainted = true;
									break;
								}
								// For DIRECT_OUTPUT_SOURCES, all field accesses are tainted
								const prevNodeType = workflow.nodes.get(prevNodeName)?.type || '';
								if (DIRECT_OUTPUT_SOURCES.includes(prevNodeType)) {
									isTainted = true;
									break;
								}
								const refField = ref.fieldPath.join('.');
								if (isFieldInList(refField, currentTaintedFields)) {
									isTainted = true;
									break;
								}
							}

							if (refSource === source.nodeName) {
								// For DIRECT_OUTPUT_SOURCES, all field accesses are tainted
								if (DIRECT_OUTPUT_SOURCES.includes(source.nodeType)) {
									isTainted = true;
									break;
								}
								const refField = ref.fieldPath.join('.');
								if (isFieldInList(refField, source.taintedFields)) {
									isTainted = true;
									break;
								}
							}
						}
					}

					if (isTainted) {
						if (!nextTaintedFields.includes(targetName)) {
							nextTaintedFields.push(targetName);
						}
					} else {
						nextTaintedFields = nextTaintedFields.filter(f => f !== targetName && !f.startsWith(targetName + '.'));
					}
				}
			}
			currentTaintedFields = nextTaintedFields;
		}
		// Handle Code nodes specially: they can arbitrarily transform field names
		// If the Code node consumes tainted data, conservatively treat all output as tainted
		else if (
			(node.type === 'n8n-nodes-base.code' ||
			 node.type === 'n8n-nodes-base.function' ||
			 node.type === 'n8n-nodes-base.functionItem') &&
			currentTaintedFields.length > 0
		) {
			// Check if the Code node's code references any tainted data
			const codeStr = String(node.parameters.jsCode || node.parameters.pythonCode || node.parameters.functionCode || '');
			const codeParsed = parseExpressions(codeStr);
			if (codeParsed.hasExpressions) {
				let consumesTaint = false;
				for (const ref of codeParsed.references) {
					const refSource = resolveReferenceSource(ref, nodeName, [prevNodeName]);
					if (refSource === prevNodeName || refSource === source.nodeName) {
						consumesTaint = true;
						break;
					}
				}
				if (consumesTaint) {
					// Code node consumes tainted data and can output under any field name
					currentTaintedFields = ['*'];
				}
			}
		}
		// Handle Unknown Nodes / PassThrough
		else {
			// For unrelated nodes or unknown transforms, we conservatively assume they propagate taint.
			// This works for IF, Switch, etc. that pass data through unchanged.
			// Current implementation: Do nothing (preserve currentTaintedFields).
		}

		// If we reached the startNode, check if the requested field is in our tainted set
		// We check AFTER processing the node because we want to know if the OUTPUT of this node is tainted
		if (nodeName === startNode) {
			const targetField = fieldPath.join('.');

			// If we are tracking wildcards, everything is tainted
			if (currentTaintedFields.includes('*')) {
				result.reachesSource = true;
				result.sourceField = '*';
				result.chain = path.slice(sourceIndex, startIndex + 1);
				return result;
			}

			// Check for exact data match
			for (const taintedField of currentTaintedFields) {
				// Exact match
				if (taintedField === targetField) {
					result.reachesSource = true;
					result.sourceField = taintedField;
					result.chain = path.slice(sourceIndex, startIndex + 1);
					return result;
				}
				// Tainted field is parent of target (e.g. tainted 'body', target 'body.email')
				if (targetField.startsWith(taintedField + '.')) {
					result.reachesSource = true;
					result.sourceField = taintedField;
					result.chain = path.slice(sourceIndex, startIndex + 1);
					return result;
				}
				// Target is parent of tainted field (e.g. tainted 'body.email', target 'body')
				if (taintedField.startsWith(targetField + '.')) {
					result.reachesSource = true;
					result.sourceField = taintedField;
					result.chain = path.slice(sourceIndex, startIndex + 1);
					return result;
				}
			}
			return result; // Not found in tainted set
		}

		// Optimization: If tainted set becomes empty, we can stop tracking?
		// Only if we are sure no side-channel re-introduction (like direct reference to source)
		// But direct reference is handled by `resolveReferenceSource` logic in Set.
		if (currentTaintedFields.length === 0) {
			// If we lost all taint, and we are just passing through, we are clean.
			// But maybe the Sink references the Source DIRECTLY?
			// traceBackToSource handles the startNode reference.
			// If startNode is this Set node, and currentTaintedFields is empty, result is false. Correct.
			// But wait, if Sink references Source directly, `startNode === source.nodeName` block handles it.
			// Here we are tracing flow THROUGH nodes.

			// Wait, what if sink references an intermediate node that WAS tainted, but we are now at a later node?
			// The loop goes up to `startIndex` (which is the node referenced by Sink).
			// So if we empty out before `startIndex`, then `startNode` is clean.
			// Correct.
		}
	}

	return result;
}

/**
 * Helper to check if a field matches any in the tainted list
 */
function isFieldInList(field: string, list: string[]): boolean {
	if (list.includes('*')) return true;
	for (const item of list) {
		if (item === field || field.startsWith(item + '.') || item.startsWith(field + '.')) {
			return true;
		}
	}
	return false;
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
					const sanitizerCheck = findSanitizersInPath(
						workflow,
						path,
						sink.riskType
					);

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
