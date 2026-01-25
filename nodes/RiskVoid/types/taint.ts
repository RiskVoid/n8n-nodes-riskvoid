/**
 * Type definitions for taint analysis
 */

import type { SourceClassification, SinkClassification, SinkSeverity } from './classification';
import type { ExpressionReference } from '../analysis/expressionTracer';

/**
 * Represents a taint source in the workflow
 */
export interface TaintSource {
	nodeName: string;
	nodeType: string;
	trustLevel: 'untrusted' | 'semi-trusted';
	taintedFields: string[];
	classification: SourceClassification;
}

/**
 * A parameter that could be dangerous if it contains tainted data
 */
export interface DangerousParameter {
	paramPath: string; // e.g., "jsCode" or "query"
	value: unknown; // The actual value
	hasExpressions: boolean; // Whether it contains {{ }}
	expressions: ExpressionReference[];
}

/**
 * Represents a security sink in the workflow
 */
export interface SecuritySink {
	nodeName: string;
	nodeType: string;
	severity: SinkSeverity;
	riskType: string;
	dangerousParams: DangerousParameter[];
	classification: SinkClassification;
}

/**
 * Represents a vulnerable taint flow path
 */
export interface TaintPath {
	id: string;
	source: TaintSource;
	sink: SecuritySink;
	path: string[]; // Node names in order
	taintedField: string; // Which field carries the taint
	sinkParam: string; // Which sink param receives taint
	severity: SinkSeverity;
	sanitized: boolean;
	sanitizerNodes: string[]; // Nodes that might sanitize
	confidence: 'high' | 'medium' | 'low';
}

/**
 * Options for taint analysis
 */
export interface TaintAnalysisOptions {
	maxPathsPerPair: number; // Max paths between source-sink pair
	maxPathDepth: number; // Max nodes in a path
	includeSanitized: boolean; // Include paths with sanitizers
}

/**
 * Result of checking if taint flows to a sink
 */
export interface TaintFlowCheckResult {
	flowsToSink: boolean;
	taintedField: string;
	sinkParam: string;
	traceChain: string[]; // How taint propagates through nodes
}

/**
 * Result of checking for sanitizers in a path
 */
export interface SanitizerCheckResult {
	hasSanitizer: boolean;
	sanitizerNodes: string[];
}

/**
 * Result of tracing back to a source
 */
export interface TraceBackResult {
	reachesSource: boolean;
	sourceField: string;
	chain: string[];
}

/**
 * Analysis error
 */
export interface AnalysisError {
	code: string;
	message: string;
	phase: 'parse' | 'graph' | 'taint' | 'unknown';
}

/**
 * Full analysis result
 */
export interface AnalysisResult {
	success: boolean;
	workflow: {
		id: string;
		name: string;
		nodeCount: number;
		connectionCount: number;
		hasCycles: boolean;
	} | null;
	analysis: {
		sources: TaintSource[];
		sinks: SecuritySink[];
		vulnerablePaths: TaintPath[];
		entryPoints: string[];
		exitPoints: string[];
		duration: number;
	} | null;
	errors: AnalysisError[];
	warnings: string[];
}

/**
 * Analysis options
 */
export interface AnalysisOptions {
	maxPathsPerPair?: number;
	maxPathDepth?: number;
	includeSanitized?: boolean;
	categories?: string[]; // Filter by vulnerability category
	minSeverity?: SinkSeverity | 'all';
}
