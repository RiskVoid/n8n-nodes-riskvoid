/**
 * Type definitions for node classification (source, sink, sanitizer)
 */

/**
 * Role of a node in security analysis
 */
export type NodeRole = 'source' | 'sink' | 'sanitizer' | 'transform' | 'unknown';

/**
 * Trust level of input sources
 */
export type TrustLevel = 'untrusted' | 'semi-trusted' | 'trusted';

/**
 * Severity level of security sinks
 */
export type SinkSeverity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Classification for source nodes (nodes that receive external input)
 */
export interface SourceClassification {
	role: 'source';
	/** Trust level of the input */
	trustLevel: TrustLevel;
	/** Fields that carry tainted data (e.g., 'body', 'headers', '*' for all) */
	taintedFields: string[];
	/** Human-readable description */
	description: string;
}

/**
 * Classification for sink nodes (nodes that perform dangerous operations)
 */
export interface SinkClassification {
	role: 'sink';
	/** Severity if tainted data reaches this sink */
	severity: SinkSeverity;
	/** Type of risk (e.g., 'RCE', 'SQL Injection', 'SSRF') */
	riskType: string;
	/** Parameters that are dangerous if tainted */
	dangerousParams: string[];
	/** Human-readable description */
	description: string;
}

/**
 * Classification for sanitizer nodes (nodes that reduce taint)
 */
export interface SanitizerClassification {
	role: 'sanitizer';
	/** Type of sanitization performed */
	sanitizerType: 'validation' | 'transformation' | 'conditional';
	/** Human-readable description */
	description: string;
}

/**
 * Classification for transform nodes (pass-through with possible modification)
 */
export interface TransformClassification {
	role: 'transform';
	/** Whether taint propagates through this node */
	propagatesTaint: boolean;
	/** Human-readable description */
	description: string;
}

/**
 * Classification for unknown/unrecognized nodes
 */
export interface UnknownClassification {
	role: 'unknown';
	/** Human-readable description */
	description: string;
}

/**
 * Union type for all node classifications
 */
export type NodeClassification =
	| SourceClassification
	| SinkClassification
	| SanitizerClassification
	| TransformClassification
	| UnknownClassification;

/**
 * Map of node names to their classifications
 */
export type ClassificationMap = Map<string, NodeClassification>;
