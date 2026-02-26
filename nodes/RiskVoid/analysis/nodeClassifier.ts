/**
 * Node Classifier - Classifies nodes as source, sink, sanitizer, or transform
 */

import type {
	N8nNode,
	NodeClassification,
	SourceClassification,
	SinkClassification,
	SanitizerClassification,
	TrustLevel,
	SinkSeverity,
} from '../types';

/**
 * Registry of source nodes (nodes that receive external input)
 */
import nodeDefinitions from '../config/nodeDefinitions.json';

/**
 * Registry of source nodes (nodes that receive external input)
 */
const SOURCE_NODES: Record<string, Omit<SourceClassification, 'role'>> =
	nodeDefinitions.sources as Record<string, Omit<SourceClassification, 'role'>>;

/**
 * Registry of sink nodes (nodes that perform dangerous operations)
 */
const SINK_NODES: Record<string, Omit<SinkClassification, 'role'>> =
	nodeDefinitions.sinks as Record<string, Omit<SinkClassification, 'role'>>;

/**
 * Registry of sanitizer nodes (nodes that can reduce taint)
 */
const SANITIZER_NODES: Record<string, Omit<SanitizerClassification, 'role'>> =
	nodeDefinitions.sanitizers as Record<string, Omit<SanitizerClassification, 'role'>>;

/**
 * Classify a node based on its type
 *
 * @param node - n8n node to classify
 * @returns NodeClassification
 */
export function classifyNode(node: N8nNode): NodeClassification {
	const { type } = node;

	// Check if it's a known source
	if (type in SOURCE_NODES) {
		return {
			role: 'source',
			...SOURCE_NODES[type],
		};
	}

	// Check if it's a known sink
	if (type in SINK_NODES) {
		return {
			role: 'sink',
			...SINK_NODES[type],
		};
	}

	// Check if it's a known sanitizer
	if (type in SANITIZER_NODES) {
		return {
			role: 'sanitizer',
			...SANITIZER_NODES[type],
		};
	}

	// Default: treat as transform (passes data through)
	return {
		role: 'transform',
		propagatesTaint: true,
		description: `Unknown node type: ${type}`,
	};
}

/**
 * Check if a node type is a trigger
 */
export function isTriggerNode(type: string): boolean {
	return (
		type.toLowerCase().includes('trigger') ||
		type.endsWith('Trigger') ||
		type === 'n8n-nodes-base.webhook' ||
		type === 'n8n-nodes-base.manualTrigger' ||
		type === 'n8n-nodes-base.scheduleTrigger'
	);
}

/**
 * Get all registered source node types
 */
export function getSourceTypes(): string[] {
	return Object.keys(SOURCE_NODES);
}

/**
 * Get all registered sink node types
 */
export function getSinkTypes(): string[] {
	return Object.keys(SINK_NODES);
}

/**
 * Get all registered sanitizer node types
 */
export function getSanitizerTypes(): string[] {
	return Object.keys(SANITIZER_NODES);
}

/**
 * Get source classification for a node type
 */
export function getSourceClassification(
	type: string,
): SourceClassification | null {
	if (type in SOURCE_NODES) {
		return { role: 'source', ...SOURCE_NODES[type] };
	}
	return null;
}

/**
 * Get sink classification for a node type
 */
export function getSinkClassification(type: string): SinkClassification | null {
	if (type in SINK_NODES) {
		return { role: 'sink', ...SINK_NODES[type] };
	}
	return null;
}

/**
 * Check if a node type is both a source and a sink (dual role)
 */
export function isDualRoleNode(type: string): boolean {
	return type in SOURCE_NODES && type in SINK_NODES;
}

/**
 * Get severity level for a sink node
 */
export function getSinkSeverity(type: string): SinkSeverity | null {
	if (type in SINK_NODES) {
		return SINK_NODES[type].severity;
	}
	return null;
}

/**
 * Get trust level for a source node
 */
export function getSourceTrustLevel(type: string): TrustLevel | null {
	if (type in SOURCE_NODES) {
		return SOURCE_NODES[type].trustLevel;
	}
	return null;
}
