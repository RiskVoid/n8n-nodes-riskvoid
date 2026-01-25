/**
 * Type definitions for workflow graph representation
 */

import type { N8nNode } from './workflow';

/**
 * Graph representation of a workflow
 */
export interface WorkflowGraph {
	/** Map of node name to GraphNode */
	nodes: Map<string, GraphNode>;

	/** All edges in the graph */
	edges: GraphEdge[];

	/** Nodes with no predecessors (triggers, start points) */
	entryPoints: string[];

	/** Nodes with no successors (end points) */
	exitPoints: string[];

	/** Whether the graph contains cycles */
	hasCycles: boolean;
}

/**
 * Node in the workflow graph
 */
export interface GraphNode {
	/** Node name (unique identifier in workflow) */
	name: string;

	/** Node type (e.g., 'n8n-nodes-base.webhook') */
	type: string;

	/** Original n8n node data */
	data: N8nNode;

	/** Names of successor nodes (outgoing edges) */
	successors: string[];

	/** Names of predecessor nodes (incoming edges) */
	predecessors: string[];

	/** Depth from nearest entry point (BFS distance) */
	depth: number;
}

/**
 * Edge in the workflow graph
 */
export interface GraphEdge {
	/** Source node name */
	source: string;

	/** Target node name */
	target: string;

	/** Output index on source node (for multi-output nodes like IF) */
	sourceOutput: number;

	/** Input index on target node */
	targetInput: number;

	/** Output type (usually 'main') */
	outputType: string;
}

/**
 * Path through the workflow graph
 */
export interface GraphPath {
	/** Ordered list of node names from source to target */
	nodes: string[];

	/** Edges traversed in this path */
	edges: GraphEdge[];
}
