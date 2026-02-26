/**
 * Graph Builder - Constructs directed graph from parsed workflow
 */

import type { WorkflowGraph, GraphNode, GraphEdge } from '../types';
import type { ParsedWorkflow } from './workflowParser';

/**
 * Build a directed graph from a parsed workflow
 *
 * @param workflow - Parsed workflow
 * @returns WorkflowGraph representation
 */
export function buildGraph(workflow: ParsedWorkflow): WorkflowGraph {
	const nodes = new Map<string, GraphNode>();
	const edges: GraphEdge[] = [];

	// Initialize graph nodes from workflow nodes
	for (const [name, node] of workflow.nodes) {
		if (node.disabled) {
			continue;
		}

		nodes.set(name, {
			name,
			type: node.type,
			data: node,
			successors: [],
			predecessors: [],
			depth: -1, // Will be calculated later
		});
	}

	// Build edges from connections
	for (const [sourceName, sourceConnections] of Object.entries(workflow.connections)) {
		const sourceNode = nodes.get(sourceName);
		if (!sourceNode) {
			// Source node doesn't exist (possibly removed or invalid)
			continue;
		}

		for (const [outputType, outputs] of Object.entries(sourceConnections)) {
			for (let outputIndex = 0; outputIndex < outputs.length; outputIndex++) {
				const targets = outputs[outputIndex];
				if (!targets) continue;

				for (const target of targets) {
					const targetNode = nodes.get(target.node);
					if (!targetNode) {
						// Target node doesn't exist
						continue;
					}

					// Add edge
					edges.push({
						source: sourceName,
						target: target.node,
						sourceOutput: outputIndex,
						targetInput: target.index,
						outputType,
					});

					// Update adjacency lists
					if (!sourceNode.successors.includes(target.node)) {
						sourceNode.successors.push(target.node);
					}
					if (!targetNode.predecessors.includes(sourceName)) {
						targetNode.predecessors.push(sourceName);
					}
				}
			}
		}
	}

	// Find entry points (nodes with no predecessors)
	const entryPoints: string[] = [];
	for (const [name, node] of nodes) {
		if (node.predecessors.length === 0) {
			entryPoints.push(name);
		}
	}

	// Find exit points (nodes with no successors)
	const exitPoints: string[] = [];
	for (const [name, node] of nodes) {
		if (node.successors.length === 0) {
			exitPoints.push(name);
		}
	}

	// Calculate depths from entry points
	calculateDepths(nodes, entryPoints);

	// Detect cycles
	const hasCycles = detectCycles(nodes);

	return {
		nodes,
		edges,
		entryPoints,
		exitPoints,
		hasCycles,
	};
}

/**
 * Calculate depth (BFS distance from nearest entry point) for each node
 */
function calculateDepths(
	nodes: Map<string, GraphNode>,
	entryPoints: string[],
): void {
	// BFS from all entry points simultaneously
	const queue: Array<{ name: string; depth: number }> = [];

	for (const entry of entryPoints) {
		queue.push({ name: entry, depth: 0 });
	}

	while (queue.length > 0) {
		const { name, depth } = queue.shift()!;
		const node = nodes.get(name);

		if (!node) continue;

		// Only update if not visited or found shorter path
		if (node.depth === -1 || depth < node.depth) {
			node.depth = depth;

			// Add successors to queue
			for (const successor of node.successors) {
				const successorNode = nodes.get(successor);
				if (successorNode && (successorNode.depth === -1 || depth + 1 < successorNode.depth)) {
					queue.push({ name: successor, depth: depth + 1 });
				}
			}
		}
	}

	// Set depth to 0 for any unreachable nodes (disconnected from entry points)
	for (const node of nodes.values()) {
		if (node.depth === -1) {
			node.depth = 0;
		}
	}
}

/**
 * Detect if the graph contains cycles using DFS
 */
function detectCycles(nodes: Map<string, GraphNode>): boolean {
	const visited = new Set<string>();
	const recursionStack = new Set<string>();

	function dfs(name: string): boolean {
		visited.add(name);
		recursionStack.add(name);

		const node = nodes.get(name);
		if (node) {
			for (const successor of node.successors) {
				if (!visited.has(successor)) {
					if (dfs(successor)) {
						return true;
					}
				} else if (recursionStack.has(successor)) {
					// Found a back edge - cycle detected
					return true;
				}
			}
		}

		recursionStack.delete(name);
		return false;
	}

	// Check all nodes (graph might be disconnected)
	for (const name of nodes.keys()) {
		if (!visited.has(name)) {
			if (dfs(name)) {
				return true;
			}
		}
	}

	return false;
}

/**
 * Get all nodes reachable from a starting node
 *
 * @param graph - Workflow graph
 * @param startNode - Starting node name
 * @param direction - 'forward' follows successors, 'backward' follows predecessors
 * @returns Set of reachable node names (includes startNode)
 */
export function getReachableNodes(
	graph: WorkflowGraph,
	startNode: string,
	direction: 'forward' | 'backward',
): Set<string> {
	const reachable = new Set<string>();
	const queue = [startNode];

	while (queue.length > 0) {
		const current = queue.shift()!;

		if (reachable.has(current)) {
			continue;
		}

		reachable.add(current);

		const node = graph.nodes.get(current);
		if (node) {
			const neighbors = direction === 'forward' ? node.successors : node.predecessors;
			for (const neighbor of neighbors) {
				if (!reachable.has(neighbor)) {
					queue.push(neighbor);
				}
			}
		}
	}

	return reachable;
}

/**
 * Find all paths between two nodes
 *
 * @param graph - Workflow graph
 * @param source - Source node name
 * @param target - Target node name
 * @param maxPaths - Maximum number of paths to return (default: 100)
 * @param maxDepth - Maximum path length (default: 20)
 * @returns Array of paths (each path is an array of node names)
 */
export function findAllPaths(
	graph: WorkflowGraph,
	source: string,
	target: string,
	maxPaths: number = 100,
	maxDepth: number = 20,
): string[][] {
	const paths: string[][] = [];

	function dfs(current: string, path: string[], visited: Set<string>): void {
		// Check limits
		if (paths.length >= maxPaths || path.length > maxDepth) {
			return;
		}

		// Found target
		if (current === target) {
			paths.push([...path]);
			return;
		}

		const node = graph.nodes.get(current);
		if (!node) return;

		// Explore successors
		for (const successor of node.successors) {
			if (!visited.has(successor)) {
				visited.add(successor);
				path.push(successor);
				dfs(successor, path, visited);
				path.pop();
				visited.delete(successor);
			}
		}
	}

	// Start DFS from source
	const startNode = graph.nodes.get(source);
	if (!startNode) {
		return paths;
	}

	const visited = new Set<string>([source]);
	dfs(source, [source], visited);

	return paths;
}

/**
 * Get the shortest path between two nodes using BFS
 *
 * @param graph - Workflow graph
 * @param source - Source node name
 * @param target - Target node name
 * @returns Shortest path as array of node names, or null if no path exists
 */
export function getShortestPath(
	graph: WorkflowGraph,
	source: string,
	target: string,
): string[] | null {
	if (source === target) {
		return [source];
	}

	const queue: Array<{ node: string; path: string[] }> = [{ node: source, path: [source] }];
	const visited = new Set<string>([source]);

	while (queue.length > 0) {
		const { node, path } = queue.shift()!;

		const graphNode = graph.nodes.get(node);
		if (!graphNode) continue;

		for (const successor of graphNode.successors) {
			if (successor === target) {
				return [...path, successor];
			}

			if (!visited.has(successor)) {
				visited.add(successor);
				queue.push({ node: successor, path: [...path, successor] });
			}
		}
	}

	return null;
}
