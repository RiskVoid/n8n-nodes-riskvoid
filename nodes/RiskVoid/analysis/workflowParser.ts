/**
 * Workflow Parser - Parses n8n workflow JSON into internal model
 */

import type {
	N8nWorkflow,
	N8nNode,
	N8nConnections,
	WorkflowMetadata,
	ParsedWorkflow,
} from '../types';

// Re-export for backwards compatibility
export type { ParsedWorkflow } from '../types';

/**
 * Result of parsing a workflow
 */
export interface ParseResult {
	success: boolean;
	workflow?: ParsedWorkflow;
	errors: ParseError[];
	warnings: ParseWarning[];
}

/**
 * Parse error (fatal - prevents analysis)
 */
export interface ParseError {
	code: string;
	message: string;
	path?: string;
}

/**
 * Parse warning (non-fatal - analysis can continue)
 */
export interface ParseWarning {
	code: string;
	message: string;
	nodeName?: string;
}

// Known trigger node type patterns
const TRIGGER_PATTERNS = [
	'Trigger',
	'trigger',
	'webhook',
	'Webhook',
	'schedule',
	'Schedule',
	'manualTrigger',
	'ManualTrigger',
];

/**
 * Check if a node type is a trigger
 */
export function isTriggerNode(type: string): boolean {
	return TRIGGER_PATTERNS.some(
		(pattern) => type.includes(pattern) || type.endsWith('Trigger'),
	);
}

/**
 * Validate that input is a valid workflow object
 */
function validateWorkflowStructure(input: unknown): ParseError[] {
	const errors: ParseError[] = [];

	if (input === null || input === undefined) {
		errors.push({
			code: 'INVALID_INPUT',
			message: 'Input is null or undefined',
		});
		return errors;
	}

	if (typeof input !== 'object') {
		errors.push({
			code: 'INVALID_INPUT',
			message: `Expected object, got ${typeof input}`,
		});
		return errors;
	}

	const obj = input as Record<string, unknown>;

	// Check for nodes array
	if (!Array.isArray(obj.nodes)) {
		errors.push({
			code: 'MISSING_NODES',
			message: 'Workflow must have a "nodes" array',
			path: 'nodes',
		});
	}

	// Check for connections object
	if (obj.connections === undefined || obj.connections === null) {
		errors.push({
			code: 'MISSING_CONNECTIONS',
			message: 'Workflow must have a "connections" object',
			path: 'connections',
		});
	} else if (typeof obj.connections !== 'object' || Array.isArray(obj.connections)) {
		errors.push({
			code: 'INVALID_CONNECTIONS',
			message: 'Connections must be an object',
			path: 'connections',
		});
	}

	return errors;
}

/**
 * Validate and parse a single node
 */
function parseNode(
	raw: unknown,
	index: number,
): { node?: N8nNode; warning?: ParseWarning } {
	if (raw === null || raw === undefined || typeof raw !== 'object') {
		return {
			warning: {
				code: 'INVALID_NODE',
				message: `Node at index ${index} is not an object`,
			},
		};
	}

	const obj = raw as Record<string, unknown>;

	// Required fields
	if (typeof obj.name !== 'string' || obj.name.trim() === '') {
		return {
			warning: {
				code: 'MISSING_NODE_NAME',
				message: `Node at index ${index} is missing a valid name`,
			},
		};
	}

	if (typeof obj.type !== 'string' || obj.type.trim() === '') {
		return {
			warning: {
				code: 'MISSING_NODE_TYPE',
				message: `Node "${obj.name}" is missing a valid type`,
				nodeName: obj.name as string,
			},
		};
	}

	// Build node with defaults for optional fields
	const node: N8nNode = {
		id: typeof obj.id === 'string' ? obj.id : `node-${index}`,
		name: obj.name as string,
		type: obj.type as string,
		typeVersion: typeof obj.typeVersion === 'number' ? obj.typeVersion : 1,
		position: Array.isArray(obj.position) ? (obj.position as [number, number]) : [0, 0],
		parameters:
			typeof obj.parameters === 'object' && obj.parameters !== null
				? (obj.parameters as Record<string, unknown>)
				: {},
		credentials:
			typeof obj.credentials === 'object' && obj.credentials !== null
				? (obj.credentials as Record<string, { id: string; name: string }>)
				: undefined,
		disabled: typeof obj.disabled === 'boolean' ? obj.disabled : false,
		notes: typeof obj.notes === 'string' ? obj.notes : undefined,
		notesInFlow: typeof obj.notesInFlow === 'boolean' ? obj.notesInFlow : undefined,
		webhookId: typeof obj.webhookId === 'string' ? obj.webhookId : undefined,
	};

	return { node };
}

/**
 * Count connections in the workflow
 */
function countConnections(connections: N8nConnections): number {
	let count = 0;
	for (const sourceNode of Object.values(connections)) {
		for (const outputType of Object.values(sourceNode)) {
			for (const outputIndex of outputType) {
				count += outputIndex.length;
			}
		}
	}
	return count;
}

/**
 * Extract metadata from parsed workflow
 */
function extractMetadata(
	nodes: Map<string, N8nNode>,
): WorkflowMetadata {
	const triggerTypes: string[] = [];
	const nodeTypes = new Set<string>();
	const credentialTypes = new Set<string>();
	let usesCredentials = false;

	for (const node of nodes.values()) {
		nodeTypes.add(node.type);

		if (isTriggerNode(node.type)) {
			triggerTypes.push(node.type);
		}

		if (node.credentials) {
			usesCredentials = true;
			for (const credType of Object.keys(node.credentials)) {
				credentialTypes.add(credType);
			}
		}
	}

	return {
		hasTriggers: triggerTypes.length > 0,
		triggerTypes,
		nodeTypes: Array.from(nodeTypes),
		usesCredentials,
		credentialTypes: Array.from(credentialTypes),
	};
}

/**
 * Parse n8n workflow JSON into internal model
 *
 * @param input - Raw workflow JSON (object or string)
 * @returns ParseResult with parsed workflow or errors
 */
export function parseWorkflow(input: unknown): ParseResult {
	const errors: ParseError[] = [];
	const warnings: ParseWarning[] = [];

	// Handle string input (JSON)
	let parsed: unknown = input;
	if (typeof input === 'string') {
		try {
			parsed = JSON.parse(input);
		} catch (e) {
			return {
				success: false,
				errors: [
					{
						code: 'INVALID_JSON',
						message: `Failed to parse JSON: ${e instanceof Error ? e.message : 'Unknown error'}`,
					},
				],
				warnings: [],
			};
		}
	}

	// Validate structure
	const structureErrors = validateWorkflowStructure(parsed);
	if (structureErrors.length > 0) {
		return {
			success: false,
			errors: structureErrors,
			warnings: [],
		};
	}

	const raw = parsed as N8nWorkflow;

	// Parse nodes
	const nodes = new Map<string, N8nNode>();
	const nodesByType = new Map<string, N8nNode[]>();

	for (let i = 0; i < raw.nodes.length; i++) {
		const result = parseNode(raw.nodes[i], i);

		if (result.warning) {
			warnings.push(result.warning);
			continue;
		}

		if (result.node) {
			// Check for duplicate names
			if (nodes.has(result.node.name)) {
				warnings.push({
					code: 'DUPLICATE_NODE_NAME',
					message: `Duplicate node name: "${result.node.name}" (keeping first occurrence)`,
					nodeName: result.node.name,
				});
				continue;
			}

			nodes.set(result.node.name, result.node);

			// Group by type
			const typeList = nodesByType.get(result.node.type) ?? [];
			typeList.push(result.node);
			nodesByType.set(result.node.type, typeList);
		}
	}

	// Check if we have any valid nodes
	if (nodes.size === 0) {
		errors.push({
			code: 'NO_VALID_NODES',
			message: 'No valid nodes found in workflow',
		});
		return {
			success: false,
			errors,
			warnings,
		};
	}

	const workflow: ParsedWorkflow = {
		id: raw.id ?? 'unknown',
		name: raw.name ?? 'Unnamed Workflow',
		nodes,
		nodesByType,
		connections: raw.connections,
		nodeCount: nodes.size,
		connectionCount: countConnections(raw.connections),
		metadata: extractMetadata(nodes),
		raw,
	};

	return {
		success: true,
		workflow,
		errors: [],
		warnings,
	};
}
