/**
 * Type definitions for n8n workflow JSON structure
 */

/**
 * Root workflow structure as exported from n8n
 */
export interface N8nWorkflow {
	id?: string;
	name: string;
	active: boolean;
	nodes: N8nNode[];
	connections: N8nConnections;
	settings?: WorkflowSettings;
	staticData?: unknown;
	tags?: WorkflowTag[];
	pinData?: Record<string, unknown>;
}

/**
 * Individual node in a workflow
 */
export interface N8nNode {
	id: string;
	name: string;
	type: string;
	typeVersion: number;
	position: [number, number];
	parameters: Record<string, unknown>;
	credentials?: Record<string, NodeCredential>;
	disabled?: boolean;
	notes?: string;
	notesInFlow?: boolean;
	webhookId?: string;
}

/**
 * Credential reference in a node
 */
export interface NodeCredential {
	id: string;
	name: string;
}

/**
 * Connection map: sourceNodeName -> outputType -> outputIndex -> targets
 */
export interface N8nConnections {
	[sourceNodeName: string]: NodeOutputConnections;
}

/**
 * Connections for a single node's outputs
 */
export interface NodeOutputConnections {
	[outputType: string]: ConnectionTarget[][];
}

/**
 * Target of a connection
 */
export interface ConnectionTarget {
	node: string;
	type: string;
	index: number;
}

/**
 * Workflow-level settings
 */
export interface WorkflowSettings {
	saveDataErrorExecution?: 'all' | 'none';
	saveDataSuccessExecution?: 'all' | 'none';
	saveManualExecutions?: boolean;
	callerPolicy?: 'any' | 'none' | 'workflowsFromAList' | 'workflowsFromSameOwner';
	executionTimeout?: number;
	timezone?: string;
}

/**
 * Workflow tag
 */
export interface WorkflowTag {
	id: string;
	name: string;
}

/**
 * Metadata extracted from a workflow
 */
export interface WorkflowMetadata {
	hasTriggers: boolean;
	triggerTypes: string[];
	nodeTypes: string[];
	usesCredentials: boolean;
	credentialTypes: string[];
}
