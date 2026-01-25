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
const SOURCE_NODES: Record<string, Omit<SourceClassification, 'role'>> = {
	// Webhooks and triggers
	'n8n-nodes-base.webhook': {
		trustLevel: 'untrusted',
		taintedFields: ['body', 'headers', 'query', 'params'],
		description: 'HTTP webhook receives external input',
	},
	'n8n-nodes-base.formTrigger': {
		trustLevel: 'untrusted',
		taintedFields: ['*'],
		description: 'Form trigger receives user-submitted data',
	},
	'n8n-nodes-base.manualTrigger': {
		trustLevel: 'trusted',
		taintedFields: [],
		description: 'Manual trigger (user-initiated)',
	},
	'n8n-nodes-base.scheduleTrigger': {
		trustLevel: 'trusted',
		taintedFields: [],
		description: 'Schedule trigger (time-based)',
	},

	// Email
	'n8n-nodes-base.emailReadImap': {
		trustLevel: 'untrusted',
		taintedFields: ['subject', 'text', 'html', 'from', 'to', 'attachments'],
		description: 'Email content from external senders',
	},
	'n8n-nodes-base.emailTrigger': {
		trustLevel: 'untrusted',
		taintedFields: ['subject', 'text', 'html', 'from', 'to', 'attachments'],
		description: 'Email trigger receives external email',
	},
	'n8n-nodes-base.gmail': {
		trustLevel: 'untrusted',
		taintedFields: ['subject', 'body', 'from', 'to', 'attachments'],
		description: 'Gmail messages from external senders',
	},

	// Messaging platforms
	'n8n-nodes-base.slack': {
		trustLevel: 'untrusted',
		taintedFields: ['text', 'user', 'channel', 'message'],
		description: 'Slack messages from users',
	},
	'n8n-nodes-base.slackTrigger': {
		trustLevel: 'untrusted',
		taintedFields: ['text', 'user', 'channel', 'message'],
		description: 'Slack trigger receives user messages',
	},
	'n8n-nodes-base.telegram': {
		trustLevel: 'untrusted',
		taintedFields: ['message.text', 'message.from', 'message.chat'],
		description: 'Telegram messages from users',
	},
	'n8n-nodes-base.telegramTrigger': {
		trustLevel: 'untrusted',
		taintedFields: ['message.text', 'message.from', 'message.chat'],
		description: 'Telegram trigger receives user messages',
	},
	'n8n-nodes-base.discord': {
		trustLevel: 'untrusted',
		taintedFields: ['content', 'author', 'channel'],
		description: 'Discord messages from users',
	},
	'n8n-nodes-base.discordTrigger': {
		trustLevel: 'untrusted',
		taintedFields: ['content', 'author', 'channel'],
		description: 'Discord trigger receives user messages',
	},

	// External data sources
	'n8n-nodes-base.rssFeedRead': {
		trustLevel: 'semi-trusted',
		taintedFields: ['title', 'content', 'link', 'description'],
		description: 'RSS feed content from external sources',
	},
	'n8n-nodes-base.httpRequest': {
		trustLevel: 'semi-trusted',
		taintedFields: ['body', 'headers'],
		description: 'HTTP response from external API',
	},

	// CRM and business tools
	'n8n-nodes-base.hubspotTrigger': {
		trustLevel: 'semi-trusted',
		taintedFields: ['*'],
		description: 'HubSpot webhook data',
	},
	'n8n-nodes-base.stripeTrigger': {
		trustLevel: 'semi-trusted',
		taintedFields: ['*'],
		description: 'Stripe webhook data',
	},
	'n8n-nodes-base.githubTrigger': {
		trustLevel: 'semi-trusted',
		taintedFields: ['*'],
		description: 'GitHub webhook data',
	},
};

/**
 * Registry of sink nodes (nodes that perform dangerous operations)
 */
const SINK_NODES: Record<string, Omit<SinkClassification, 'role'>> = {
	// Code execution (Critical)
	'n8n-nodes-base.code': {
		severity: 'critical',
		riskType: 'RCE',
		dangerousParams: ['jsCode', 'pythonCode'],
		description: 'Executes arbitrary code',
	},
	'n8n-nodes-base.executeCommand': {
		severity: 'critical',
		riskType: 'Command Injection',
		dangerousParams: ['command'],
		description: 'Executes system commands',
	},
	'n8n-nodes-base.ssh': {
		severity: 'critical',
		riskType: 'RCE',
		dangerousParams: ['command'],
		description: 'Executes commands via SSH',
	},
	'n8n-nodes-base.function': {
		severity: 'critical',
		riskType: 'RCE',
		dangerousParams: ['functionCode'],
		description: 'Executes JavaScript function',
	},
	'n8n-nodes-base.functionItem': {
		severity: 'critical',
		riskType: 'RCE',
		dangerousParams: ['functionCode'],
		description: 'Executes JavaScript per item',
	},

	// Database queries (High)
	'n8n-nodes-base.mySql': {
		severity: 'high',
		riskType: 'SQL Injection',
		dangerousParams: ['query'],
		description: 'Executes MySQL queries',
	},
	'n8n-nodes-base.postgres': {
		severity: 'high',
		riskType: 'SQL Injection',
		dangerousParams: ['query'],
		description: 'Executes PostgreSQL queries',
	},
	'n8n-nodes-base.microsoftSql': {
		severity: 'high',
		riskType: 'SQL Injection',
		dangerousParams: ['query'],
		description: 'Executes Microsoft SQL queries',
	},
	'n8n-nodes-base.mongoDb': {
		severity: 'high',
		riskType: 'NoSQL Injection',
		dangerousParams: ['query', 'options.query'],
		description: 'Executes MongoDB queries',
	},

	// Network requests (High - SSRF)
	'n8n-nodes-base.httpRequest': {
		severity: 'high',
		riskType: 'SSRF',
		dangerousParams: ['url'],
		description: 'Makes HTTP requests to specified URL',
	},

	// File system (Medium)
	'n8n-nodes-base.readWriteFile': {
		severity: 'medium',
		riskType: 'Path Traversal',
		dangerousParams: ['filePath', 'fileName'],
		description: 'Reads/writes files on the server',
	},
	'n8n-nodes-base.ftp': {
		severity: 'medium',
		riskType: 'Path Traversal',
		dangerousParams: ['path'],
		description: 'FTP file operations',
	},

	// LLM/AI (Medium - Prompt Injection)
	'@n8n/n8n-nodes-langchain.openAi': {
		severity: 'medium',
		riskType: 'Prompt Injection',
		dangerousParams: ['text', 'messages', 'prompt'],
		description: 'OpenAI API calls',
	},
	'@n8n/n8n-nodes-langchain.lmChatOpenAi': {
		severity: 'medium',
		riskType: 'Prompt Injection',
		dangerousParams: ['messages', 'prompt'],
		description: 'OpenAI Chat API calls',
	},
	'@n8n/n8n-nodes-langchain.lmChatAnthropic': {
		severity: 'medium',
		riskType: 'Prompt Injection',
		dangerousParams: ['messages', 'prompt'],
		description: 'Anthropic Claude API calls',
	},
	'@n8n/n8n-nodes-langchain.agent': {
		severity: 'medium',
		riskType: 'Prompt Injection',
		dangerousParams: ['text', 'input'],
		description: 'LangChain agent with tools',
	},

	// HTML/Template rendering (Medium - XSS)
	'n8n-nodes-base.html': {
		severity: 'medium',
		riskType: 'XSS',
		dangerousParams: ['html'],
		description: 'Renders HTML content',
	},
	'n8n-nodes-base.respondToWebhook': {
		severity: 'medium',
		riskType: 'XSS',
		dangerousParams: ['respondWith', 'responseBody'],
		description: 'Responds to webhook with content',
	},
};

/**
 * Registry of sanitizer nodes (nodes that can reduce taint)
 */
const SANITIZER_NODES: Record<string, Omit<SanitizerClassification, 'role'>> = {
	'n8n-nodes-base.if': {
		sanitizerType: 'conditional',
		description: 'Conditional branching can filter invalid input',
	},
	'n8n-nodes-base.switch': {
		sanitizerType: 'conditional',
		description: 'Switch routing can filter unexpected values',
	},
	'n8n-nodes-base.filter': {
		sanitizerType: 'validation',
		description: 'Filters items based on conditions',
	},
	'n8n-nodes-base.itemLists': {
		sanitizerType: 'transformation',
		description: 'List operations may transform data',
	},
};

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
