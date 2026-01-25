/**
 * Expression Tracer - Parses and traces n8n expressions
 *
 * Handles expressions like:
 * - {{ $json.field }}
 * - {{ $('NodeName').item.json.field }}
 * - {{ $input.first().json.field }}
 * - {{ $env.VAR_NAME }}
 */

/**
 * Represents a reference found in an expression
 */
export interface ExpressionReference {
	type: 'json' | 'node' | 'input' | 'env' | 'workflow' | 'execution' | 'unknown';
	nodeName?: string; // For explicit node references
	fieldPath: string[]; // Path to the field (e.g., ['data', 'user', 'name'])
	raw: string; // Original expression text
	isImplicit: boolean; // Whether it references previous node implicitly
}

/**
 * Result of parsing a parameter value for expressions
 */
export interface ExpressionParseResult {
	hasExpressions: boolean;
	references: ExpressionReference[];
	rawValue: string;
	errors: string[];
}

/**
 * Regex patterns for different expression types
 */
const EXPRESSION_PATTERNS = {
	// Full expression wrapper: {{ ... }}
	wrapper: /\{\{\s*([^}]+?)\s*\}\}/g,

	// $json with path - handles both dot and bracket notation
	// Match $json followed by accessor chain
	jsonPath: /\$json((?:\.[a-zA-Z_][a-zA-Z0-9_]*|\[['"][^'"]+['"]\]|\[\d+\])+)/g,

	// Standalone $json (entire output)
	jsonStandalone: /\$json(?![[.])/g,

	// $('NodeName').item.json.field or $('NodeName').first().json.field
	nodeReference:
		/\$\(['"]([^'"]+)['"]\)(?:\.item|\.first\(\)|\.last\(\)|\.all\(\)\[\d+\])?\.json((?:\.[a-zA-Z_][a-zA-Z0-9_]*|\[['"][^'"]+['"]\]|\[\d+\])*)/g,

	// $input.first().json.field or $input.item.json.field
	inputReference:
		/\$input(?:\.first\(\)|\.last\(\)|\.item|\.all\(\)\[\d+\])?\.json((?:\.[a-zA-Z_][a-zA-Z0-9_]*|\[['"][^'"]+['"]\]|\[\d+\])*)/g,

	// $env.VAR_NAME
	envReference: /\$env\.([a-zA-Z_][a-zA-Z0-9_]*)/g,

	// $workflow.id, $workflow.name
	workflowReference: /\$workflow\.([a-zA-Z_][a-zA-Z0-9_]*)/g,

	// $execution.id
	executionReference: /\$execution\.([a-zA-Z_][a-zA-Z0-9_]*)/g,
};

/**
 * Parse a parameter value and extract all expression references
 */
export function parseExpressions(value: unknown): ExpressionParseResult {
	const result: ExpressionParseResult = {
		hasExpressions: false,
		references: [],
		rawValue: '',
		errors: [],
	};

	// Handle different value types
	if (value === null || value === undefined) {
		return result;
	}

	if (typeof value === 'string') {
		result.rawValue = value;
		return parseStringExpressions(value, result);
	}

	if (typeof value === 'object') {
		// Recursively parse object values
		result.rawValue = JSON.stringify(value);
		return parseObjectExpressions(value as Record<string, unknown>, result);
	}

	return result;
}

/**
 * Parse expressions from a string value
 */
function parseStringExpressions(
	value: string,
	result: ExpressionParseResult,
): ExpressionParseResult {
	// Find all {{ }} wrappers (template expressions)
	const wrapperRegex = new RegExp(EXPRESSION_PATTERNS.wrapper.source, 'g');
	let match;

	while ((match = wrapperRegex.exec(value)) !== null) {
		result.hasExpressions = true;
		const expressionContent = match[1].trim();

		// Try to parse the expression content
		const refs = parseExpressionContent(expressionContent);
		result.references.push(...refs);
	}

	// Also scan for raw JavaScript n8n API calls (used in Code nodes)
	// This catches patterns like $input.first().json.field without {{ }} wrappers
	const rawRefs = parseExpressionContent(value);
	if (rawRefs.length > 0) {
		result.hasExpressions = true;
		// Deduplicate by raw value
		const existingRaws = new Set(result.references.map(r => r.raw));
		for (const ref of rawRefs) {
			if (!existingRaws.has(ref.raw)) {
				result.references.push(ref);
				existingRaws.add(ref.raw);
			}
		}
	}

	return result;
}

/**
 * Parse the content inside {{ }}
 */
function parseExpressionContent(content: string): ExpressionReference[] {
	const references: ExpressionReference[] = [];
	const seenRaws = new Set<string>();

	// Check for explicit node references $('NodeName') first (most specific)
	const nodeRegex = new RegExp(EXPRESSION_PATTERNS.nodeReference.source, 'g');
	let match;

	while ((match = nodeRegex.exec(content)) !== null) {
		const nodeName = match[1];
		const pathStr = match[2] || '';
		const fieldPath = parseFieldPath(pathStr);

		if (!seenRaws.has(match[0])) {
			seenRaws.add(match[0]);
			references.push({
				type: 'node',
				nodeName,
				fieldPath,
				raw: match[0],
				isImplicit: false,
			});
		}
	}

	// Check for $input references
	const inputRegex = new RegExp(EXPRESSION_PATTERNS.inputReference.source, 'g');

	while ((match = inputRegex.exec(content)) !== null) {
		const pathStr = match[1] || '';
		const fieldPath = parseFieldPath(pathStr);

		if (!seenRaws.has(match[0])) {
			seenRaws.add(match[0]);
			references.push({
				type: 'input',
				fieldPath,
				raw: match[0],
				isImplicit: true,
			});
		}
	}

	// Check for $json references (implicit previous node)
	const jsonRegex = new RegExp(EXPRESSION_PATTERNS.jsonPath.source, 'g');

	while ((match = jsonRegex.exec(content)) !== null) {
		const pathStr = match[1];
		const fieldPath = parseFieldPath(pathStr);

		if (!seenRaws.has(match[0])) {
			seenRaws.add(match[0]);
			references.push({
				type: 'json',
				fieldPath,
				raw: match[0],
				isImplicit: true,
			});
		}
	}

	// Check for standalone $json
	const standaloneRegex = new RegExp(EXPRESSION_PATTERNS.jsonStandalone.source, 'g');

	while ((match = standaloneRegex.exec(content)) !== null) {
		if (!seenRaws.has(match[0])) {
			seenRaws.add(match[0]);
			references.push({
				type: 'json',
				fieldPath: [], // Entire JSON object
				raw: match[0],
				isImplicit: true,
			});
		}
	}

	// Check for $env references
	const envRegex = new RegExp(EXPRESSION_PATTERNS.envReference.source, 'g');

	while ((match = envRegex.exec(content)) !== null) {
		if (!seenRaws.has(match[0])) {
			seenRaws.add(match[0]);
			references.push({
				type: 'env',
				fieldPath: [match[1]],
				raw: match[0],
				isImplicit: false,
			});
		}
	}

	// Check for $workflow references
	const workflowRegex = new RegExp(EXPRESSION_PATTERNS.workflowReference.source, 'g');

	while ((match = workflowRegex.exec(content)) !== null) {
		if (!seenRaws.has(match[0])) {
			seenRaws.add(match[0]);
			references.push({
				type: 'workflow',
				fieldPath: [match[1]],
				raw: match[0],
				isImplicit: false,
			});
		}
	}

	// Check for $execution references
	const executionRegex = new RegExp(EXPRESSION_PATTERNS.executionReference.source, 'g');

	while ((match = executionRegex.exec(content)) !== null) {
		if (!seenRaws.has(match[0])) {
			seenRaws.add(match[0]);
			references.push({
				type: 'execution',
				fieldPath: [match[1]],
				raw: match[0],
				isImplicit: false,
			});
		}
	}

	return references;
}

/**
 * Parse a field path string into array of field names
 * ".data.user.name" → ["data", "user", "name"]
 * "['field-name'].subfield" → ["field-name", "subfield"]
 * "[0].field" → ["0", "field"]
 */
function parseFieldPath(pathStr: string): string[] {
	const fields: string[] = [];

	// Match .field, ['field'], ["field"], or [0] patterns
	const pathPattern = /\.([a-zA-Z_][a-zA-Z0-9_]*)|(?:\[['"]([^'"]+)['"]\])|\[(\d+)\]/g;

	let match;
	while ((match = pathPattern.exec(pathStr)) !== null) {
		const field = match[1] || match[2] || match[3];
		if (field !== undefined) {
			fields.push(field);
		}
	}

	return fields;
}

/**
 * Recursively parse expressions from an object
 */
function parseObjectExpressions(
	obj: Record<string, unknown>,
	result: ExpressionParseResult,
): ExpressionParseResult {
	for (const value of Object.values(obj)) {
		if (typeof value === 'string') {
			const strResult = parseStringExpressions(value, {
				hasExpressions: false,
				references: [],
				rawValue: value,
				errors: [],
			});

			if (strResult.hasExpressions) {
				result.hasExpressions = true;
				result.references.push(...strResult.references);
			}
		} else if (typeof value === 'object' && value !== null) {
			if (Array.isArray(value)) {
				for (const item of value) {
					if (typeof item === 'object' && item !== null) {
						parseObjectExpressions(item as Record<string, unknown>, result);
					} else if (typeof item === 'string') {
						const strResult = parseStringExpressions(item, {
							hasExpressions: false,
							references: [],
							rawValue: item,
							errors: [],
						});
						if (strResult.hasExpressions) {
							result.hasExpressions = true;
							result.references.push(...strResult.references);
						}
					}
				}
			} else {
				parseObjectExpressions(value as Record<string, unknown>, result);
			}
		}
	}

	return result;
}

/**
 * Resolve which node a reference points to
 * For implicit references ($json), this requires knowing the previous node in the graph
 */
export function resolveReferenceSource(
	reference: ExpressionReference,
	currentNodeName: string,
	predecessors: string[],
): string | null {
	// Explicit node reference
	if (reference.type === 'node' && reference.nodeName) {
		return reference.nodeName;
	}

	// Implicit reference ($json, $input) - refers to previous node
	if (reference.isImplicit && predecessors.length > 0) {
		// In n8n, $json typically refers to the first (or only) predecessor
		return predecessors[0];
	}

	// Environment or workflow references don't point to nodes
	if (
		reference.type === 'env' ||
		reference.type === 'workflow' ||
		reference.type === 'execution'
	) {
		return null;
	}

	return null;
}

/**
 * Check if a value contains any expressions
 */
export function hasExpressions(value: unknown): boolean {
	if (typeof value === 'string') {
		return /\{\{[^}]+\}\}/.test(value);
	}

	if (typeof value === 'object' && value !== null) {
		const str = JSON.stringify(value);
		return /\{\{[^}]+\}\}/.test(str);
	}

	return false;
}

/**
 * Get all unique node names referenced in expressions
 */
export function getReferencedNodeNames(references: ExpressionReference[]): string[] {
	const nodeNames = new Set<string>();

	for (const ref of references) {
		if (ref.type === 'node' && ref.nodeName) {
			nodeNames.add(ref.nodeName);
		}
	}

	return Array.from(nodeNames);
}
