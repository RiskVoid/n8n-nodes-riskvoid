import {
	parseExpressions,
	resolveReferenceSource,
	hasExpressions,
	getReferencedNodeNames,
} from '../../nodes/RiskVoid/analysis/expressionTracer';
import type { ExpressionReference } from '../../nodes/RiskVoid/analysis/expressionTracer';

describe('expressionTracer', () => {
	describe('parseExpressions', () => {
		describe('$json references', () => {
			it('should parse simple $json.field reference', () => {
				const result = parseExpressions('{{ $json.userName }}');

				expect(result.hasExpressions).toBe(true);
				expect(result.references).toHaveLength(1);
				expect(result.references[0].type).toBe('json');
				expect(result.references[0].fieldPath).toEqual(['userName']);
				expect(result.references[0].isImplicit).toBe(true);
			});

			it('should parse nested field paths', () => {
				const result = parseExpressions('{{ $json.data.user.profile.name }}');

				expect(result.references).toHaveLength(1);
				expect(result.references[0].fieldPath).toEqual(['data', 'user', 'profile', 'name']);
			});

			it('should parse bracket notation', () => {
				const result = parseExpressions("{{ $json['field-with-dash'] }}");

				expect(result.references).toHaveLength(1);
				expect(result.references[0].fieldPath).toEqual(['field-with-dash']);
			});

			it('should parse mixed dot and bracket notation', () => {
				const result = parseExpressions("{{ $json.data['field-name'].value }}");

				expect(result.references).toHaveLength(1);
				expect(result.references[0].fieldPath).toEqual(['data', 'field-name', 'value']);
			});

			it('should parse array index access', () => {
				const result = parseExpressions('{{ $json.items[0].name }}');

				expect(result.references).toHaveLength(1);
				expect(result.references[0].fieldPath).toEqual(['items', '0', 'name']);
			});

			it('should parse standalone $json', () => {
				const result = parseExpressions('{{ $json }}');

				expect(result.hasExpressions).toBe(true);
				expect(result.references).toHaveLength(1);
				expect(result.references[0].type).toBe('json');
				expect(result.references[0].fieldPath).toEqual([]);
			});
		});

		describe('explicit node references', () => {
			it('should parse $("NodeName").item.json.field', () => {
				const result = parseExpressions("{{ $('Webhook').item.json.body.command }}");

				expect(result.references).toHaveLength(1);
				expect(result.references[0].type).toBe('node');
				expect(result.references[0].nodeName).toBe('Webhook');
				expect(result.references[0].fieldPath).toEqual(['body', 'command']);
				expect(result.references[0].isImplicit).toBe(false);
			});

			it('should parse $("NodeName").first().json.field', () => {
				const result = parseExpressions("{{ $('Set Data').first().json.value }}");

				expect(result.references).toHaveLength(1);
				expect(result.references[0].nodeName).toBe('Set Data');
				expect(result.references[0].fieldPath).toEqual(['value']);
			});

			it('should parse node reference with double quotes', () => {
				const result = parseExpressions('{{ $("Webhook").item.json.body }}');

				expect(result.references).toHaveLength(1);
				expect(result.references[0].nodeName).toBe('Webhook');
			});
		});

		describe('$input references', () => {
			it('should parse $input.first().json.field', () => {
				const result = parseExpressions('{{ $input.first().json.message }}');

				expect(result.references).toHaveLength(1);
				expect(result.references[0].type).toBe('input');
				expect(result.references[0].fieldPath).toEqual(['message']);
				expect(result.references[0].isImplicit).toBe(true);
			});

			it('should parse $input.item.json.field', () => {
				const result = parseExpressions('{{ $input.item.json.data }}');

				expect(result.references).toHaveLength(1);
				expect(result.references[0].type).toBe('input');
				expect(result.references[0].fieldPath).toEqual(['data']);
			});
		});

		describe('$env references', () => {
			it('should parse $env.VAR_NAME', () => {
				const result = parseExpressions('{{ $env.API_KEY }}');

				expect(result.references).toHaveLength(1);
				expect(result.references[0].type).toBe('env');
				expect(result.references[0].fieldPath).toEqual(['API_KEY']);
				expect(result.references[0].isImplicit).toBe(false);
			});
		});

		describe('$workflow references', () => {
			it('should parse $workflow.id', () => {
				const result = parseExpressions('{{ $workflow.id }}');

				expect(result.references).toHaveLength(1);
				expect(result.references[0].type).toBe('workflow');
				expect(result.references[0].fieldPath).toEqual(['id']);
			});
		});

		describe('$execution references', () => {
			it('should parse $execution.id', () => {
				const result = parseExpressions('{{ $execution.id }}');

				expect(result.references).toHaveLength(1);
				expect(result.references[0].type).toBe('execution');
				expect(result.references[0].fieldPath).toEqual(['id']);
			});
		});

		describe('multiple expressions', () => {
			it('should parse multiple expressions in one string', () => {
				const result = parseExpressions('Hello {{ $json.name }}, your ID is {{ $json.id }}');

				expect(result.hasExpressions).toBe(true);
				expect(result.references).toHaveLength(2);
				expect(result.references[0].fieldPath).toEqual(['name']);
				expect(result.references[1].fieldPath).toEqual(['id']);
			});

			it('should parse mixed expression types', () => {
				const result = parseExpressions(
					"{{ $json.data }} and {{ $('Node').item.json.value }}",
				);

				expect(result.references).toHaveLength(2);
				expect(result.references[0].type).toBe('json');
				expect(result.references[1].type).toBe('node');
			});
		});

		describe('expressions in objects', () => {
			it('should parse expressions in object values', () => {
				const result = parseExpressions({
					url: 'https://api.example.com/{{ $json.endpoint }}',
					headers: {
						Authorization: 'Bearer {{ $json.token }}',
					},
				});

				expect(result.hasExpressions).toBe(true);
				expect(result.references).toHaveLength(2);
			});

			it('should parse expressions in arrays', () => {
				const result = parseExpressions({
					items: ['{{ $json.first }}', '{{ $json.second }}'],
				});

				expect(result.references).toHaveLength(2);
			});

			it('should parse deeply nested expressions', () => {
				const result = parseExpressions({
					level1: {
						level2: {
							level3: '{{ $json.deep }}',
						},
					},
				});

				expect(result.references).toHaveLength(1);
				expect(result.references[0].fieldPath).toEqual(['deep']);
			});
		});

		describe('edge cases', () => {
			it('should return no expressions for static values', () => {
				const result = parseExpressions('Hello World');

				expect(result.hasExpressions).toBe(false);
				expect(result.references).toHaveLength(0);
			});

			it('should handle null input', () => {
				const result = parseExpressions(null);

				expect(result.hasExpressions).toBe(false);
				expect(result.references).toHaveLength(0);
			});

			it('should handle undefined input', () => {
				const result = parseExpressions(undefined);

				expect(result.hasExpressions).toBe(false);
				expect(result.references).toHaveLength(0);
			});

			it('should handle empty string', () => {
				const result = parseExpressions('');

				expect(result.hasExpressions).toBe(false);
				expect(result.references).toHaveLength(0);
			});

			it('should handle empty object', () => {
				const result = parseExpressions({});

				expect(result.hasExpressions).toBe(false);
				expect(result.references).toHaveLength(0);
			});

			it('should handle expressions with whitespace', () => {
				const result = parseExpressions('{{   $json.field   }}');

				expect(result.hasExpressions).toBe(true);
				expect(result.references).toHaveLength(1);
			});
		});
	});

	describe('resolveReferenceSource', () => {
		it('should resolve explicit node reference', () => {
			const ref: ExpressionReference = {
				type: 'node',
				nodeName: 'Webhook',
				fieldPath: ['body'],
				raw: "$('Webhook').item.json.body",
				isImplicit: false,
			};

			const source = resolveReferenceSource(ref, 'Code', ['Set', 'Filter']);
			expect(source).toBe('Webhook');
		});

		it('should resolve implicit reference to first predecessor', () => {
			const ref: ExpressionReference = {
				type: 'json',
				fieldPath: ['userName'],
				raw: '$json.userName',
				isImplicit: true,
			};

			const source = resolveReferenceSource(ref, 'Code', ['Webhook']);
			expect(source).toBe('Webhook');
		});

		it('should resolve implicit $input reference to first predecessor', () => {
			const ref: ExpressionReference = {
				type: 'input',
				fieldPath: ['data'],
				raw: '$input.first().json.data',
				isImplicit: true,
			};

			const source = resolveReferenceSource(ref, 'Code', ['Set', 'Webhook']);
			expect(source).toBe('Set');
		});

		it('should return null for $env reference', () => {
			const ref: ExpressionReference = {
				type: 'env',
				fieldPath: ['API_KEY'],
				raw: '$env.API_KEY',
				isImplicit: false,
			};

			const source = resolveReferenceSource(ref, 'Code', ['Webhook']);
			expect(source).toBeNull();
		});

		it('should return null for $workflow reference', () => {
			const ref: ExpressionReference = {
				type: 'workflow',
				fieldPath: ['id'],
				raw: '$workflow.id',
				isImplicit: false,
			};

			const source = resolveReferenceSource(ref, 'Code', ['Webhook']);
			expect(source).toBeNull();
		});

		it('should return null for implicit reference with no predecessors', () => {
			const ref: ExpressionReference = {
				type: 'json',
				fieldPath: ['data'],
				raw: '$json.data',
				isImplicit: true,
			};

			const source = resolveReferenceSource(ref, 'Code', []);
			expect(source).toBeNull();
		});
	});

	describe('hasExpressions', () => {
		it('should return true for string with expressions', () => {
			expect(hasExpressions('{{ $json.field }}')).toBe(true);
		});

		it('should return false for string without expressions', () => {
			expect(hasExpressions('static value')).toBe(false);
		});

		it('should return true for object with expressions', () => {
			expect(hasExpressions({ key: '{{ $json.value }}' })).toBe(true);
		});

		it('should return false for null', () => {
			expect(hasExpressions(null)).toBe(false);
		});

		it('should return false for number', () => {
			expect(hasExpressions(42)).toBe(false);
		});
	});

	describe('getReferencedNodeNames', () => {
		it('should extract unique node names from references', () => {
			const refs: ExpressionReference[] = [
				{ type: 'node', nodeName: 'Webhook', fieldPath: ['body'], raw: '', isImplicit: false },
				{ type: 'node', nodeName: 'Set', fieldPath: ['data'], raw: '', isImplicit: false },
				{ type: 'node', nodeName: 'Webhook', fieldPath: ['headers'], raw: '', isImplicit: false },
			];

			const nodeNames = getReferencedNodeNames(refs);

			expect(nodeNames).toHaveLength(2);
			expect(nodeNames).toContain('Webhook');
			expect(nodeNames).toContain('Set');
		});

		it('should return empty array for non-node references', () => {
			const refs: ExpressionReference[] = [
				{ type: 'json', fieldPath: ['data'], raw: '', isImplicit: true },
				{ type: 'env', fieldPath: ['VAR'], raw: '', isImplicit: false },
			];

			const nodeNames = getReferencedNodeNames(refs);
			expect(nodeNames).toHaveLength(0);
		});
	});
});
