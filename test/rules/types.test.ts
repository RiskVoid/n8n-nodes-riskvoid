/**
 * Tests for detection rule types and helper functions
 */

import {
	createFindingId,
	getEffectiveSeverity,
	compareSeverity,
	meetsSeverityThreshold,
	SEVERITY_ORDER,
	type FindingSeverity,
} from '../../nodes/RiskVoid/rules/types';

describe('rules/types', () => {
	describe('createFindingId', () => {
		it('should create unique IDs with rule prefix', () => {
			const id1 = createFindingId('RV-RCE-001');
			const id2 = createFindingId('RV-RCE-001');

			expect(id1).toMatch(/^RV-RCE-001-\d+-[a-z0-9]+$/);
			expect(id2).toMatch(/^RV-RCE-001-\d+-[a-z0-9]+$/);
			expect(id1).not.toBe(id2);
		});

		it('should work with different rule IDs', () => {
			const rceId = createFindingId('RV-RCE-001');
			const sqliId = createFindingId('RV-SQLI-001');

			expect(rceId).toContain('RV-RCE-001');
			expect(sqliId).toContain('RV-SQLI-001');
		});
	});

	describe('getEffectiveSeverity', () => {
		it('should return base severity when not sanitized', () => {
			expect(getEffectiveSeverity('critical', false)).toBe('critical');
			expect(getEffectiveSeverity('high', false)).toBe('high');
			expect(getEffectiveSeverity('medium', false)).toBe('medium');
			expect(getEffectiveSeverity('low', false)).toBe('low');
			expect(getEffectiveSeverity('info', false)).toBe('info');
		});

		it('should reduce severity by one level when sanitized', () => {
			expect(getEffectiveSeverity('critical', true)).toBe('high');
			expect(getEffectiveSeverity('high', true)).toBe('medium');
			expect(getEffectiveSeverity('medium', true)).toBe('low');
			expect(getEffectiveSeverity('low', true)).toBe('info');
		});

		it('should not reduce severity below info', () => {
			expect(getEffectiveSeverity('info', true)).toBe('info');
		});
	});

	describe('compareSeverity', () => {
		it('should return negative when first is more severe', () => {
			expect(compareSeverity('critical', 'high')).toBeLessThan(0);
			expect(compareSeverity('critical', 'medium')).toBeLessThan(0);
			expect(compareSeverity('high', 'low')).toBeLessThan(0);
			expect(compareSeverity('medium', 'info')).toBeLessThan(0);
		});

		it('should return positive when second is more severe', () => {
			expect(compareSeverity('high', 'critical')).toBeGreaterThan(0);
			expect(compareSeverity('low', 'high')).toBeGreaterThan(0);
			expect(compareSeverity('info', 'medium')).toBeGreaterThan(0);
		});

		it('should return 0 when severities are equal', () => {
			expect(compareSeverity('critical', 'critical')).toBe(0);
			expect(compareSeverity('high', 'high')).toBe(0);
			expect(compareSeverity('info', 'info')).toBe(0);
		});
	});

	describe('meetsSeverityThreshold', () => {
		it('should return true when severity meets threshold', () => {
			expect(meetsSeverityThreshold('critical', 'critical')).toBe(true);
			expect(meetsSeverityThreshold('critical', 'high')).toBe(true);
			expect(meetsSeverityThreshold('critical', 'info')).toBe(true);
			expect(meetsSeverityThreshold('high', 'high')).toBe(true);
			expect(meetsSeverityThreshold('high', 'low')).toBe(true);
		});

		it('should return false when severity does not meet threshold', () => {
			expect(meetsSeverityThreshold('high', 'critical')).toBe(false);
			expect(meetsSeverityThreshold('medium', 'high')).toBe(false);
			expect(meetsSeverityThreshold('info', 'low')).toBe(false);
		});
	});

	describe('SEVERITY_ORDER', () => {
		it('should have correct ordering', () => {
			const severities: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

			for (let i = 0; i < severities.length - 1; i++) {
				expect(SEVERITY_ORDER[severities[i]]).toBeLessThan(SEVERITY_ORDER[severities[i + 1]]);
			}
		});

		it('should include all severity levels', () => {
			expect(SEVERITY_ORDER).toHaveProperty('critical');
			expect(SEVERITY_ORDER).toHaveProperty('high');
			expect(SEVERITY_ORDER).toHaveProperty('medium');
			expect(SEVERITY_ORDER).toHaveProperty('low');
			expect(SEVERITY_ORDER).toHaveProperty('info');
		});
	});
});
