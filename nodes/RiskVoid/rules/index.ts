/**
 * Detection Rules Registry and Orchestrator
 *
 * This module provides the central registry for all detection rules
 * and the orchestration logic for running them against workflows.
 */

import type {
	DetectionRule,
	RuleMetadata,
	Finding,
	RuleContext,
	RulesConfig,
	RunRulesOptions,
	RulesResult,
	RuleError,
	FindingCategory,
} from './types';
import { meetsSeverityThreshold, compareSeverity } from './types';

// Import all detection rules
import { CodeInjectionRule } from './codeInjection';
import { CommandInjectionRule } from './commandInjection';
import { SqlInjectionRule } from './sqlInjection';
import { SsrfRule } from './ssrf';
import { PromptInjectionRule } from './promptInjection';
import { CredentialExposureRule } from './credentialExposure';

/**
 * Registry of all detection rules
 */
const ruleRegistry: DetectionRule[] = [];

/**
 * Register a detection rule
 */
export function registerRule(rule: DetectionRule): void {
	// Prevent duplicate registration
	const existingIndex = ruleRegistry.findIndex((r) => r.metadata.id === rule.metadata.id);
	if (existingIndex >= 0) {
		ruleRegistry[existingIndex] = rule;
	} else {
		ruleRegistry.push(rule);
	}
}

/**
 * Unregister a detection rule by ID
 */
export function unregisterRule(ruleId: string): boolean {
	const index = ruleRegistry.findIndex((r) => r.metadata.id === ruleId);
	if (index >= 0) {
		ruleRegistry.splice(index, 1);
		return true;
	}
	return false;
}

/**
 * Get all registered rules
 */
export function getAllRules(): DetectionRule[] {
	return [...ruleRegistry];
}

/**
 * Get a specific rule by ID
 */
export function getRule(ruleId: string): DetectionRule | undefined {
	return ruleRegistry.find((r) => r.metadata.id === ruleId);
}

/**
 * Get metadata for all registered rules
 */
export function getAllRuleMetadata(): RuleMetadata[] {
	return ruleRegistry.map((r) => r.metadata);
}

/**
 * Get rules by category
 */
export function getRulesByCategory(category: FindingCategory): DetectionRule[] {
	return ruleRegistry.filter((r) => r.metadata.category === category);
}

/**
 * Get rules by tag
 */
export function getRulesByTag(tag: string): DetectionRule[] {
	return ruleRegistry.filter((r) => r.metadata.tags.includes(tag));
}

/**
 * Default rule configuration
 */
function getDefaultConfig(): RulesConfig {
	const config: RulesConfig = {};
	for (const rule of ruleRegistry) {
		config[rule.metadata.id] = { enabled: true };
	}
	return config;
}

/**
 * Merge user config with defaults
 */
function mergeConfig(userConfig: RulesConfig | undefined): RulesConfig {
	const defaults = getDefaultConfig();
	if (!userConfig) {
		return defaults;
	}

	const merged: RulesConfig = { ...defaults };
	for (const [ruleId, config] of Object.entries(userConfig)) {
		if (merged[ruleId]) {
			merged[ruleId] = { ...merged[ruleId], ...config };
		} else {
			merged[ruleId] = config;
		}
	}
	return merged;
}

/**
 * Check if a rule should be skipped based on options
 */
function shouldSkipRule(
	rule: DetectionRule,
	options: RunRulesOptions,
	config: RulesConfig,
): boolean {
	const ruleConfig = config[rule.metadata.id];

	// Skip if disabled
	if (ruleConfig && !ruleConfig.enabled) {
		return true;
	}

	// Skip if not in requested rule IDs
	if (options.ruleIds && options.ruleIds.length > 0) {
		if (!options.ruleIds.includes(rule.metadata.id)) {
			return true;
		}
	}

	// Skip if not in requested categories
	if (options.categories && options.categories.length > 0) {
		if (!options.categories.includes(rule.metadata.category)) {
			return true;
		}
	}

	return false;
}

/**
 * Apply severity override from config
 */
function applySeverityOverride(findings: Finding[], ruleId: string, config: RulesConfig): void {
	const ruleConfig = config[ruleId];
	if (ruleConfig?.severityOverride) {
		for (const finding of findings) {
			finding.severity = ruleConfig.severityOverride;
		}
	}
}

/**
 * Filter findings by minimum severity
 */
function filterBySeverity(findings: Finding[], options: RunRulesOptions): Finding[] {
	if (!options.minSeverity) {
		return findings;
	}

	return findings.filter((f) => meetsSeverityThreshold(f.severity, options.minSeverity!));
}

/**
 * Sort findings by severity (most severe first)
 */
function sortBySeverity(findings: Finding[]): Finding[] {
	return [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
}

/**
 * Deduplicate similar findings
 * Findings are considered similar if they have the same:
 * - rule ID
 * - source node
 * - sink node
 * - sink parameter
 */
function deduplicateFindings(findings: Finding[]): Finding[] {
	const seen = new Set<string>();
	const unique: Finding[] = [];

	for (const finding of findings) {
		const key = `${finding.ruleId}:${finding.source.node}:${finding.sink.node}:${finding.sink.parameter}`;

		if (!seen.has(key)) {
			seen.add(key);
			unique.push(finding);
		}
	}

	return unique;
}

/**
 * Run all applicable detection rules against a workflow
 *
 * @param context - The analysis context (workflow, graph, sources, sinks, taint paths)
 * @param options - Options for filtering and configuring rules
 * @returns Result containing all findings and execution metadata
 */
export function runAllRules(context: RuleContext, options: RunRulesOptions = {}): RulesResult {
	const startTime = Date.now();
	const config = mergeConfig(options.config);
	const allFindings: Finding[] = [];
	const errors: RuleError[] = [];
	let rulesRun = 0;
	let rulesSkipped = 0;

	for (const rule of ruleRegistry) {
		// Check if rule should be skipped
		if (shouldSkipRule(rule, options, config)) {
			rulesSkipped++;
			continue;
		}

		// Check if rule is applicable to this workflow
		try {
			if (!rule.isApplicable(context)) {
				rulesSkipped++;
				continue;
			}
		} catch (error) {
			errors.push({
				ruleId: rule.metadata.id,
				message: `Error checking applicability: ${error instanceof Error ? error.message : 'Unknown error'}`,
				stack: error instanceof Error ? error.stack : undefined,
			});
			rulesSkipped++;
			continue;
		}

		// Run the rule
		try {
			const ruleFindings = rule.detect(context);
			rulesRun++;

			// Apply severity override if configured
			applySeverityOverride(ruleFindings, rule.metadata.id, config);

			allFindings.push(...ruleFindings);
		} catch (error) {
			errors.push({
				ruleId: rule.metadata.id,
				message: `Error running rule: ${error instanceof Error ? error.message : 'Unknown error'}`,
				stack: error instanceof Error ? error.stack : undefined,
			});
		}
	}

	// Post-process findings
	let findings = deduplicateFindings(allFindings);
	findings = filterBySeverity(findings, options);
	findings = sortBySeverity(findings);

	const duration = Date.now() - startTime;

	return {
		findings,
		rulesRun,
		rulesSkipped,
		errors,
		duration,
	};
}

/**
 * Run a single rule against a workflow
 */
export function runRule(
	ruleId: string,
	context: RuleContext,
	config?: RulesConfig,
): Finding[] | null {
	const rule = getRule(ruleId);
	if (!rule) {
		return null;
	}

	const mergedConfig = mergeConfig(config);
	const ruleConfig = mergedConfig[ruleId];

	if (ruleConfig && !ruleConfig.enabled) {
		return [];
	}

	if (!rule.isApplicable(context)) {
		return [];
	}

	const findings = rule.detect(context);
	applySeverityOverride(findings, ruleId, mergedConfig);

	return findings;
}

/**
 * Initialize built-in rules
 * Call this once at startup to register all built-in rules
 */
export function initializeBuiltInRules(): void {
	registerRule(new CodeInjectionRule());
	registerRule(new CommandInjectionRule());
	registerRule(new SqlInjectionRule());
	registerRule(new SsrfRule());
	registerRule(new PromptInjectionRule());
	registerRule(new CredentialExposureRule());
}

// Export rule classes for direct use
export { CodeInjectionRule } from './codeInjection';
export { CommandInjectionRule } from './commandInjection';
export { SqlInjectionRule } from './sqlInjection';
export { SsrfRule } from './ssrf';
export { PromptInjectionRule } from './promptInjection';
export { CredentialExposureRule } from './credentialExposure';

/**
 * Clear all registered rules (useful for testing)
 */
export function clearAllRules(): void {
	ruleRegistry.length = 0;
}

// Re-export types
export * from './types';
