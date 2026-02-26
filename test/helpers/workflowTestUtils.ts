import {
	analyzeWorkflow,
	parseWorkflow,
	buildGraph,
} from '../../nodes/RiskVoid/analysis';
import {
	findTaintSources,
	findSecuritySinks,
	analyzeTaintFlows,
} from '../../nodes/RiskVoid/analysis/taintAnalyzer';
import {
	initializeBuiltInRules,
	runAllRules,
	clearAllRules,
} from '../../nodes/RiskVoid/rules';
import type { RuleContext, Finding } from '../../nodes/RiskVoid/rules/types';
import type { N8nWorkflow } from '../../nodes/RiskVoid/types';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Load a workflow JSON file from the vulnerable_workflows directory.
 */
export function loadWorkflow(relativePath: string): N8nWorkflow {
	const fullPath = path.join(__dirname, '../../vulnerable_workflows', relativePath);
	const content = fs.readFileSync(fullPath, 'utf-8');
	return JSON.parse(content);
}

/**
 * Run full analysis pipeline on a workflow and return findings + duration.
 */
export function analyzeAndGetFindings(workflowJson: N8nWorkflow): {
	findings: Finding[];
	duration: number;
} {
	const startTime = Date.now();

	const analysisResult = analyzeWorkflow(workflowJson);
	expect(analysisResult.success).toBe(true);

	const parseResult = parseWorkflow(workflowJson);
	expect(parseResult.success).toBe(true);

	const graph = buildGraph(parseResult.workflow!);
	const sources = findTaintSources(parseResult.workflow!, graph);
	const sinks = findSecuritySinks(parseResult.workflow!, graph);
	const taintPaths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

	const ruleContext: RuleContext = {
		workflow: parseResult.workflow!,
		graph,
		sources,
		sinks,
		taintPaths,
	};

	const rulesResult = runAllRules(ruleContext);

	const duration = Date.now() - startTime;

	return {
		findings: rulesResult.findings,
		duration,
	};
}

/**
 * Run analysis pipeline with graceful error handling (used by audit).
 * Does not call expect() internally so callers can handle errors.
 */
export function scanWorkflow(workflowJson: N8nWorkflow): {
	findings: Finding[];
	duration: number;
} {
	const startTime = Date.now();

	const analysisResult = analyzeWorkflow(workflowJson);
	if (!analysisResult.success) {
		return { findings: [], duration: Date.now() - startTime };
	}

	const parseResult = parseWorkflow(workflowJson);
	if (!parseResult.success || !parseResult.workflow) {
		return { findings: [], duration: Date.now() - startTime };
	}

	const graph = buildGraph(parseResult.workflow);
	const sources = findTaintSources(parseResult.workflow, graph);
	const sinks = findSecuritySinks(parseResult.workflow, graph);
	const taintPaths = analyzeTaintFlows(parseResult.workflow, graph, sources, sinks);

	const ruleContext: RuleContext = {
		workflow: parseResult.workflow,
		graph,
		sources,
		sinks,
		taintPaths,
	};

	const rulesResult = runAllRules(ruleContext);
	return { findings: rulesResult.findings, duration: Date.now() - startTime };
}

/**
 * Assert properties of a single finding.
 */
export function assertFinding(
	finding: Finding,
	expectedRuleId: string,
	expectedSeverity: string,
	expectedConfidence: string,
	expectedNodesInPath?: string[],
) {
	expect(finding.ruleId).toBe(expectedRuleId);
	expect(finding.severity).toBe(expectedSeverity);
	expect(finding.confidence).toBe(expectedConfidence);

	if (expectedNodesInPath) {
		for (const nodeName of expectedNodesInPath) {
			const pathContainsNode = finding.path.some((node) => node.includes(nodeName));
			expect(pathContainsNode).toBe(true);
		}
	}
}

/**
 * Assert vulnerability detection with graceful fallback for unimplemented features.
 * Increments stats counters for tracking accuracy.
 */
export function assertVulnerabilityDetection(
	findings: Finding[],
	expectedRuleId: string,
	expectedSeverity: string,
	expectedConfidence: string,
	stats: {
		truePositives: number;
		trueNegatives: number;
		falsePositives: number;
		falseNegatives: number;
		totalDuration: number;
	},
	expectedNodesInPath?: string[],
): void {
	const finding = findings.find((f) => f.ruleId === expectedRuleId);
	if (finding) {
		expect(findings.length).toBeGreaterThanOrEqual(1);
		assertFinding(finding, expectedRuleId, expectedSeverity, expectedConfidence, expectedNodesInPath);
		stats.truePositives++;
	} else {
		stats.falseNegatives++;
	}
}

/**
 * Setup rules before tests. Call in beforeAll().
 */
export function setupRules() {
	clearAllRules();
	initializeBuiltInRules();
}

/**
 * Teardown rules after tests. Call in afterAll().
 */
export function teardownRules() {
	clearAllRules();
}
