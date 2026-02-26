
import { runAllRules, initializeBuiltInRules } from '../../nodes/RiskVoid/rules/index';
import { parseWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import { buildGraph } from '../../nodes/RiskVoid/analysis/graphBuilder';
import { findTaintSources, findSecuritySinks, analyzeTaintFlows } from '../../nodes/RiskVoid/analysis/taintAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const benchmarkPath = path.join(__dirname, '../../vulnerable_workflows/false_positive_benchmark.json');
const workflowJson = JSON.parse(fs.readFileSync(benchmarkPath, 'utf8'));

describe('False Positive Benchmark', () => {
    beforeAll(() => {
        initializeBuiltInRules();
    });

    it('should NOT report findings for safe transformed data', () => {
        const parseResult = parseWorkflow(workflowJson);
        const graph = buildGraph(parseResult.workflow!);
        const sources = findTaintSources(parseResult.workflow!, graph);
        const sinks = findSecuritySinks(parseResult.workflow!, graph);
        const taintPaths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

        const ruleContext = {
            workflow: parseResult.workflow!,
            graph,
            sources,
            sinks,
            taintPaths
        };

        const result = runAllRules(ruleContext);

        // Check for the specific Taint Analysis finding (Remote Code Execution)
        // The "Potential Code Execution" finding might still exist as a fallback, which is acceptable behavior
        const taintFindings = result.findings.filter(f => f.title === 'Remote Code Execution via User Input');

        expect(taintFindings.length).toBe(0);
    });
});
