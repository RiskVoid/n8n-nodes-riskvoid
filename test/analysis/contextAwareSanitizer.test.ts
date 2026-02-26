
import { buildGraph } from '../../nodes/RiskVoid/analysis/graphBuilder';
import { findSecuritySinks, findTaintSources, analyzeTaintFlows } from '../../nodes/RiskVoid/analysis/taintAnalyzer';
import { parseWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';


// Mock classification to simulate specific sanitizer capabilities
jest.mock('../../nodes/RiskVoid/analysis/nodeClassifier', () => {
    const original = jest.requireActual('../../nodes/RiskVoid/analysis/nodeClassifier');
    return {
        ...original,
        classifyNode: (node: any) => {
            if (node.name === 'SQL Sanitizer') {
                return {
                    role: 'sanitizer',
                    sanitizerType: 'validation',
                    validatesAgainst: ['SQL Injection'], // Only sanitizes SQLi
                    description: 'Sanitizes SQL',
                };
            }
            if (node.name === 'XSS Sanitizer') {
                return {
                    role: 'sanitizer',
                    sanitizerType: 'validation',
                    validatesAgainst: ['XSS'], // Only sanitizes XSS
                    description: 'Sanitizes XSS',
                };
            }
            return original.classifyNode(node);
        },
    };
});

describe('Context-Aware Sanitizer Logic', () => {
    // Workflow with SQL Injection sink and various sanitizers
    const workflow = {
        nodes: [
            {
                id: '1',
                name: 'Webhook',
                type: 'n8n-nodes-base.webhook',
                typeVersion: 1,
                position: [100, 300],
            },
            {
                id: '2',
                name: 'SQL Sanitizer',
                type: 'n8n-nodes-base.function', // Mocked as sanitizer
                typeVersion: 1,
                position: [300, 300],
            },
            {
                id: '3',
                name: 'XSS Sanitizer',
                type: 'n8n-nodes-base.function', // Mocked as sanitizer
                typeVersion: 1,
                position: [500, 300],
            },
            {
                id: '4',
                name: 'MySQL',
                type: 'n8n-nodes-base.mySql',
                typeVersion: 1,
                position: [700, 300],
                parameters: {
                    operation: 'executeQuery',
                    query: 'SELECT * FROM users WHERE name = {{ $json.body.name }}',
                },
            },
        ],
        connections: {
            Webhook: {
                main: [[{ node: 'SQL Sanitizer', type: 'main', index: 0 }]],
            },
            'SQL Sanitizer': { // SQL Sanitizer -> MySQL (Should be Safe)
                main: [[{ node: 'MySQL', type: 'main', index: 0 }]],
            },
        },
    };

    it('should sanitize SQL Injection when SQL Sanitizer is used', () => {
        const parseResult = parseWorkflow(workflow);
        const graph = buildGraph(parseResult.workflow!);
        const sources = findTaintSources(parseResult.workflow!, graph);
        const sinks = findSecuritySinks(parseResult.workflow!, graph);

        // Path: Webhook -> SQL Sanitizer -> MySQL
        const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

        expect(paths.length).toBeGreaterThan(0);
        // Should be marked as sanitized because SQL Sanitizer covers SQL Injection risk
        expect(paths[0].sanitized).toBe(true);
        expect(paths[0].severity).not.toBe('high'); // Should be reduced
    });

    it('should NOT sanitize SQL Injection when XSS Sanitizer is used', () => {
        // Rewire: Webhook -> XSS Sanitizer -> MySQL
        const xssWorkflow = JSON.parse(JSON.stringify(workflow));
        xssWorkflow.connections = {
            Webhook: {
                main: [[{ node: 'XSS Sanitizer', type: 'main', index: 0 }]],
            },
            'XSS Sanitizer': {
                main: [[{ node: 'MySQL', type: 'main', index: 0 }]],
            }
        };

        const parseResult = parseWorkflow(xssWorkflow);
        const graph = buildGraph(parseResult.workflow!);
        const sources = findTaintSources(parseResult.workflow!, graph);
        const sinks = findSecuritySinks(parseResult.workflow!, graph);

        // Path: Webhook -> XSS Sanitizer -> MySQL
        const paths = analyzeTaintFlows(parseResult.workflow!, graph, sources, sinks);

        expect(paths.length).toBeGreaterThan(0);
        // Should NOT be sanitized because XSS Sanitizer does NOT cover SQL Injection
        expect(paths[0].sanitized).toBe(false);
        expect(paths[0].severity).toBe('high'); // Critical/High severity retained
    });
});
