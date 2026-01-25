import {
	buildGraph,
	getReachableNodes,
	findAllPaths,
	getShortestPath,
} from '../../nodes/RiskVoid/analysis/graphBuilder';
import { parseWorkflow } from '../../nodes/RiskVoid/analysis/workflowParser';
import {
	simpleLinearWorkflow,
	branchingWorkflow,
	cyclicWorkflow,
	disconnectedWorkflow,
} from '../fixtures/workflows';

describe('graphBuilder', () => {
	describe('buildGraph', () => {
		it('should build graph with correct edges for linear workflow', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			expect(graph.edges).toHaveLength(2);
			expect(graph.edges[0].source).toBe('Webhook');
			expect(graph.edges[0].target).toBe('Set Data');
		});

		it('should build graph for branching workflow', () => {
			const parseResult = parseWorkflow(branchingWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			// IF node should have two outgoing edges
			const ifNode = graph.nodes.get('IF');
			expect(ifNode!.successors).toHaveLength(2);
			expect(ifNode!.successors).toContain('Code');
			expect(ifNode!.successors).toContain('Slack');
		});

		it('should identify entry points (nodes with no predecessors)', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			expect(graph.entryPoints).toContain('Webhook');
			expect(graph.entryPoints).toHaveLength(1);
		});

		it('should identify exit points (nodes with no successors)', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			expect(graph.exitPoints).toContain('HTTP Request');
			expect(graph.exitPoints).toHaveLength(1);
		});

		it('should identify multiple exit points in branching workflow', () => {
			const parseResult = parseWorkflow(branchingWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			expect(graph.exitPoints).toHaveLength(2);
			expect(graph.exitPoints).toContain('Code');
			expect(graph.exitPoints).toContain('Slack');
		});

		it('should detect cycles correctly', () => {
			const parseResult = parseWorkflow(cyclicWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			expect(graph.hasCycles).toBe(true);
		});

		it('should not detect cycles in acyclic graph', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			expect(graph.hasCycles).toBe(false);
		});

		it('should calculate depths correctly', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			expect(graph.nodes.get('Webhook')!.depth).toBe(0);
			expect(graph.nodes.get('Set Data')!.depth).toBe(1);
			expect(graph.nodes.get('HTTP Request')!.depth).toBe(2);
		});

		it('should handle disconnected nodes', () => {
			const parseResult = parseWorkflow(disconnectedWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			// Both nodes should be entry points (no predecessors)
			expect(graph.entryPoints).toHaveLength(2);
			// Both nodes should be exit points (no successors)
			expect(graph.exitPoints).toHaveLength(2);
		});
	});

	describe('getReachableNodes', () => {
		it('should return all forward reachable nodes', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const reachable = getReachableNodes(graph, 'Webhook', 'forward');

			expect(reachable.has('Webhook')).toBe(true);
			expect(reachable.has('Set Data')).toBe(true);
			expect(reachable.has('HTTP Request')).toBe(true);
		});

		it('should return all backward reachable nodes', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const reachable = getReachableNodes(graph, 'HTTP Request', 'backward');

			expect(reachable.has('HTTP Request')).toBe(true);
			expect(reachable.has('Set Data')).toBe(true);
			expect(reachable.has('Webhook')).toBe(true);
		});

		it('should handle branching correctly', () => {
			const parseResult = parseWorkflow(branchingWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const reachable = getReachableNodes(graph, 'IF', 'forward');

			expect(reachable.has('IF')).toBe(true);
			expect(reachable.has('Code')).toBe(true);
			expect(reachable.has('Slack')).toBe(true);
		});
	});

	describe('findAllPaths', () => {
		it('should find all paths between source and target', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const paths = findAllPaths(graph, 'Webhook', 'HTTP Request');

			expect(paths).toHaveLength(1);
			expect(paths[0]).toEqual(['Webhook', 'Set Data', 'HTTP Request']);
		});

		it('should find multiple paths in branching workflow', () => {
			// Create a workflow with converging paths
			const convergingWorkflow = {
				id: 'test',
				name: 'Converging',
				active: false,
				nodes: [
					{
						id: '1',
						name: 'Start',
						type: 'n8n-nodes-base.webhook',
						typeVersion: 1,
						position: [0, 0] as [number, number],
						parameters: {},
					},
					{
						id: '2',
						name: 'IF',
						type: 'n8n-nodes-base.if',
						typeVersion: 1,
						position: [200, 0] as [number, number],
						parameters: {},
					},
					{
						id: '3',
						name: 'Path A',
						type: 'n8n-nodes-base.set',
						typeVersion: 1,
						position: [400, -100] as [number, number],
						parameters: {},
					},
					{
						id: '4',
						name: 'Path B',
						type: 'n8n-nodes-base.set',
						typeVersion: 1,
						position: [400, 100] as [number, number],
						parameters: {},
					},
					{
						id: '5',
						name: 'End',
						type: 'n8n-nodes-base.code',
						typeVersion: 1,
						position: [600, 0] as [number, number],
						parameters: {},
					},
				],
				connections: {
					Start: { main: [[{ node: 'IF', type: 'main', index: 0 }]] },
					IF: {
						main: [
							[{ node: 'Path A', type: 'main', index: 0 }],
							[{ node: 'Path B', type: 'main', index: 0 }],
						],
					},
					'Path A': { main: [[{ node: 'End', type: 'main', index: 0 }]] },
					'Path B': { main: [[{ node: 'End', type: 'main', index: 0 }]] },
				},
			};

			const parseResult = parseWorkflow(convergingWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const paths = findAllPaths(graph, 'Start', 'End');

			expect(paths).toHaveLength(2);
		});

		it('should respect maxPaths limit', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const paths = findAllPaths(graph, 'Webhook', 'HTTP Request', 1);

			expect(paths.length).toBeLessThanOrEqual(1);
		});

		it('should return empty array if no path exists', () => {
			const parseResult = parseWorkflow(disconnectedWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const paths = findAllPaths(graph, 'Webhook', 'Code');

			expect(paths).toHaveLength(0);
		});
	});

	describe('getShortestPath', () => {
		it('should return shortest path between nodes', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const path = getShortestPath(graph, 'Webhook', 'HTTP Request');

			expect(path).toEqual(['Webhook', 'Set Data', 'HTTP Request']);
		});

		it('should return null if no path exists', () => {
			const parseResult = parseWorkflow(disconnectedWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const path = getShortestPath(graph, 'Webhook', 'Code');

			expect(path).toBeNull();
		});

		it('should return single node path for same source and target', () => {
			const parseResult = parseWorkflow(simpleLinearWorkflow);
			const graph = buildGraph(parseResult.workflow!);

			const path = getShortestPath(graph, 'Webhook', 'Webhook');

			expect(path).toEqual(['Webhook']);
		});
	});
});
