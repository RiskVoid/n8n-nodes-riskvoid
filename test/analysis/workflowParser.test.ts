import { parseWorkflow, isTriggerNode } from '../../nodes/RiskVoid/analysis/workflowParser';
import {
	simpleLinearWorkflow,
	branchingWorkflow,
	emptyWorkflow,
	invalidWorkflow,
	workflowWithDisabledNode,
} from '../fixtures/workflows';

describe('workflowParser', () => {
	describe('parseWorkflow', () => {
		it('should parse a valid workflow with nodes and connections', () => {
			const result = parseWorkflow(simpleLinearWorkflow);

			expect(result.success).toBe(true);
			expect(result.errors).toHaveLength(0);
			expect(result.workflow).toBeDefined();
			expect(result.workflow!.nodeCount).toBe(3);
			expect(result.workflow!.name).toBe('Simple Linear Workflow');
		});

		it('should build a Map of nodes keyed by name', () => {
			const result = parseWorkflow(simpleLinearWorkflow);

			expect(result.workflow!.nodes.has('Webhook')).toBe(true);
			expect(result.workflow!.nodes.has('Set Data')).toBe(true);
			expect(result.workflow!.nodes.has('HTTP Request')).toBe(true);
		});

		it('should group nodes by type', () => {
			const result = parseWorkflow(branchingWorkflow);

			expect(result.workflow!.nodesByType.has('n8n-nodes-base.webhook')).toBe(true);
			expect(result.workflow!.nodesByType.get('n8n-nodes-base.webhook')).toHaveLength(1);
		});

		it('should count connections correctly', () => {
			const result = parseWorkflow(simpleLinearWorkflow);

			// Webhook -> Set Data -> HTTP Request = 2 connections
			expect(result.workflow!.connectionCount).toBe(2);
		});

		it('should count connections for branching workflows', () => {
			const result = parseWorkflow(branchingWorkflow);

			// Webhook -> IF = 1, IF -> Code = 1, IF -> Slack = 1 = 3 connections
			expect(result.workflow!.connectionCount).toBe(3);
		});

		it('should extract workflow metadata', () => {
			const result = parseWorkflow(simpleLinearWorkflow);

			expect(result.workflow!.metadata.hasTriggers).toBe(true);
			expect(result.workflow!.metadata.triggerTypes).toContain('n8n-nodes-base.webhook');
			expect(result.workflow!.metadata.nodeTypes).toContain('n8n-nodes-base.httpRequest');
		});

		it('should fail on null input', () => {
			const result = parseWorkflow(null);

			expect(result.success).toBe(false);
			expect(result.errors.length).toBeGreaterThan(0);
			expect(result.errors[0].code).toBe('INVALID_INPUT');
		});

		it('should fail on missing nodes array', () => {
			const result = parseWorkflow(invalidWorkflow);

			expect(result.success).toBe(false);
			expect(result.errors.some((e) => e.code === 'MISSING_NODES')).toBe(true);
		});

		it('should fail on empty workflow', () => {
			const result = parseWorkflow(emptyWorkflow);

			expect(result.success).toBe(false);
			expect(result.errors.some((e) => e.code === 'NO_VALID_NODES')).toBe(true);
		});

		it('should parse workflow JSON string', () => {
			const jsonString = JSON.stringify(simpleLinearWorkflow);
			const result = parseWorkflow(jsonString);

			expect(result.success).toBe(true);
			expect(result.workflow!.name).toBe('Simple Linear Workflow');
		});

		it('should fail on invalid JSON string', () => {
			const result = parseWorkflow('{ invalid json }');

			expect(result.success).toBe(false);
			expect(result.errors[0].code).toBe('INVALID_JSON');
		});

		it('should handle workflow with disabled nodes', () => {
			const result = parseWorkflow(workflowWithDisabledNode);

			expect(result.success).toBe(true);
			const disabledNode = result.workflow!.nodes.get('Disabled Code');
			expect(disabledNode).toBeDefined();
			expect(disabledNode!.disabled).toBe(true);
		});

		it('should generate warnings for malformed nodes', () => {
			const workflowWithBadNode = {
				...simpleLinearWorkflow,
				nodes: [
					...simpleLinearWorkflow.nodes,
					{ invalid: 'node' }, // Missing required fields
				],
			};

			const result = parseWorkflow(workflowWithBadNode);

			expect(result.success).toBe(true);
			expect(result.warnings.length).toBeGreaterThan(0);
		});

		it('should warn on duplicate node names', () => {
			const workflowWithDuplicates = {
				...simpleLinearWorkflow,
				nodes: [
					...simpleLinearWorkflow.nodes,
					{
						id: 'node-dup',
						name: 'Webhook', // Duplicate name
						type: 'n8n-nodes-base.webhook',
						typeVersion: 1,
						position: [600, 0] as [number, number],
						parameters: {},
					},
				],
			};

			const result = parseWorkflow(workflowWithDuplicates);

			expect(result.success).toBe(true);
			expect(result.warnings.some((w) => w.code === 'DUPLICATE_NODE_NAME')).toBe(true);
			// Should keep only the first occurrence
			expect(result.workflow!.nodeCount).toBe(3);
		});
	});

	describe('isTriggerNode', () => {
		it('should identify webhook as trigger', () => {
			expect(isTriggerNode('n8n-nodes-base.webhook')).toBe(true);
		});

		it('should identify nodes ending with Trigger', () => {
			expect(isTriggerNode('n8n-nodes-base.manualTrigger')).toBe(true);
			expect(isTriggerNode('n8n-nodes-base.scheduleTrigger')).toBe(true);
		});

		it('should identify nodes containing trigger', () => {
			expect(isTriggerNode('n8n-nodes-base.emailTrigger')).toBe(true);
		});

		it('should not identify regular nodes as triggers', () => {
			expect(isTriggerNode('n8n-nodes-base.code')).toBe(false);
			expect(isTriggerNode('n8n-nodes-base.httpRequest')).toBe(false);
		});
	});
});
