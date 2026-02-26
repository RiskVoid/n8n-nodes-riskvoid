
import { PrototypePollutionRule } from '../../nodes/RiskVoid/rules/prototypePollution';
import { RuleContext } from '../../nodes/RiskVoid/rules/types';

describe('PrototypePollutionRule', () => {
    let rule: PrototypePollutionRule;
    let mockContext: RuleContext;

    beforeEach(() => {
        rule = new PrototypePollutionRule();
        mockContext = {
            workflow: {
                nodes: new Map(),
                connections: {},
            },
            // Other context fields not needed for this rule's detection logic (it depends on node properties)
            graph: { nodes: new Map(), adjacency: new Map() },
            sources: [],
            sinks: [],
            taintPaths: [],
        } as any;
    });

    it('should detect __proto__ assignment in JS Code', () => {
        const node = {
            name: 'Code',
            type: 'n8n-nodes-base.code',
            parameters: {
                jsCode: 'const x = {}; x.__proto__.polluted = true;',
            },
        };
        mockContext.workflow.nodes.set('Code', node as any);

        const findings = rule.detect(mockContext);
        expect(findings).toHaveLength(1);
        expect(findings[0].title).toBe('Potential Prototype Pollution');
        expect(findings[0].sink.dangerousExpression).toContain('__proto__');
    });

    it('should detect constructor.prototype assignment', () => {
        const node = {
            name: 'Code',
            type: 'n8n-nodes-base.code',
            parameters: {
                jsCode: 'someObj.constructor.prototype.isAdmin = true;',
            },
        };
        mockContext.workflow.nodes.set('Code', node as any);

        const findings = rule.detect(mockContext);
        expect(findings).toHaveLength(1);
        expect(findings[0].sink.dangerousExpression).toContain('constructor.prototype');
    });

    it('should ignore safe code', () => {
        const node = {
            name: 'SafeCode',
            type: 'n8n-nodes-base.code',
            parameters: {
                jsCode: 'const x = {}; x.property = true;',
            },
        };
        mockContext.workflow.nodes.set('SafeCode', node as any);

        const findings = rule.detect(mockContext);
        expect(findings).toHaveLength(0);
    });
});
