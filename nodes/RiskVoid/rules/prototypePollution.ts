
import type {
    DetectionRule,
    RuleContext,
    Finding,
    RuleMetadata,
} from './types';
import { createFindingId } from './types';
import type { N8nNode } from '../types';

export class PrototypePollutionRule implements DetectionRule {
    metadata: RuleMetadata = {
        id: 'RV-PP-001',
        name: 'Prototype Pollution',
        description: 'Detects potential prototype pollution vulnerabilities where user input can modify object prototypes.',
        category: 'prototype-pollution',
        severity: 'medium',
        tags: ['injection', 'javascript', 'prototype-pollution'],
        references: {
            cwe: 'CWE-1321',
            owasp: 'A03:2021-Injection',
            documentation: 'https://portswigger.net/web-security/prototype-pollution',
        },
    };

    isApplicable(context: RuleContext): boolean {
        // Only run if there are Code nodes or Function nodes
        for (const [, node] of context.workflow.nodes) {
            if (
                node.type === 'n8n-nodes-base.code' ||
                node.type === 'n8n-nodes-base.function' ||
                node.type === 'n8n-nodes-base.functionItem'
            ) {
                return true;
            }
        }
        return false;
    }

    detect(context: RuleContext): Finding[] {
        const findings: Finding[] = [];

        for (const [nodeName, node] of context.workflow.nodes) {
            if (
                node.type !== 'n8n-nodes-base.code' &&
                node.type !== 'n8n-nodes-base.function' &&
                node.type !== 'n8n-nodes-base.functionItem'
            ) {
                continue;
            }

            const code = this.extractCode(node);
            if (!code) continue;

            const patterns = this.findPollutionPatterns(code);
            if (patterns.length > 0) {
                findings.push(this.createFinding(nodeName, node.type, patterns));
            }
        }

        return findings;
    }

    private extractCode(node: N8nNode): string {
        const params = node.parameters;
        if (params.jsCode) return params.jsCode as string;
        if (params.functionCode) return params.functionCode as string;
        return '';
    }

    private findPollutionPatterns(code: string): string[] {
        const patterns: string[] = [];

        // Regex for __proto__ access/assignment
        // Matches: obj.__proto__, obj["__proto__"], obj['__proto__']
        const protoRegex = /(\w+)?(\.__proto__|\[['"]__proto__['"]\])/g;

        // Regex for constructor.prototype access/assignment
        // Matches: obj.constructor.prototype
        const constructorRegex = /\.constructor\.prototype/g;

        let match;
        while ((match = protoRegex.exec(code)) !== null) {
            patterns.push(match[0]);
        }
        while ((match = constructorRegex.exec(code)) !== null) {
            patterns.push(match[0]);
        }

        return patterns;
    }

    private createFinding(nodeName: string, nodeType: string, patterns: string[]): Finding {
        return {
            id: createFindingId(this.metadata.id),
            ruleId: this.metadata.id,
            severity: this.metadata.severity,
            confidence: 'medium',
            title: 'Potential Prototype Pollution',
            description: `The code contains patterns associated with Prototype Pollution: ${patterns.join(', ')}. Attackers could modify the prototype of base objects, potentially leading to Denial of Service or Remote Code Execution.`,
            category: this.metadata.category,
            source: {
                node: nodeName,
                nodeType: nodeType,
                field: 'code',
            },
            sink: {
                node: nodeName,
                nodeType: nodeType,
                parameter: 'jsCode',
                dangerousExpression: patterns[0],
            },
            path: [nodeName],
            remediation: {
                summary: 'Avoid direct assignment to __proto__ or recursive merges without key validation.',
                steps: [
                    'Ensure keys like "__proto__", "constructor", and "prototype" are blocked in merge functions.',
                    'Use Object.freeze() on prototypes if possible.',
                    'Use Map instead of Object for user-controlled keys.'
                ],
                safePattern: 'const safeObj = Object.assign(Object.create(null), userInput);',
            },
            references: this.metadata.references,
            metadata: {},
        };
    }
}
