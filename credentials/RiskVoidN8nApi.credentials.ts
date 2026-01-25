import type {
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class RiskVoidN8nApi implements ICredentialType {
	name = 'riskVoidN8nApi';

	displayName = 'RiskVoid N8n API';

	documentationUrl = 'https://docs.n8n.io/api/authentication/';

	icon = {
		light: 'file:../nodes/RiskVoid/riskvoid.svg',
		dark: 'file:../nodes/RiskVoid/riskvoid.svg',
	} as const;

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description: 'The API key for your n8n instance. Generate one in Settings → API.',
		},
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: '',
			placeholder: 'https://your-n8n-instance.com',
			description:
				'The base URL of your n8n instance (without trailing slash). Leave empty to use the current instance.',
		},
	];

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl || "http://localhost:5678"}}',
			url: '/api/v1/workflows',
			method: 'GET',
			headers: {
				'X-N8N-API-KEY': '={{$credentials.apiKey}}',
			},
		},
	};
}
