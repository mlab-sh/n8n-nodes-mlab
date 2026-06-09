import type {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class MlabApi implements ICredentialType {
	name = 'mlabApi';

	displayName = 'mlab.sh API';

	documentationUrl = 'https://mlab.sh/developer/documentation';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'Your mlab.sh API key (starts with "mlab_"). Generate one under Account → Settings → API Keys.',
		},
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://mlab.sh/api/v1',
			description: 'Base URL of the mlab.sh core API. Only change this for self-hosted instances.',
		},
	];

	// Injects "Authorization: token mlab_xxx" into every request that uses this credential.
	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=token {{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '/limit/ip',
			method: 'GET',
		},
	};
}
