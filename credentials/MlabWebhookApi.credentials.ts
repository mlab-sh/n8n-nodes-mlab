import type { ICredentialType, Icon, INodeProperties } from 'n8n-workflow';

export class MlabWebhookApi implements ICredentialType {
	name = 'mlabWebhookApi';

	displayName = 'mlab.sh Webhook API';

	icon: Icon = { light: 'file:../nodes/Mlab/mlab.svg', dark: 'file:../nodes/Mlab/mlab.dark.svg' };

	documentationUrl = 'https://mlab.sh/developer/documentation';

	properties: INodeProperties[] = [
		{
			displayName: 'Signing Secret',
			name: 'secret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'The secret mlab.sh shows when the webhook endpoint is created (Organization → Alerting → Channels). Used to verify X-Mlab-Signature.',
		},
	];
}
