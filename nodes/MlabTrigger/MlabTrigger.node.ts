import type {
	IDataObject,
	INodeType,
	INodeTypeDescription,
	IWebhookFunctions,
	IWebhookResponseData,
} from 'n8n-workflow';
import { NodeConnectionTypes } from 'n8n-workflow';

import { verifyWebhookSignature } from '../shared/GenericFunctions';

/** Every event an mlab.sh endpoint can subscribe to (`EVENT_CATALOG`, helper/alerting/webhook.rs). */
const EVENTS = [
	'agent.offline', 'agent.outdated', 'agent.policy_drift', 'agent.recovered',
	'audit.access', 'audit.billing', 'audit.licenses', 'audit.members', 'audit.organization',
	'audit.security', 'audit.webhooks', 'audit.workspaces',
	'case.sweep.hits',
	'infra.domain.unverified',
	'ir.instance.down', 'ir.instance.recovered',
	'monitoring.finding.escalated', 'monitoring.finding.new',
	'quota.reached', 'quota.warning',
	'scan.code.completed', 'scan.code.failed',
	'scan.domain.changed', 'scan.domain.completed', 'scan.domain.failed', 'scan.domain.partial',
	'scan.redkit.completed', 'scan.redkit.failed', 'scan.redkit.findings.new',
	'scan.watchdog.quota_exhausted', 'scan.watchdog.triggered',
	'tprm.instance.down', 'tprm.instance.recovered',
	'webhook.test',
];

/** Delivery ids remembered for de-duplication. mlab retries for about 7 hours. */
const SEEN_MAX = 1000;

export class MlabTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'mlab.sh Trigger',
		name: 'mlabTrigger',
		icon: { light: 'file:mlab.svg', dark: 'file:mlab.dark.svg' },
		group: ['trigger'],
		version: 1,
		subtitle: '={{$parameter["events"].length ? $parameter["events"].join(", ") : "All events"}}',
		description: 'Starts the workflow on a signed mlab.sh webhook delivery',
		defaults: { name: 'mlab.sh Trigger' },
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		credentials: [{ name: 'mlabWebhookApi', required: true }],
		webhooks: [
			{
				name: 'default',
				httpMethod: 'POST',
				responseMode: 'onReceived',
				path: 'webhook',
			},
		],
		properties: [
			{
				displayName:
					'In mlab.sh, create a webhook endpoint with the <b>Generic (signed JSON)</b> format and this node\'s production URL, then paste its secret in the credential.',
				name: 'notice',
				type: 'notice',
				default: '',
			},
			{
				displayName: 'Events',
				name: 'events',
				type: 'multiOptions',
				default: [],
				options: EVENTS.map((e) => ({ name: e, value: e })),
				description:
					'Only start the workflow for these events. Leave empty for every event the endpoint is subscribed to.',
			},
			{
				displayName: 'Timestamp Tolerance (Seconds)',
				name: 'tolerance',
				type: 'number',
				default: 300,
				typeOptions: { minValue: 0 },
				description:
					'Refuse a delivery whose X-Mlab-Timestamp is further than this from now, so a captured one cannot be replayed. 0 turns the check off.',
			},
		],
	};

	async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
		const req = this.getRequestObject();
		const res = this.getResponseObject();
		const header = (name: string) => {
			const v = req.headers[name];
			return Array.isArray(v) ? v[0] : v;
		};
		const reply = (status: number, message: string): IWebhookResponseData => {
			res.status(status).json({ message });
			return { noWebhookResponse: true };
		};

		const { secret } = await this.getCredentials('mlabWebhookApi');
		const raw = (req as unknown as { rawBody?: Buffer }).rawBody ?? JSON.stringify(req.body ?? {});
		const refused = verifyWebhookSignature(
			secret as string,
			raw,
			header('x-mlab-signature'),
			header('x-mlab-timestamp'),
			this.getNodeParameter('tolerance', 300) as number,
		);
		if (refused) return reply(401, `Delivery refused: ${refused}.`);

		// The delivery id is stable across mlab's retries: a retry of a delivery
		// that did land is acknowledged, not run twice.
		const delivery = header('x-mlab-delivery');
		if (delivery) {
			const store = this.getWorkflowStaticData('node');
			const seen = (store.seenDeliveries as string[] | undefined) ?? [];
			if (seen.includes(delivery)) return reply(200, 'Already received.');
			seen.push(delivery);
			store.seenDeliveries = seen.slice(-SEEN_MAX);
		}

		const body = (req.body ?? {}) as IDataObject;
		const event = (header('x-mlab-event') ?? body.event) as string | undefined;
		const wanted = this.getNodeParameter('events', []) as string[];
		if (wanted.length && (!event || !wanted.includes(event))) return reply(200, 'Event not selected.');

		return { workflowData: [this.helpers.returnJsonArray(body)] };
	}
}
