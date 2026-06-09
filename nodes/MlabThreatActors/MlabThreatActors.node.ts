import type {
	IExecuteFunctions,
	IDataObject,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';

import { mlabPublicApiRequest, MLAB_ACTORS_BASE_URL } from '../shared/GenericFunctions';

export class MlabThreatActors implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'mlab.sh Threat Actors',
		name: 'mlabThreatActors',
		icon: 'file:mlab.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Look up cyber threat actor intelligence from actors.mlab.sh',
		defaults: {
			name: 'mlab.sh Threat Actors',
		},
		inputs: ['main'],
		outputs: ['main'],
		// actors.mlab.sh is a public, unauthenticated API — no credentials needed.
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'List / Search',
						value: 'list',
						action: 'List or search threat actors',
						description: 'List actors with optional filters (origin, motivation, sector)',
					},
					{
						name: 'Get',
						value: 'get',
						action: 'Get a threat actor',
						description: 'Get a single actor by slug, including aliases, tools, CVEs and techniques',
					},
					{
						name: 'Get by CVE',
						value: 'byCve',
						action: 'Get actors that exploit a CVE',
						description: 'Reverse lookup: which actors are known to exploit a given CVE',
					},
				],
				default: 'list',
			},

			// ----------------------------------------------------------------------
			//                              Get
			// ----------------------------------------------------------------------
			{
				displayName: 'Actor Slug',
				name: 'slug',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'apt28',
				displayOptions: { show: { operation: ['get'] } },
				description: 'The slug of the actor to retrieve',
			},

			// ----------------------------------------------------------------------
			//                              Get by CVE
			// ----------------------------------------------------------------------
			{
				displayName: 'CVE ID',
				name: 'cveId',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'CVE-2021-44228',
				displayOptions: { show: { operation: ['byCve'] } },
				description: 'The CVE identifier to reverse-lookup actors for',
			},

			// ----------------------------------------------------------------------
			//                              List / Search
			// ----------------------------------------------------------------------
			{
				displayName: 'Filters',
				name: 'filters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { operation: ['list'] } },
				options: [
					{
						displayName: 'Origin',
						name: 'origin',
						type: 'string',
						default: '',
						description: 'Filter by country of origin (e.g. "China", "Russia")',
					},
					{
						displayName: 'Motivation',
						name: 'motivation',
						type: 'string',
						default: '',
						placeholder: 'Espionage',
						description: 'Filter by motivation type',
					},
					{
						displayName: 'Sector',
						name: 'sector',
						type: 'string',
						default: '',
						placeholder: 'Government',
						description: 'Filter by targeted sector',
					},
				],
			},
			{
				displayName: 'Limit',
				name: 'limit',
				type: 'number',
				typeOptions: { minValue: 1 },
				default: 50,
				displayOptions: { show: { operation: ['list'] } },
				description: 'Max number of results to return',
			},
			{
				displayName: 'Offset',
				name: 'offset',
				type: 'number',
				default: 0,
				displayOptions: { show: { operation: ['list'] } },
				description: 'Number of results to skip (for pagination)',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const operation = this.getNodeParameter('operation', 0) as string;

		for (let i = 0; i < items.length; i++) {
			try {
				let responseData: IDataObject | IDataObject[] = {};

				if (operation === 'get') {
					const slug = (this.getNodeParameter('slug', i) as string).trim();
					responseData = (await mlabPublicApiRequest.call(
						this,
						MLAB_ACTORS_BASE_URL,
						'GET',
						`/actors/${encodeURIComponent(slug)}`,
					)) as IDataObject;
				} else if (operation === 'byCve') {
					const cveId = (this.getNodeParameter('cveId', i) as string).trim().toUpperCase();
					responseData = (await mlabPublicApiRequest.call(
						this,
						MLAB_ACTORS_BASE_URL,
						'GET',
						`/cves/${encodeURIComponent(cveId)}/actors`,
					)) as IDataObject;
				} else if (operation === 'list') {
					const filters = this.getNodeParameter('filters', i, {}) as IDataObject;
					const limit = this.getNodeParameter('limit', i) as number;
					const offset = this.getNodeParameter('offset', i) as number;
					const qs: IDataObject = { limit, offset };

					if (filters.origin) qs.origin = filters.origin;
					if (filters.motivation) qs.motivation = filters.motivation;
					if (filters.sector) qs.sector = filters.sector;

					responseData = (await mlabPublicApiRequest.call(
						this,
						MLAB_ACTORS_BASE_URL,
						'GET',
						'/actors',
						qs,
					)) as IDataObject;
				}

				const executionData = this.helpers.constructExecutionMetaData(
					this.helpers.returnJsonArray(responseData as IDataObject | IDataObject[]),
					{ itemData: { item: i } },
				);
				returnData.push(...executionData);
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: (error as Error).message },
						pairedItem: { item: i },
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}
