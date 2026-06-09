import type {
	IExecuteFunctions,
	IDataObject,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';

import { mlabPublicApiRequest, MLAB_CVE_BASE_URL } from '../shared/GenericFunctions';

export class MlabCve implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'mlab.sh CVE',
		name: 'mlabCve',
		icon: 'file:mlab.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Search and retrieve CVE vulnerability data from vuln.mlab.sh',
		defaults: {
			name: 'mlab.sh CVE',
		},
		inputs: ['main'],
		outputs: ['main'],
		// vuln.mlab.sh is a public, unauthenticated API — no credentials needed.
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Search',
						value: 'search',
						action: 'Search vulnerabilities',
						description: 'Search vulnerabilities by keyword, vendor or product',
					},
					{
						name: 'Get',
						value: 'get',
						action: 'Get a CVE by ID',
						description: 'Retrieve full details for a CVE (including EPSS and KEV data)',
					},
					{
						name: 'Get Latest',
						value: 'latest',
						action: 'Get latest vulnerabilities',
						description: 'Fetch vulnerabilities from the last 7 days',
					},
				],
				default: 'search',
			},

			// ----------------------------------------------------------------------
			//                              Get
			// ----------------------------------------------------------------------
			{
				displayName: 'CVE ID',
				name: 'cveId',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'CVE-2024-3094',
				displayOptions: { show: { operation: ['get'] } },
				description: 'The CVE identifier to retrieve',
			},

			// ----------------------------------------------------------------------
			//                              Search
			// ----------------------------------------------------------------------
			{
				displayName: 'Query',
				name: 'query',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'openssl',
				displayOptions: { show: { operation: ['search'] } },
				description: 'Keyword, vendor or product name to search for',
			},
			{
				displayName: 'Filters',
				name: 'filters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { operation: ['search'] } },
				options: [
					{
						displayName: 'Severity',
						name: 'severity',
						type: 'options',
						default: 'CRITICAL',
						options: [
							{ name: 'Critical', value: 'CRITICAL' },
							{ name: 'High', value: 'HIGH' },
							{ name: 'Medium', value: 'MEDIUM' },
							{ name: 'Low', value: 'LOW' },
						],
					},
					{
						displayName: 'Published After',
						name: 'dateStart',
						type: 'dateTime',
						default: '',
						description: 'Only return CVEs published on or after this date',
					},
					{
						displayName: 'Exact Match',
						name: 'exact',
						type: 'boolean',
						default: false,
						description: 'Whether to perform an exact-match search instead of fuzzy',
					},
					{
						displayName: 'Known Exploited Only (KEV)',
						name: 'kev',
						type: 'boolean',
						default: false,
						description: 'Whether to only return CVEs in the CISA Known Exploited Vulnerabilities catalog',
					},
				],
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
					const cveId = (this.getNodeParameter('cveId', i) as string).trim().toUpperCase();
					responseData = (await mlabPublicApiRequest.call(
						this,
						MLAB_CVE_BASE_URL,
						'GET',
						`/cve/${encodeURIComponent(cveId)}`,
					)) as IDataObject;
				} else if (operation === 'latest') {
					responseData = (await mlabPublicApiRequest.call(
						this,
						MLAB_CVE_BASE_URL,
						'GET',
						'/cve/latest',
					)) as IDataObject;
				} else if (operation === 'search') {
					const query = this.getNodeParameter('query', i) as string;
					const filters = this.getNodeParameter('filters', i, {}) as IDataObject;
					const qs: IDataObject = { q: query };

					if (filters.severity) qs.severity = filters.severity;
					if (filters.exact) qs.exact = 1;
					if (filters.kev) qs.kev = 1;
					if (filters.dateStart) {
						// Accept full ISO datetime, send the date part only (YYYY-MM-DD).
						qs.dateStart = (filters.dateStart as string).slice(0, 10);
					}

					responseData = (await mlabPublicApiRequest.call(
						this,
						MLAB_CVE_BASE_URL,
						'GET',
						'/cve',
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
