import type {
	IExecuteFunctions,
	IDataObject,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

import {
	mlabCoreApiRequest,
	mlabPublicApiRequest,
	pollDomainScan,
	MLAB_CVE_BASE_URL,
	MLAB_ACTORS_BASE_URL,
} from '../shared/GenericFunctions';

export class Mlab implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'mlab.sh',
		name: 'mlab',
		icon: 'file:mlab.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description:
			'mlab.sh security tooling: core scanning (domain/IP/crypto/file), CVE search and threat actor intelligence',
		defaults: {
			name: 'mlab.sh',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'mlabApi',
				// Only the core (authenticated) resources need credentials; the CVE
				// and Threat Actor surfaces are public, unauthenticated APIs.
				required: true,
				displayOptions: {
					show: {
						resource: ['domain', 'ip', 'crypto', 'file', 'quota'],
					},
				},
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{ name: 'Crypto Address', value: 'crypto' },
					{ name: 'CVE', value: 'cve' },
					{ name: 'Domain', value: 'domain' },
					{ name: 'File', value: 'file' },
					{ name: 'IP Address', value: 'ip' },
					{ name: 'Quota', value: 'quota' },
					{ name: 'Threat Actor', value: 'threatActor' },
				],
				default: 'domain',
			},

			// ======================================================================
			//                              Core: Domain
			// ======================================================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['domain'] } },
				options: [
					{
						name: 'Scan',
						value: 'scan',
						action: 'Scan a domain',
						description: 'Launch a domain scan and (optionally) wait for the results',
					},
					{
						name: 'Get Status',
						value: 'status',
						action: 'Get the status of a domain scan',
					},
					{
						name: 'Get Results',
						value: 'results',
						action: 'Get the results of a domain scan',
					},
				],
				default: 'scan',
			},
			{
				displayName: 'Domain',
				name: 'domain',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'example.com',
				displayOptions: { show: { resource: ['domain'] } },
				description: 'The domain to scan (without protocol)',
			},
			{
				displayName: 'Wait for Completion',
				name: 'waitForCompletion',
				type: 'boolean',
				default: true,
				displayOptions: { show: { resource: ['domain'], operation: ['scan'] } },
				description:
					'Whether to poll until the scan finishes and return the full results. If disabled, only the job acknowledgement is returned.',
			},
			{
				displayName: 'Timeout (Seconds)',
				name: 'timeout',
				type: 'number',
				default: 120,
				typeOptions: { minValue: 10 },
				displayOptions: {
					show: { resource: ['domain'], operation: ['scan'], waitForCompletion: [true] },
				},
				description: 'How long to wait for the scan to complete before giving up',
			},

			// ======================================================================
			//                              Core: IP
			// ======================================================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['ip'] } },
				options: [
					{
						name: 'Lookup',
						value: 'lookup',
						action: 'Look up an IP address',
						description: 'Resolve geolocation, ASN and ownership for an IP address',
					},
				],
				default: 'lookup',
			},
			{
				displayName: 'IP Address',
				name: 'ip',
				type: 'string',
				required: true,
				default: '',
				placeholder: '8.8.8.8',
				displayOptions: { show: { resource: ['ip'] } },
				description: 'IPv4 or IPv6 address to look up',
			},

			// ======================================================================
			//                              Core: Crypto
			// ======================================================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['crypto'] } },
				options: [
					{
						name: 'Lookup',
						value: 'lookup',
						action: 'Look up a crypto address',
						description: 'Check sanctions, labels and risk score for a crypto address',
					},
				],
				default: 'lookup',
			},
			{
				displayName: 'Address',
				name: 'address',
				type: 'string',
				required: true,
				default: '',
				placeholder: '0x...',
				displayOptions: { show: { resource: ['crypto'] } },
				description: 'The crypto address to look up',
			},
			{
				displayName: 'Chain',
				name: 'chain',
				type: 'options',
				default: '',
				displayOptions: { show: { resource: ['crypto'] } },
				description: 'Blockchain of the address. Leave on "Auto-detect" when unsure.',
				options: [
					{ name: 'Arbitrum', value: 'arbitrum' },
					{ name: 'Auto-Detect', value: '' },
					{ name: 'Avalanche', value: 'avax' },
					{ name: 'Base', value: 'base' },
					{ name: 'Bitcoin', value: 'btc' },
					{ name: 'BSC', value: 'bsc' },
					{ name: 'Dogecoin', value: 'doge' },
					{ name: 'Ethereum', value: 'eth' },
					{ name: 'Optimism', value: 'optimism' },
					{ name: 'Polygon', value: 'polygon' },
					{ name: 'Solana', value: 'sol' },
					{ name: 'TON', value: 'ton' },
					{ name: 'Tron', value: 'trx' },
				],
			},

			// ======================================================================
			//                              Core: File
			// ======================================================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['file'] } },
				options: [
					{
						name: 'Upload',
						value: 'upload',
						action: 'Upload a file for analysis',
						description: 'Upload a file (max 10MB) and launch analysis',
					},
					{
						name: 'Get Results',
						value: 'results',
						action: 'Get file analysis results',
						description: 'Fetch analysis results by SHA-256 hash',
					},
				],
				default: 'upload',
			},
			{
				displayName: 'Input Binary Field',
				name: 'binaryPropertyName',
				type: 'string',
				default: 'data',
				required: true,
				hint: 'The name of the input binary field containing the file to upload',
				displayOptions: { show: { resource: ['file'], operation: ['upload'] } },
			},
			{
				displayName: 'SHA-256',
				name: 'sha256',
				type: 'string',
				required: true,
				default: '',
				displayOptions: { show: { resource: ['file'], operation: ['results'] } },
				description: 'SHA-256 hash returned by the upload operation',
			},

			// ======================================================================
			//                              Core: Quota
			// ======================================================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['quota'] } },
				options: [
					{
						name: 'Get',
						value: 'get',
						action: 'Get remaining quota',
						description: 'Get the remaining daily quota for a scan type',
					},
				],
				default: 'get',
			},
			{
				displayName: 'Scan Type',
				name: 'scanType',
				type: 'options',
				default: 'domain',
				displayOptions: { show: { resource: ['quota'] } },
				options: [
					{ name: 'Domain', value: 'domain' },
					{ name: 'IP', value: 'ip' },
					{ name: 'File', value: 'file' },
					{ name: 'Crypto', value: 'crypto' },
				],
			},

			// ======================================================================
			//                              CVE
			// ======================================================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['cve'] } },
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
			{
				displayName: 'CVE ID',
				name: 'cveId',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'CVE-2024-3094',
				displayOptions: { show: { resource: ['cve'], operation: ['get'] } },
				description: 'The CVE identifier to retrieve',
			},
			{
				displayName: 'Query',
				name: 'query',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'openssl',
				displayOptions: { show: { resource: ['cve'], operation: ['search'] } },
				description: 'Keyword, vendor or product name to search for',
			},
			{
				displayName: 'Filters',
				name: 'cveFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['cve'], operation: ['search'] } },
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
						description:
							'Whether to only return CVEs in the CISA Known Exploited Vulnerabilities catalog',
					},
				],
			},

			// ======================================================================
			//                              Threat Actor
			// ======================================================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['threatActor'] } },
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
			{
				displayName: 'Actor Slug',
				name: 'slug',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'apt28',
				displayOptions: { show: { resource: ['threatActor'], operation: ['get'] } },
				description: 'The slug of the actor to retrieve',
			},
			{
				displayName: 'CVE ID',
				name: 'actorCveId',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'CVE-2021-44228',
				displayOptions: { show: { resource: ['threatActor'], operation: ['byCve'] } },
				description: 'The CVE identifier to reverse-lookup actors for',
			},
			{
				displayName: 'Filters',
				name: 'actorFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['threatActor'], operation: ['list'] } },
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
				displayOptions: { show: { resource: ['threatActor'], operation: ['list'] } },
				description: 'Max number of results to return',
			},
			{
				displayName: 'Offset',
				name: 'offset',
				type: 'number',
				default: 0,
				displayOptions: { show: { resource: ['threatActor'], operation: ['list'] } },
				description: 'Number of results to skip (for pagination)',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;

		for (let i = 0; i < items.length; i++) {
			try {
				let responseData: IDataObject | IDataObject[] = {};

				if (resource === 'domain') {
					const domain = this.getNodeParameter('domain', i) as string;

					if (operation === 'scan') {
						const waitForCompletion = this.getNodeParameter('waitForCompletion', i) as boolean;
						const launch = (await mlabCoreApiRequest.call(this, 'POST', '/scan/domain', {
							domain,
						})) as IDataObject;

						if (waitForCompletion) {
							const timeout = this.getNodeParameter('timeout', i) as number;
							const intervalMs = 4000;
							const maxAttempts = Math.max(1, Math.ceil((timeout * 1000) / intervalMs));
							responseData = await pollDomainScan.call(this, domain, maxAttempts, intervalMs);
						} else {
							responseData = launch;
						}
					} else if (operation === 'status') {
						responseData = (await mlabCoreApiRequest.call(this, 'GET', '/scan/domain/status', {}, {
							domain,
						})) as IDataObject;
					} else if (operation === 'results') {
						responseData = (await mlabCoreApiRequest.call(this, 'GET', '/scan/domain/results', {}, {
							domain,
						})) as IDataObject;
					}
				} else if (resource === 'ip') {
					const ip = this.getNodeParameter('ip', i) as string;
					responseData = (await mlabCoreApiRequest.call(this, 'GET', '/scan/ip', {}, {
						ip,
					})) as IDataObject;
				} else if (resource === 'crypto') {
					const address = this.getNodeParameter('address', i) as string;
					const chain = this.getNodeParameter('chain', i) as string;
					const qs: IDataObject = { address };
					if (chain) qs.chain = chain;
					responseData = (await mlabCoreApiRequest.call(
						this,
						'GET',
						'/scan/crypto',
						{},
						qs,
					)) as IDataObject;
				} else if (resource === 'file') {
					if (operation === 'upload') {
						const binaryPropertyName = this.getNodeParameter('binaryPropertyName', i) as string;
						const binaryData = this.helpers.assertBinaryData(i, binaryPropertyName);
						const buffer = await this.helpers.getBinaryDataBuffer(i, binaryPropertyName);

						responseData = (await mlabCoreApiRequest.call(this, 'POST', '/upload/file', {}, {}, {
							body: {
								file: {
									value: buffer,
									options: {
										filename: binaryData.fileName ?? 'file',
										contentType: binaryData.mimeType,
									},
								},
							},
							headers: { 'Content-Type': 'multipart/form-data' },
							json: false,
						})) as IDataObject;
					} else if (operation === 'results') {
						const sha256 = this.getNodeParameter('sha256', i) as string;
						responseData = (await mlabCoreApiRequest.call(this, 'GET', '/scan/file/results', {}, {
							sha256,
						})) as IDataObject;
					}
				} else if (resource === 'quota') {
					const scanType = this.getNodeParameter('scanType', i) as string;
					responseData = (await mlabCoreApiRequest.call(
						this,
						'GET',
						`/limit/${scanType}`,
					)) as IDataObject;
				} else if (resource === 'cve') {
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
						const filters = this.getNodeParameter('cveFilters', i, {}) as IDataObject;
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
				} else if (resource === 'threatActor') {
					if (operation === 'get') {
						const slug = (this.getNodeParameter('slug', i) as string).trim();
						responseData = (await mlabPublicApiRequest.call(
							this,
							MLAB_ACTORS_BASE_URL,
							'GET',
							`/actors/${encodeURIComponent(slug)}`,
						)) as IDataObject;
					} else if (operation === 'byCve') {
						const cveId = (this.getNodeParameter('actorCveId', i) as string).trim().toUpperCase();
						responseData = (await mlabPublicApiRequest.call(
							this,
							MLAB_ACTORS_BASE_URL,
							'GET',
							`/cves/${encodeURIComponent(cveId)}/actors`,
						)) as IDataObject;
					} else if (operation === 'list') {
						const filters = this.getNodeParameter('actorFilters', i, {}) as IDataObject;
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
				} else {
					throw new NodeOperationError(this.getNode(), `Unknown resource "${resource}"`, {
						itemIndex: i,
					});
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
