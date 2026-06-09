import type {
	IExecuteFunctions,
	IDataObject,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

import { mlabCoreApiRequest, pollDomainScan } from '../shared/GenericFunctions';

export class MlabCore implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'mlab.sh Core',
		name: 'mlabCore',
		icon: 'file:mlab.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description: 'Run mlab.sh core scans: domain, IP, crypto address, and file analysis',
		defaults: {
			name: 'mlab.sh Core',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'mlabApi',
				required: true,
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
					{ name: 'Domain', value: 'domain' },
					{ name: 'File', value: 'file' },
					{ name: 'IP Address', value: 'ip' },
					{ name: 'Quota', value: 'quota' },
				],
				default: 'domain',
			},

			// ----------------------------------------------------------------------
			//                              Domain
			// ----------------------------------------------------------------------
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

			// ----------------------------------------------------------------------
			//                              IP
			// ----------------------------------------------------------------------
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

			// ----------------------------------------------------------------------
			//                              Crypto
			// ----------------------------------------------------------------------
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

			// ----------------------------------------------------------------------
			//                              File
			// ----------------------------------------------------------------------
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

			// ----------------------------------------------------------------------
			//                              Quota
			// ----------------------------------------------------------------------
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
