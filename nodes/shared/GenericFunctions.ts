import type {
	IExecuteFunctions,
	IDataObject,
	IHttpRequestMethods,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError } from 'n8n-workflow';

/**
 * Public base URLs for the three mlab.sh services. The core API base URL can be
 * overridden per credential (for self-hosted setups); the vuln and actors APIs
 * are public and unauthenticated.
 */
export const MLAB_CVE_BASE_URL = 'https://vuln.mlab.sh/api/v1';
export const MLAB_ACTORS_BASE_URL = 'https://actors.mlab.sh/api/v1';

/**
 * Authenticated request against the mlab.sh core API. Uses the `mlabApi`
 * credential, which injects the `Authorization: token <key>` header.
 */
export async function mlabCoreApiRequest(
	this: IExecuteFunctions | ILoadOptionsFunctions,
	method: IHttpRequestMethods,
	resource: string,
	body: IDataObject = {},
	qs: IDataObject = {},
	option: Partial<IHttpRequestOptions> = {},
): Promise<any> {
	const credentials = await this.getCredentials('mlabApi');
	const baseUrl = ((credentials.baseUrl as string) || 'https://mlab.sh/api/v1').replace(/\/$/, '');

	const options: IHttpRequestOptions = {
		method,
		url: `${baseUrl}${resource}`,
		json: true,
	};

	if (Object.keys(body).length > 0) {
		options.body = body;
	}
	if (Object.keys(qs).length > 0) {
		options.qs = qs;
	}

	// Caller overrides (e.g. multipart upload body/headers) take precedence.
	Object.assign(options, option);

	try {
		return await this.helpers.httpRequestWithAuthentication.call(this, 'mlabApi', options);
	} catch (error) {
		throw new NodeApiError(this.getNode(), error as JsonObject);
	}
}

/**
 * Unauthenticated request against one of the public mlab.sh services
 * (vuln.mlab.sh or actors.mlab.sh).
 */
export async function mlabPublicApiRequest(
	this: IExecuteFunctions | ILoadOptionsFunctions,
	baseUrl: string,
	method: IHttpRequestMethods,
	resource: string,
	qs: IDataObject = {},
	option: Partial<IHttpRequestOptions> = {},
): Promise<any> {
	const options: IHttpRequestOptions = {
		method,
		url: `${baseUrl.replace(/\/$/, '')}${resource}`,
		json: true,
	};

	if (Object.keys(qs).length > 0) {
		options.qs = qs;
	}

	Object.assign(options, option);

	try {
		return await this.helpers.httpRequest(options);
	} catch (error) {
		throw new NodeApiError(this.getNode(), error as JsonObject);
	}
}

/**
 * Poll a domain scan until it reaches the `success` state (or times out).
 * Returns the final results payload.
 */
export async function pollDomainScan(
	this: IExecuteFunctions,
	domain: string,
	maxAttempts = 30,
	intervalMs = 4000,
): Promise<IDataObject> {
	for (let attempt = 0; attempt < maxAttempts; attempt++) {
		const status = (await mlabCoreApiRequest.call(this, 'GET', '/scan/domain/status', {}, {
			domain,
		})) as IDataObject;

		const state = (status.status ?? status.state) as string | undefined;
		if (state === 'success') {
			return (await mlabCoreApiRequest.call(this, 'GET', '/scan/domain/results', {}, {
				domain,
			})) as IDataObject;
		}
		if (state === 'error') {
			throw new NodeApiError(this.getNode(), status as JsonObject, {
				message: `Domain scan failed for "${domain}"`,
			});
		}
		await sleep(intervalMs);
	}

	throw new NodeApiError(
		this.getNode(),
		{ message: 'timeout' },
		{
			message: `Domain scan for "${domain}" did not finish within ${
				(maxAttempts * intervalMs) / 1000
			}s. Try the "Get Results" operation later.`,
		},
	);
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
