import type {
	IExecuteFunctions,
	IDataObject,
	IHttpRequestMethods,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, sleep } from 'n8n-workflow';
import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Public base URLs for the three mlab.sh services. The core API base URL can be
 * overridden per credential (for self-hosted setups); the vuln and actors APIs
 * are public and unauthenticated.
 */
export const MLAB_CVE_BASE_URL = 'https://vuln.mlab.sh/api/v1';
export const MLAB_ACTORS_BASE_URL = 'https://actors.mlab.sh/api/v1';

// Credentials are decrypted on every getCredentials call; the base URL cannot
// change during one execution, so read it once per execution context.
const baseUrlCache = new WeakMap<object, string>();

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
	let baseUrl = baseUrlCache.get(this);
	if (baseUrl === undefined) {
		const credentials = await this.getCredentials('mlabApi');
		baseUrl = ((credentials.baseUrl as string) || 'https://mlab.sh/api/v1').replace(/\/$/, '');
		baseUrlCache.set(this, baseUrl);
	}
	// The upload endpoint lives at the site root, not under /api/v1.
	if (resource.startsWith('/upload/')) baseUrl = baseUrl.replace(/\/api\/v1$/, '');

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
	// Read the headers too, for the quota a key call reports. Not on the
	// multipart upload, whose caller handles the raw response itself.
	const full = option.body === undefined;
	if (full) options.returnFullResponse = true;

	let response: any;
	try {
		response = await this.helpers.httpRequestWithAuthentication.call(this, 'mlabApi', options);
	} catch (error) {
		throw explainError(this, error);
	}
	if (!full) return response;

	const payload = response.body;
	const rateLimit = readRateLimit(response.headers ?? {});
	if (rateLimit && payload && typeof payload === 'object' && !Array.isArray(payload)) {
		return { ...payload, rateLimit };
	}
	return payload;
}

/**
 * The `X-RateLimit-*` headers mlab.sh sets on every scan made with a key, as
 * one object, or undefined when the call reported no quota.
 */
export function readRateLimit(headers: IDataObject): IDataObject | undefined {
	const h = (name: string) => headers[name] ?? headers[name.toLowerCase()];
	const limit = h('X-RateLimit-Limit');
	if (limit === undefined) return undefined;
	return {
		limit: Number(limit),
		remaining: Number(h('X-RateLimit-Remaining')),
		resource: h('X-RateLimit-Resource'),
		windowSeconds: Number(h('X-RateLimit-Window')),
	};
}

/** Turn a failed call into an error that says what to do about it. */
function explainError(ctx: IExecuteFunctions | ILoadOptionsFunctions, error: any): NodeApiError {
	const code = Number(error?.httpCode ?? error?.response?.status ?? error?.statusCode ?? 0);
	if (code === 401) {
		return new NodeApiError(ctx.getNode(), error as JsonObject, {
			httpCode: '401',
			message: 'mlab.sh refused the API key: it is unknown, revoked or expired',
			description:
				'API keys expire after 90 days by default. Create a new one in Organization settings → API keys on mlab.sh and update the mlab.sh API credential.',
		});
	}
	if (code === 429) {
		return new NodeApiError(ctx.getNode(), error as JsonObject, {
			httpCode: '429',
			message: 'The mlab.sh quota for this scan type is spent',
			description:
				'The quota is a rolling 24-hour window. Check it with the Quota resource, or wait for older scans to age out.',
		});
	}
	return new NodeApiError(ctx.getNode(), error as JsonObject);
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
 * Verify an mlab.sh webhook delivery: `X-Mlab-Signature` is
 * `sha256=` + hex HMAC-SHA256(secret, "<timestamp>.<raw body>"), and the
 * timestamp must sit within `toleranceSeconds` of now. Returns why it was
 * refused, or undefined when it holds.
 */
export function verifyWebhookSignature(
	secret: string,
	rawBody: Buffer | string,
	signature: string | undefined,
	timestamp: string | undefined,
	toleranceSeconds: number,
	nowSeconds = Math.floor(Date.now() / 1000),
): string | undefined {
	if (!signature || !timestamp) return 'missing X-Mlab-Signature or X-Mlab-Timestamp';
	const ts = Number(timestamp);
	if (!Number.isInteger(ts)) return 'invalid X-Mlab-Timestamp';
	if (toleranceSeconds > 0 && Math.abs(nowSeconds - ts) > toleranceSeconds) return 'timestamp outside the tolerance';
	const expected = Buffer.from(
		'sha256=' + createHmac('sha256', secret).update(`${timestamp}.`).update(rawBody).digest('hex'),
	);
	const got = Buffer.from(signature.trim());
	if (got.length !== expected.length || !timingSafeEqual(got, expected)) return 'signature mismatch';
	return undefined;
}

/**
 * Poll a domain scan until it reaches the `success` state (or times out).
 * Returns the v2 report or the legacy v1 results, per `output`.
 */
export async function pollDomainScan(
	this: IExecuteFunctions,
	domain: string,
	output: 'report' | 'results',
	maxAttempts = 30,
	intervalMs = 4000,
): Promise<IDataObject> {
	for (let attempt = 0; attempt < maxAttempts; attempt++) {
		const status = (await mlabCoreApiRequest.call(this, 'GET', '/scan/domain/status', {}, {
			domain,
		})) as IDataObject;

		const state = (status.status ?? status.state) as string | undefined;
		if (state === 'success') {
			const payload = (await mlabCoreApiRequest.call(this, 'GET', `/scan/domain/${output}`, {}, {
				domain,
			})) as IDataObject;
			// The status route reports any finished scan as `success`; only the v2
			// report tells a failed scan apart.
			if (payload.status === 'failed') {
				throw new NodeApiError(this.getNode(), payload as JsonObject, {
					message: `Domain scan failed for "${domain}"`,
				});
			}
			return payload;
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
