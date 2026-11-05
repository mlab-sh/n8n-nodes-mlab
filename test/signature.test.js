// Run with `npm test` (builds first). Locks down the webhook signature check and
// the rate-limit header reading against what mlab.sh sends.
const { test } = require('node:test');
const assert = require('node:assert');
const { createHmac } = require('node:crypto');
const { verifyWebhookSignature, readRateLimit } = require('../dist/nodes/shared/GenericFunctions');

const secret = 'whsec_test';
const body = '{"event":"webhook.test","data":{}}';
const now = 1_800_000_000;
const sign = (ts, b = body, s = secret) => 'sha256=' + createHmac('sha256', s).update(`${ts}.${b}`).digest('hex');

test('a delivery signed like mlab.sh signs it passes', () => {
	assert.strictEqual(verifyWebhookSignature(secret, Buffer.from(body), sign(now), String(now), 300, now), undefined);
});

test('a wrong secret, an edited body or a missing header is refused', () => {
	assert.strictEqual(verifyWebhookSignature(secret, body, sign(now, body, 'other'), String(now), 300, now), 'signature mismatch');
	assert.strictEqual(verifyWebhookSignature(secret, body + ' ', sign(now), String(now), 300, now), 'signature mismatch');
	assert.match(verifyWebhookSignature(secret, body, undefined, String(now), 300, now), /missing/);
});

test('an old delivery is refused unless the tolerance is off', () => {
	const old = now - 301;
	assert.strictEqual(verifyWebhookSignature(secret, body, sign(old), String(old), 300, now), 'timestamp outside the tolerance');
	assert.strictEqual(verifyWebhookSignature(secret, body, sign(old), String(old), 0, now), undefined);
});

test('rate-limit headers are read whatever their case', () => {
	assert.deepStrictEqual(
		readRateLimit({ 'x-ratelimit-limit': '100', 'x-ratelimit-remaining': '42', 'x-ratelimit-resource': 'ip', 'x-ratelimit-window': '86400' }),
		{ limit: 100, remaining: 42, resource: 'ip', windowSeconds: 86400 },
	);
	assert.strictEqual(readRateLimit({}), undefined);
});
