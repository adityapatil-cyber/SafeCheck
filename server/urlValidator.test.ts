import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isPrivateOrReservedIp,
  validateAndNormalizeUrl,
  verifyPublicHostnameDns,
} from './urlValidator.ts';

test('accepts and normalizes valid HTTP and HTTPS URLs', () => {
  const httpsRes = validateAndNormalizeUrl('  https://Example.COM/login?next=1#frag  ');
  assert.equal(httpsRes.valid, true);
  assert.equal(httpsRes.normalizedUrl, 'https://example.com/login?next=1');
  assert.equal(httpsRes.hostname, 'example.com');

  const httpRes = validateAndNormalizeUrl('http://sub.domain.org/path');
  assert.equal(httpRes.valid, true);
  assert.equal(httpRes.normalizedUrl, 'http://sub.domain.org/path');
});

test('rejects non-HTTP/HTTPS schemes and malformed URLs', () => {
  for (const bad of [
    '',
    '   ',
    'ftp://example.com/file.zip',
    'javascript:alert(1)',
    'file:///etc/passwd',
    'not-a-url',
    'https://user:pass@example.com',
    'https://intranet',
    'https://example.com/hello world',
  ]) {
    const res = validateAndNormalizeUrl(bad);
    assert.equal(res.valid, false, `Expected ${bad} to be invalid`);
    assert.equal(res.errorCode, 'INVALID_URL');
  }
});

test('blocks localhost, metadata, and private IPv4/IPv6 addresses (SSRF protection)', () => {
  for (const ssrfUrl of [
    'http://localhost:3000/admin',
    'http://127.0.0.1:8080/health',
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://10.0.0.5/internal',
    'http://172.16.12.1/',
    'http://192.168.1.1/',
    'http://0.0.0.0/',
    'http://[::1]/',
    'http://[fe80::1]/',
  ]) {
    const res = validateAndNormalizeUrl(ssrfUrl);
    assert.equal(res.valid, false, `Expected SSRF target ${ssrfUrl} to be blocked`);
    assert.equal(res.errorCode, 'SSRF_BLOCKED');
  }
});

test('isPrivateOrReservedIp detects IPv4-mapped IPv6 loopback and private ranges', () => {
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:7f00:0001'), true);
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
  assert.equal(isPrivateOrReservedIp('2606:4700:4700::1111'), false);
});

test('verifyPublicHostnameDns blocks domains resolving to private IPs', async () => {
  const blocked = await verifyPublicHostnameDns('evil-rebind.example', (async () => [
    { address: '127.0.0.1', family: 4 },
  ]) as never);
  assert.equal(blocked.safe, false);

  const allowed = await verifyPublicHostnameDns('public.example', (async () => [
    { address: '93.184.216.34', family: 4 },
  ]) as never);
  assert.equal(allowed.safe, true);
});
