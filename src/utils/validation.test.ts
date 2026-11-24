import assert from 'node:assert/strict';
import test from 'node:test';
import { formatFileSize, validateClientFile, validateClientUrl } from './validation.ts';

test('formatFileSize formats bytes, KB, and MB cleanly', () => {
  assert.equal(formatFileSize(512), '512 B');
  assert.equal(formatFileSize(2048), '2.0 KB');
  assert.equal(formatFileSize(5 * 1024 * 1024), '5.00 MB');
});

test('validateClientUrl accepts HTTP/HTTPS, normalizes bare domains, and blocks SSRF/invalid inputs', () => {
  assert.equal(validateClientUrl('https://example.org/test').valid, true);
  assert.equal(validateClientUrl('example.org/test').normalizedInput, 'https://example.org/test');
  assert.equal(validateClientUrl('ftp://example.org').errorCode, 'INVALID_URL');
  assert.equal(validateClientUrl('http://localhost:3000').errorCode, 'SSRF_BLOCKED');
  assert.equal(validateClientUrl('http://127.0.0.1/admin').errorCode, 'SSRF_BLOCKED');
  assert.equal(validateClientUrl('127.0.0.1/admin').errorCode, 'INVALID_URL');
});

test('validateClientFile checks presence, size limits, and extensions', () => {
  assert.equal(validateClientFile(null).errorCode, 'NO_FILE');

  const validPdf = new File([new Uint8Array([0x25, 0x50, 0x44, 0x46])], 'doc.pdf');
  assert.equal(validateClientFile(validPdf).valid, true);

  const emptyFile = new File([], 'empty.pdf');
  assert.equal(validateClientFile(emptyFile).errorCode, 'CORRUPTED_FILE');

  const badExt = new File([new Uint8Array([1, 2, 3])], 'script.exe');
  assert.equal(validateClientFile(badExt).errorCode, 'UNSUPPORTED_FILE');
});
