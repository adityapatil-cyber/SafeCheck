import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createApp } from './app.ts';
import type { HealthResponse, ScanResponse } from './types.ts';

async function startTestServer(options: Parameters<typeof createApp>[0] = {}) {
  const app = createApp({ enableRateLimit: false, ...options });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('Failed to bind test server');
  }
  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}

test('GET /api/health reports unconfigured scanners honestly without exposing secrets', async () => {
  const prevWebRisk = process.env.WEBRISK_API_KEY;
  const prevGemini = process.env.GEMINI_API_KEY;
  const prevClam = process.env.CLAMAV_SCANNER_URL;
  delete process.env.WEBRISK_API_KEY;
  delete process.env.GEMINI_API_KEY;
  delete process.env.CLAMAV_SCANNER_URL;

  const srv = await startTestServer();
  try {
    const res = await fetch(`${srv.baseUrl}/api/health`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as HealthResponse;
    assert.equal(body.status, 'degraded');
    assert.equal(body.services.webRisk.configured, false);
    assert.equal(body.services.geminiBot.configured, false);
    assert.equal(body.services.clamav.configured, false);
  } finally {
    await srv.close();
    if (prevWebRisk !== undefined) process.env.WEBRISK_API_KEY = prevWebRisk;
    if (prevGemini !== undefined) process.env.GEMINI_API_KEY = prevGemini;
    if (prevClam !== undefined) process.env.CLAMAV_SCANNER_URL = prevClam;
  }
});

test('POST /api/scan/url rejects invalid/SSRF URLs and never fakes clean when all scanners are unconfigured', async () => {
  const prevWebRisk = process.env.WEBRISK_API_KEY;
  const prevGemini = process.env.GEMINI_API_KEY;
  delete process.env.WEBRISK_API_KEY;
  delete process.env.GEMINI_API_KEY;

  const offlineFetch: typeof fetch = async () => new Response('', { status: 503 });
  const srv = await startTestServer({ fetchFn: offlineFetch });
  try {
    const invalidRes = await fetch(`${srv.baseUrl}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://127.0.0.1/secret' }),
    });
    assert.equal(invalidRes.status, 400);
    const invalidJson = (await invalidRes.json()) as ScanResponse;
    assert.equal(invalidJson.status, 'unavailable');
    assert.equal(invalidJson.error?.code, 'SSRF_BLOCKED');

    const unconfigRes = await fetch(`${srv.baseUrl}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com' }),
    });
    assert.equal(unconfigRes.status, 200);
    const unconfigJson = (await unconfigRes.json()) as ScanResponse;
    assert.equal(unconfigJson.status, 'unavailable');
    assert.equal(unconfigJson.error?.code, 'SERVICE_UNCONFIGURED');
  } finally {
    await srv.close();
    if (prevWebRisk !== undefined) process.env.WEBRISK_API_KEY = prevWebRisk;
    if (prevGemini !== undefined) process.env.GEMINI_API_KEY = prevGemini;
  }
});

test('POST /api/scan/url parses Web Risk results and falls back to AI Security Bot when Web Risk key is rejected', async () => {
  const prevWebRisk = process.env.WEBRISK_API_KEY;
  process.env.WEBRISK_API_KEY = 'WEBRISK_API_KEY="test-only-key"';

  let mockMode: 'clean' | 'threat' | 'quota' | 'invalidKey' = 'clean';
  let observedHeaderKey = '';
  const mockFetch: typeof fetch = async (input, init) => {
    const urlStr = String(input);
    if (urlStr.includes('webrisk.googleapis.com')) {
      const headers = new Headers(init?.headers);
      observedHeaderKey = headers.get('X-Goog-Api-Key') || '';
      if (mockMode === 'invalidKey') {
        return new Response(
          JSON.stringify({
            error: {
              code: 400,
              message: 'API key not valid. Please pass a valid API key.',
              status: 'INVALID_ARGUMENT',
            },
          }),
          { status: 400 },
        );
      }
      if (mockMode === 'quota') {
        return new Response(JSON.stringify({ error: { code: 429 } }), { status: 429 });
      }
      if (mockMode === 'threat') {
        return new Response(
          JSON.stringify({
            threat: {
              threatTypes: ['SOCIAL_ENGINEERING'],
              expireTime: '2026-11-24T13:00:00Z',
            },
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }
    if (urlStr.includes('openphish.com')) {
      return new Response('', { status: 200 });
    }
    if (urlStr.includes('dns.google')) {
      return new Response(JSON.stringify({ Status: 0, Answer: [{ data: '93.184.216.34', type: 1 }] }), {
        status: 200,
      });
    }
    return new Response('', { status: 404 });
  };

  const mockAiClient = {
    models: {
      generateContent: async () => ({
        text: JSON.stringify({
          verdict: 'warning',
          summary: 'Third-party reputation sources report mixed trust signals for this domain.',
          findings: ['Found user caution reports on third-party sites'],
          detectedCategories: ['SUSPICIOUS_REPUTATION'],
        }),
        candidates: [
          {
            groundingMetadata: {
              groundingChunks: [
                { web: { uri: 'https://www.scamadviser.com/check-website/example.com', title: 'ScamAdviser' } },
              ],
            },
          },
        ],
      }),
    },
  };

  const srv = await startTestServer({ fetchFn: mockFetch, aiClient: mockAiClient });
  try {
    const cleanRes = await fetch(`${srv.baseUrl}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com' }),
    });
    assert.equal(cleanRes.status, 200);
    assert.equal(observedHeaderKey, 'test-only-key');
    const cleanJson = (await cleanRes.json()) as ScanResponse;
    assert.equal(cleanJson.status, 'clean');

    mockMode = 'threat';
    const threatRes = await fetch(`${srv.baseUrl}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://phish.example.com' }),
    });
    const threatJson = (await threatRes.json()) as ScanResponse;
    assert.equal(threatJson.status, 'threat');
    assert.equal(threatJson.threats?.[0]?.type, 'SOCIAL_ENGINEERING');

    mockMode = 'invalidKey';
    const fallbackRes = await fetch(`${srv.baseUrl}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://suspicious-lookalike.example', language: 'en' }),
    });
    const fallbackJson = (await fallbackRes.json()) as ScanResponse;
    assert.equal(fallbackJson.status, 'warning');
    assert.ok(fallbackJson.botAnalysis);
    assert.equal(fallbackJson.botAnalysis.sources[0]?.title, 'ScamAdviser');
    assert.equal(fallbackJson.technicalDetails?.webRiskStatus, 'API_KEY_INVALID');
  } finally {
    await srv.close();
    if (prevWebRisk !== undefined) {
      process.env.WEBRISK_API_KEY = prevWebRisk;
    } else {
      delete process.env.WEBRISK_API_KEY;
    }
  }
});

test('POST /api/scan/file deletes temporary files on success, unsupported format, and unconfigured ClamAV', async () => {
  const tempUploadDir = await fs.mkdtemp(path.join(os.tmpdir(), 'safecheck-test-uploads-'));
  const prevClamUrl = process.env.CLAMAV_SCANNER_URL;
  delete process.env.CLAMAV_SCANNER_URL;

  let clamResponseMode: 'clean' | 'infected' = 'clean';
  const mockFetch: typeof fetch = async (input) => {
    const urlStr = String(input);
    if (urlStr.endsWith('/scan')) {
      if (clamResponseMode === 'infected') {
        return new Response(
          JSON.stringify({ status: 'infected', signature: 'Eicar-Test-Signature', engine: 'ClamAV' }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ status: 'clean', signature: null, engine: 'ClamAV' }), {
        status: 200,
      });
    }
    return new Response('ok', { status: 200 });
  };

  const srv = await startTestServer({ uploadDir: tempUploadDir, fetchFn: mockFetch });
  try {
    // 1. Unsupported binary disguised as .txt
    const badForm = new FormData();
    badForm.append('file', new Blob([Buffer.from([0x4d, 0x5a, 0x00, 0x01])]), 'evil.txt');
    const badRes = await fetch(`${srv.baseUrl}/api/scan/file`, { method: 'POST', body: badForm });
    assert.equal(badRes.status, 400);
    const badJson = (await badRes.json()) as ScanResponse;
    assert.equal(badJson.error?.code, 'UNSUPPORTED_FILE');
    assert.equal((await fs.readdir(tempUploadDir)).length, 0);

    // 2. Valid PDF when ClamAV is unconfigured -> honest unavailable
    const pdfForm = new FormData();
    pdfForm.append('file', new Blob([Buffer.from('%PDF-1.5\n%%EOF\n')]), 'doc.pdf');
    const unconfRes = await fetch(`${srv.baseUrl}/api/scan/file`, { method: 'POST', body: pdfForm });
    assert.equal(unconfRes.status, 200);
    const unconfJson = (await unconfRes.json()) as ScanResponse;
    assert.equal(unconfJson.status, 'unavailable');
    assert.equal(unconfJson.error?.code, 'SERVICE_UNCONFIGURED');
    assert.equal((await fs.readdir(tempUploadDir)).length, 0);

    // 3. Configured ClamAV clean + infected
    process.env.CLAMAV_SCANNER_URL = 'https://clamav.internal.run.app';
    const cleanForm = new FormData();
    cleanForm.append('file', new Blob([Buffer.from('%PDF-1.5\n%%EOF\n')]), 'clean.pdf');
    const cleanRes = await fetch(`${srv.baseUrl}/api/scan/file`, { method: 'POST', body: cleanForm });
    assert.equal(cleanRes.status, 200);
    const cleanJson = (await cleanRes.json()) as ScanResponse;
    assert.equal(cleanJson.status, 'clean');
    assert.equal((await fs.readdir(tempUploadDir)).length, 0);

    clamResponseMode = 'infected';
    const infForm = new FormData();
    infForm.append('file', new Blob([Buffer.from('EICAR-TEST-TEXT')]), 'eicar.txt');
    const infRes = await fetch(`${srv.baseUrl}/api/scan/file`, { method: 'POST', body: infForm });
    assert.equal(infRes.status, 200);
    const infJson = (await infRes.json()) as ScanResponse;
    assert.equal(infJson.status, 'threat');
    assert.match(infJson.threats?.[0]?.description || '', /Eicar-Test-Signature/);
    assert.equal((await fs.readdir(tempUploadDir)).length, 0);
  } finally {
    await srv.close();
    await fs.rm(tempUploadDir, { recursive: true, force: true });
    if (prevClamUrl !== undefined) {
      process.env.CLAMAV_SCANNER_URL = prevClamUrl;
    } else {
      delete process.env.CLAMAV_SCANNER_URL;
    }
  }
});

test('CORS allows same-origin Cloud Run hosts, blocks third-party origins, and /api returns JSON 404', async () => {
  const srv = await startTestServer();
  try {
    const sameOriginRes = await fetch(`${srv.baseUrl}/api/health`, {
      headers: {
        Origin: 'https://ais-pre-example.run.app',
        'X-Forwarded-Host': 'ais-pre-example.run.app',
      },
    });
    assert.equal(sameOriginRes.status, 200);
    assert.equal(
      sameOriginRes.headers.get('access-control-allow-origin'),
      'https://ais-pre-example.run.app',
    );

    const evilOriginRes = await fetch(`${srv.baseUrl}/api/health`, {
      headers: {
        Origin: 'https://evil-attacker.example',
        'X-Forwarded-Host': 'ais-pre-example.run.app',
      },
    });
    assert.equal(evilOriginRes.status, 403);

    const notFoundRes = await fetch(`${srv.baseUrl}/api/does-not-exist`);
    assert.equal(notFoundRes.status, 404);
    const notFoundJson = (await notFoundRes.json()) as { error?: { code?: string } };
    assert.equal(notFoundJson.error?.code, 'API_ERROR');

    // Ensure AI Studio iframe embedding is never blocked by X-Frame-Options or frame-ancestors 'self'
    assert.equal(sameOriginRes.headers.get('x-frame-options'), null);
    const csp = sameOriginRes.headers.get('content-security-policy') || '';
    assert.equal(csp.includes('frame-ancestors'), false);
  } finally {
    await srv.close();
  }
});
