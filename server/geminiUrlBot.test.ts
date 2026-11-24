import assert from 'node:assert/strict';
import test from 'node:test';
import {
  extractSafeGroundingSources,
  parseBotVerdictJson,
  scanUrlWithAiBot,
  type GeminiClientLike,
} from './geminiUrlBot.ts';
import {
  analyzeUrlStructure,
  checkCloudflareSecurityDns,
  checkDomainRdapAge,
  checkGooglePublicDns,
  checkOpenPhishFeed,
  resetPublicFeedCacheForTests,
} from './publicThreatFeeds.ts';

test('parseBotVerdictJson parses fenced JSON and rejects invalid payloads', () => {
  const valid = parseBotVerdictJson(
    '```json\n{"verdict":"warning","summary":"Lookalike domain risk.","findings":["Resembles a bank domain"],"detectedCategories":["SUSPICIOUS_REPUTATION","UNKNOWN"]}\n```',
  );
  assert.ok(valid);
  assert.equal(valid.verdict, 'warning');
  assert.equal(valid.summary, 'Lookalike domain risk.');
  assert.deepEqual(valid.findings, ['Resembles a bank domain']);
  assert.deepEqual(valid.detectedCategories, ['SUSPICIOUS_REPUTATION']);

  assert.equal(parseBotVerdictJson('not json at all'), null);
  assert.equal(parseBotVerdictJson('{"verdict":"unknown","summary":"x"}'), null);
});

test('extractSafeGroundingSources keeps http/https links and blocks javascript/data URIs', () => {
  const sources = extractSafeGroundingSources({
    text: '{}',
    candidates: [
      {
        groundingMetadata: {
          groundingChunks: [
            { web: { uri: 'https://www.virustotal.com/gui/domain/example.com', title: 'VirusTotal' } },
            { web: { uri: 'javascript:alert(1)', title: 'Evil' } },
            { web: { uri: 'data:text/html,hi', title: 'Data' } },
            { web: { uri: 'https://www.virustotal.com/gui/domain/example.com', title: 'Duplicate' } },
            { web: { uri: 'https://www.scamadviser.com/check-website/example.com', title: 'ScamAdviser' } },
          ],
        },
      },
    ],
  });

  assert.deepEqual(sources, [
    { title: 'VirusTotal', url: 'https://www.virustotal.com/gui/domain/example.com' },
    { title: 'ScamAdviser', url: 'https://www.scamadviser.com/check-website/example.com' },
  ]);
});

test('OpenPhish feed check matches dedicated phishing hosts while protecting shared hosting domains', async () => {
  resetPublicFeedCacheForTests();
  const mockFetch: typeof fetch = async (input) => {
    if (String(input).includes('openphish.com')) {
      return new Response(
        [
          'https://bad-phish-login.example/signin',
          'https://attacker.github.io/fake-bank/login',
        ].join('\n'),
        { status: 200 },
      );
    }
    return new Response('{}', { status: 404 });
  };

  const exactMatch = await checkOpenPhishFeed(
    'https://bad-phish-login.example/other',
    'bad-phish-login.example',
    mockFetch,
  );
  assert.equal(exactMatch.checked, true);
  assert.equal(exactMatch.matched, true);
  assert.equal(exactMatch.matchType, 'domain');

  const sharedHostSafe = await checkOpenPhishFeed(
    'https://legit-org.github.io/docs',
    'legit-org.github.io',
    mockFetch,
  );
  assert.equal(sharedHostSafe.checked, true);
  assert.equal(sharedHostSafe.matched, false);

  const sharedHostExact = await checkOpenPhishFeed(
    'https://attacker.github.io/fake-bank/login',
    'attacker.github.io',
    mockFetch,
  );
  assert.equal(sharedHostExact.matched, true);
  assert.equal(sharedHostExact.matchType, 'exact_url');
});

test('checkGooglePublicDns, checkCloudflareSecurityDns, checkDomainRdapAge, and analyzeUrlStructure inspect metadata safely', async () => {
  resetPublicFeedCacheForTests();
  const mockFetch: typeof fetch = async (input) => {
    const urlStr = String(input);
    if (urlStr.includes('security.cloudflare-dns.com') && urlStr.includes('malware.test')) {
      return new Response(
        JSON.stringify({
          Status: 0,
          Answer: [{ data: '0.0.0.0', type: 1 }],
          Comment: ['EDE(16): Censored'],
        }),
        { status: 200 },
      );
    }
    if (urlStr.includes('data.iana.org/rdap/dns.json')) {
      return new Response(
        JSON.stringify({
          services: [[['com'], ['https://rdap.verisign.com/com/v1/']]],
        }),
        { status: 200 },
      );
    }
    if (urlStr.includes('rdap.verisign.com/com/v1/domain/example.com')) {
      return new Response(
        JSON.stringify({
          events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }],
        }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify({ Status: 0, Answer: [{ data: '93.184.216.34', type: 1 }] }), {
      status: 200,
    });
  };

  const dnsResult = await checkGooglePublicDns('example.com', mockFetch);
  assert.equal(dnsResult.checked, true);
  assert.equal(dnsResult.resolves, true);
  assert.equal(dnsResult.hasPrivateAnswer, false);

  const cfBlocked = await checkCloudflareSecurityDns('malware.test', mockFetch);
  assert.equal(cfBlocked.checked, true);
  assert.equal(cfBlocked.blocked, true);

  const rdap = await checkDomainRdapAge('sub.example.com', mockFetch);
  assert.equal(rdap.checked, true);
  assert.equal(rdap.registrableDomain, 'example.com');
  assert.equal(rdap.registrationDate, '1995-08-14');
  assert.ok((rdap.domainAgeDays ?? 0) > 1000);

  const structure = analyzeUrlStructure('http://xn--p1ai.example.com/update.apk', 'xn--p1ai.example.com');
  assert.equal(structure.usesPlainHttp, true);
  assert.equal(structure.isPunycode, true);
  assert.equal(structure.hasSuspiciousDownloadExt, true);
});

test('scanUrlWithAiBot never lets LLM downgrade a confirmed OpenPhish threat match', async () => {
  resetPublicFeedCacheForTests();
  const mockFetch: typeof fetch = async (input) => {
    const url = String(input);
    if (url.includes('openphish.com')) {
      return new Response('https://confirmed-phish.example/login\n', { status: 200 });
    }
    return new Response(JSON.stringify({ Status: 0, Answer: [{ data: '203.0.113.10', type: 1 }] }), {
      status: 200,
    });
  };

  const naiveAiClient: GeminiClientLike = {
    models: {
      generateContent: async () => ({
        text: JSON.stringify({
          verdict: 'clean',
          summary: 'No complaints found in web search.',
          findings: ['No web search articles found'],
          detectedCategories: [],
        }),
        candidates: [
          {
            groundingMetadata: {
              groundingChunks: [
                { web: { uri: 'https://transparencyreport.google.com/', title: 'Google Transparency Report' } },
              ],
            },
          },
        ],
      }),
    },
  };

  const result = await scanUrlWithAiBot({
    normalizedUrl: 'https://confirmed-phish.example/login',
    hostname: 'confirmed-phish.example',
    language: 'en',
    fetchFn: mockFetch,
    aiClient: naiveAiClient,
  });

  assert.equal(result.status, 'threat');
  assert.equal(result.threats?.[0]?.type, 'SOCIAL_ENGINEERING');
  assert.ok(result.botAnalysis?.sources.length === 1);
});

test('scanUrlWithAiBot uses live Cloudflare Security DNS + OpenPhish + RDAP if Gemini hits 429 quota', async () => {
  resetPublicFeedCacheForTests();
  const mockFetch: typeof fetch = async (input) => {
    const urlStr = String(input);
    if (urlStr.includes('openphish.com')) {
      return new Response('', { status: 200 });
    }
    if (urlStr.includes('security.cloudflare-dns.com') && urlStr.includes('malware.test')) {
      return new Response(
        JSON.stringify({
          Status: 0,
          Answer: [{ data: '0.0.0.0', type: 1 }],
          Comment: ['EDE(16): Censored'],
        }),
        { status: 200 },
      );
    }
    if (urlStr.includes('dns.google') || urlStr.includes('security.cloudflare-dns.com')) {
      return new Response(JSON.stringify({ Status: 0, Answer: [{ data: '93.184.216.34', type: 1 }] }), {
        status: 200,
      });
    }
    return new Response('', { status: 404 });
  };

  const quotaErrorAiClient: GeminiClientLike = {
    models: {
      generateContent: async () => {
        throw new Error('429 RESOURCE_EXHAUSTED');
      },
    },
  };

  const blockedRes = await scanUrlWithAiBot({
    normalizedUrl: 'https://malware.test/',
    hostname: 'malware.test',
    language: 'en',
    fetchFn: mockFetch,
    aiClient: quotaErrorAiClient,
  });
  assert.equal(blockedRes.status, 'threat');
  assert.equal(blockedRes.threats?.[0]?.type, 'MALWARE');

  const cleanRes = await scanUrlWithAiBot({
    normalizedUrl: 'https://example.com/',
    hostname: 'example.com',
    language: 'en',
    fetchFn: mockFetch,
    aiClient: quotaErrorAiClient,
  });
  assert.equal(cleanRes.status, 'clean');
  assert.ok(cleanRes.botAnalysis?.feedsChecked.includes('Cloudflare Security DNS (1.1.1.2)'));
});
