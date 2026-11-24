import type { ScanResponse, ThreatDetail } from './types.ts';

const WEBRISK_ENDPOINT = 'https://webrisk.googleapis.com/v1/uris:search';
const WEBRISK_CATEGORIES = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'] as const;
const DEFAULT_TIMEOUT_MS = 10_000;

interface WebRiskApiResponse {
  threat?: {
    threatTypes?: string[];
    expireTime?: string;
  };
  error?: {
    code?: number;
    message?: string;
    status?: string;
  };
}

function describeThreatType(threatType: string): string {
  switch (threatType) {
    case 'MALWARE':
      return 'Malicious software (malware) distribution or infection risk';
    case 'SOCIAL_ENGINEERING':
      return 'Phishing or deceptive social engineering site';
    case 'UNWANTED_SOFTWARE':
      return 'Potentially unwanted or deceptive software downloads';
    default:
      return `Security threat flagged by Web Risk (${threatType})`;
  }
}

function getCleanApiKey(): string {
  let raw = (process.env.WEBRISK_API_KEY?.trim() || '').replace(/^["']|["']$/g, '').trim();
  raw = raw.replace(/^WEBRISK_API_KEY\s*=\s*/i, '').trim();
  raw = raw.replace(/^Bearer\s+/i, '').trim();
  return raw.replace(/^["']|["']$/g, '').trim();
}

export function isWebRiskConfigured(): boolean {
  const apiKey = getCleanApiKey();
  return Boolean(
    apiKey &&
      apiKey !== 'MY_WEBRISK_API_KEY' &&
      apiKey !== 'YOUR_API_KEY' &&
      apiKey !== 'YOUR_WEBRISK_API_KEY',
  );
}

export async function scanUrlWithWebRisk(
  normalizedUrl: string,
  fetchFn: typeof fetch = fetch,
): Promise<ScanResponse> {
  const timestamp = new Date().toISOString();
  const scannerName = 'Google Web Risk Lookup API';
  const categoriesChecked = [...WEBRISK_CATEGORIES];

  if (!isWebRiskConfigured()) {
    return {
      status: 'unavailable',
      scanType: 'url',
      scannedItem: normalizedUrl,
      scannerName,
      timestamp,
      categoriesChecked,
      error: {
        code: 'SERVICE_UNCONFIGURED',
        message:
          'Google Web Risk Lookup API is not configured on the server (missing WEBRISK_API_KEY).',
      },
    };
  }

  const apiKey = getCleanApiKey();
  const requestUrl = new URL(WEBRISK_ENDPOINT);
  requestUrl.searchParams.set('uri', normalizedUrl);
  for (const threatType of WEBRISK_CATEGORIES) {
    requestUrl.searchParams.append('threatTypes', threatType);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const response = await fetchFn(requestUrl.toString(), {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-Goog-Api-Key': apiKey,
      },
      signal: controller.signal,
    });

    if (response.status === 429) {
      return {
        status: 'unavailable',
        scanType: 'url',
        scannedItem: normalizedUrl,
        scannerName,
        timestamp,
        categoriesChecked,
        error: {
          code: 'API_QUOTA_EXCEEDED',
          message: 'The link reputation service has temporarily reached its usage limit. Please try again later.',
        },
      };
    }

    if (!response.ok) {
      let safeReason = `HTTP ${response.status}`;
      let mappedCode: 'API_KEY_INVALID' | 'SERVICE_UNAVAILABLE' | 'API_ERROR' =
        response.status >= 500 ? 'SERVICE_UNAVAILABLE' : 'API_ERROR';

      try {
        const errPayload = (await response.json()) as WebRiskApiResponse;
        const msg = errPayload.error?.message || '';
        const statusText = errPayload.error?.status || '';
        if (msg.toLowerCase().includes('api key not valid')) {
          mappedCode = 'API_KEY_INVALID';
          safeReason = 'The configured Web Risk API key is invalid.';
        } else if (statusText === 'PERMISSION_DENIED') {
          safeReason = 'Web Risk API permission denied for this API key or project.';
        } else if (msg) {
          safeReason = msg.slice(0, 160);
        }
      } catch {
        // Non-JSON error body
      }

      return {
        status: 'unavailable',
        scanType: 'url',
        scannedItem: normalizedUrl,
        scannerName,
        timestamp,
        categoriesChecked,
        error: {
          code: mappedCode,
          message: `The link reputation service could not process this request (${safeReason}).`,
        },
      };
    }

    const payload = (await response.json()) as WebRiskApiResponse;

    if (payload.threat && Array.isArray(payload.threat.threatTypes) && payload.threat.threatTypes.length > 0) {
      const threats: ThreatDetail[] = payload.threat.threatTypes.map((type) => ({
        type,
        description: describeThreatType(type),
        expireTime: payload.threat?.expireTime,
      }));

      return {
        status: 'threat',
        scanType: 'url',
        scannedItem: normalizedUrl,
        scannerName,
        timestamp,
        categoriesChecked,
        threats,
        technicalDetails: {
          threatTypes: payload.threat.threatTypes.join(', '),
          ...(payload.threat.expireTime ? { cacheExpiration: payload.threat.expireTime } : {}),
          apiResponse: 'Threat match returned by Google Web Risk',
        },
      };
    }

    return {
      status: 'clean',
      scanType: 'url',
      scannedItem: normalizedUrl,
      scannerName,
      timestamp,
      categoriesChecked,
      technicalDetails: {
        apiResponse: 'No matching entries found in Web Risk threat lists',
      },
    };
  } catch (err) {
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return {
      status: 'unavailable',
      scanType: 'url',
      scannedItem: normalizedUrl,
      scannerName,
      timestamp,
      categoriesChecked,
      error: {
        code: isTimeout ? 'TIMEOUT' : 'SERVICE_UNAVAILABLE',
        message: isTimeout
          ? 'The link reputation check timed out before the security service responded.'
          : 'Unable to reach the Google Web Risk Lookup service.',
      },
    };
  } finally {
    clearTimeout(timeoutId);
  }
}
