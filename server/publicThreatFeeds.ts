import net from 'node:net';
import { isPrivateOrReservedIp } from './urlValidator.ts';

const OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt';
const IANA_RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const FEED_CACHE_TTL_MS = 15 * 60 * 1000;
const RDAP_BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;
const FEED_TIMEOUT_MS = 5_000;
const DNS_TIMEOUT_MS = 4_000;
const RDAP_TIMEOUT_MS = 4_000;
const MAX_FEED_ENTRIES = 50_000;

// Shared hosting/CDN roots where a single malicious page must not flag unrelated subdomains/paths
const SHARED_HOSTING_SUFFIXES = [
  'github.io',
  'sites.google.com',
  'drive.google.com',
  'docs.google.com',
  'blogspot.com',
  'wordpress.com',
  'wixsite.com',
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'workers.dev',
  'firebaseapp.com',
  'web.app',
  'herokuapp.com',
  'azurewebsites.net',
  's3.amazonaws.com',
  'cloudfront.net',
];

const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'co.in',
  'org.in',
  'net.in',
  'gov.in',
  'com.au',
  'net.au',
  'org.au',
  'co.jp',
  'ne.jp',
  'or.jp',
  'com.br',
  'com.mx',
  'co.za',
  'co.nz',
]);

export interface OpenPhishCheckResult {
  checked: boolean;
  matched: boolean;
  matchType?: 'exact_url' | 'domain';
  feedSize: number;
}

export interface DnsCheckResult {
  checked: boolean;
  resolves: boolean;
  dnsStatus?: number;
  answersCount: number;
  hasPrivateAnswer: boolean;
}

export interface CloudflareSecurityDnsResult {
  checked: boolean;
  blocked: boolean;
  resolves: boolean;
  answersCount: number;
  blockReason?: string;
}

export interface RdapDomainResult {
  checked: boolean;
  registrableDomain?: string;
  registrationDate?: string;
  domainAgeDays?: number;
  registrar?: string;
}

export interface UrlStructureSignals {
  usesPlainHttp: boolean;
  isIpLiteral: boolean;
  isPunycode: boolean;
  subdomainDepth: number;
  hasSuspiciousDownloadExt: boolean;
  urlLength: number;
}

interface FeedCache {
  fetchedAt: number;
  exactUrls: Set<string>;
  dedicatedHosts: Set<string>;
}

interface RdapBootstrapCache {
  fetchedAt: number;
  tldToBaseUrl: Map<string, string>;
}

let cachedFeed: FeedCache | null = null;
let inFlightFeedLoad: Promise<FeedCache | null> | null = null;
let cachedRdapBootstrap: RdapBootstrapCache | null = null;
let inFlightRdapBootstrap: Promise<RdapBootstrapCache | null> | null = null;

export function resetPublicFeedCacheForTests(): void {
  cachedFeed = null;
  inFlightFeedLoad = null;
  cachedRdapBootstrap = null;
  inFlightRdapBootstrap = null;
}

function canonicalizeForFeedMatch(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl.trim());
    parsed.hash = '';
    parsed.hostname = parsed.hostname.toLowerCase();
    const str = parsed.toString();
    return parsed.pathname === '/' ? str : str.replace(/\/+$/, '');
  } catch {
    return rawUrl.trim().toLowerCase();
  }
}

function isSharedHostingDomain(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return SHARED_HOSTING_SUFFIXES.some(
    (suffix) => lower === suffix || lower.endsWith(`.${suffix}`),
  );
}

export function extractRegistrableDomain(hostname: string): string {
  const clean = hostname.toLowerCase().replace(/\.$/, '');
  if (net.isIP(clean) !== 0) return clean;
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (MULTI_PART_PUBLIC_SUFFIXES.has(lastTwo) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${lastTwo}`;
  }
  return lastTwo;
}

async function loadOpenPhishFeed(fetchFn: typeof fetch): Promise<FeedCache | null> {
  const now = Date.now();
  if (cachedFeed && now - cachedFeed.fetchedAt < FEED_CACHE_TTL_MS) {
    return cachedFeed;
  }

  if (inFlightFeedLoad) {
    return inFlightFeedLoad;
  }

  inFlightFeedLoad = (async () => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FEED_TIMEOUT_MS);

    try {
      const response = await fetchFn(OPENPHISH_FEED_URL, {
        method: 'GET',
        headers: { Accept: 'text/plain' },
        signal: controller.signal,
      });

      if (!response.ok) {
        return cachedFeed;
      }

      const body = await response.text();
      const lines = body.split(/\r?\n/);
      const exactUrls = new Set<string>();
      const dedicatedHosts = new Set<string>();

      for (const line of lines) {
        if (exactUrls.size >= MAX_FEED_ENTRIES) break;
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        try {
          const parsed = new URL(trimmed);
          const canonical = canonicalizeForFeedMatch(parsed.toString());
          exactUrls.add(canonical);
          const host = parsed.hostname.toLowerCase().replace(/^www\./, '');
          if (host && !isSharedHostingDomain(host)) {
            dedicatedHosts.add(host);
          }
        } catch {
          // Ignore malformed feed lines
        }
      }

      cachedFeed = {
        fetchedAt: Date.now(),
        exactUrls,
        dedicatedHosts,
      };
      return cachedFeed;
    } catch {
      return cachedFeed;
    } finally {
      clearTimeout(timeoutId);
      inFlightFeedLoad = null;
    }
  })();

  return inFlightFeedLoad;
}

export async function checkOpenPhishFeed(
  normalizedUrl: string,
  hostname: string,
  fetchFn: typeof fetch = fetch,
): Promise<OpenPhishCheckResult> {
  const feed = await loadOpenPhishFeed(fetchFn);
  if (!feed) {
    return { checked: false, matched: false, feedSize: 0 };
  }

  const canonical = canonicalizeForFeedMatch(normalizedUrl);
  if (feed.exactUrls.has(canonical)) {
    return {
      checked: true,
      matched: true,
      matchType: 'exact_url',
      feedSize: feed.exactUrls.size,
    };
  }

  const bareHost = hostname.toLowerCase().replace(/^www\./, '');
  if (!isSharedHostingDomain(bareHost) && feed.dedicatedHosts.has(bareHost)) {
    return {
      checked: true,
      matched: true,
      matchType: 'domain',
      feedSize: feed.exactUrls.size,
    };
  }

  return {
    checked: true,
    matched: false,
    feedSize: feed.exactUrls.size,
  };
}

interface DohJson {
  Status?: number;
  Answer?: Array<{ data?: string; type?: number }>;
  Comment?: string[];
}

export async function checkGooglePublicDns(
  hostname: string,
  fetchFn: typeof fetch = fetch,
): Promise<DnsCheckResult> {
  if (net.isIP(hostname) !== 0) {
    return {
      checked: true,
      resolves: true,
      dnsStatus: 0,
      answersCount: 1,
      hasPrivateAnswer: isPrivateOrReservedIp(hostname),
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);

  try {
    const endpoint = new URL('https://dns.google/resolve');
    endpoint.searchParams.set('name', hostname);
    endpoint.searchParams.set('type', 'A');

    const response = await fetchFn(endpoint.toString(), {
      method: 'GET',
      headers: { Accept: 'application/dns-json' },
      signal: controller.signal,
    });

    if (!response.ok) {
      return { checked: false, resolves: false, answersCount: 0, hasPrivateAnswer: false };
    }

    const data = (await response.json()) as DohJson;
    const answers = Array.isArray(data.Answer) ? data.Answer : [];
    const hasPrivateAnswer = answers.some(
      (a) => typeof a.data === 'string' && net.isIP(a.data) !== 0 && isPrivateOrReservedIp(a.data),
    );

    return {
      checked: true,
      resolves: data.Status === 0 && answers.length > 0,
      dnsStatus: data.Status,
      answersCount: answers.length,
      hasPrivateAnswer,
    };
  } catch {
    return { checked: false, resolves: false, answersCount: 0, hasPrivateAnswer: false };
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function checkCloudflareSecurityDns(
  hostname: string,
  fetchFn: typeof fetch = fetch,
): Promise<CloudflareSecurityDnsResult> {
  if (net.isIP(hostname) !== 0) {
    return { checked: false, blocked: false, resolves: true, answersCount: 1 };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);

  try {
    const endpoint = new URL('https://security.cloudflare-dns.com/dns-query');
    endpoint.searchParams.set('name', hostname);
    endpoint.searchParams.set('type', 'A');

    const response = await fetchFn(endpoint.toString(), {
      method: 'GET',
      headers: { Accept: 'application/dns-json' },
      signal: controller.signal,
    });

    if (!response.ok) {
      return { checked: false, blocked: false, resolves: false, answersCount: 0 };
    }

    const data = (await response.json()) as DohJson;
    const answers = Array.isArray(data.Answer) ? data.Answer : [];
    const comments = Array.isArray(data.Comment) ? data.Comment.map((c) => String(c)) : [];
    const hasZeroIp = answers.some((a) => a.data === '0.0.0.0' || a.data === '::');
    const hasCensorComment = comments.some(
      (c) => /censored|blocked|ede\(16\)|malware|phishing/i.test(c),
    );
    const blocked = hasZeroIp || hasCensorComment;

    return {
      checked: true,
      blocked,
      resolves: !blocked && data.Status === 0 && answers.length > 0,
      answersCount: answers.length,
      ...(blocked ? { blockReason: comments[0] || 'Blocked by Cloudflare Security DNS (1.1.1.2)' } : {}),
    };
  } catch {
    return { checked: false, blocked: false, resolves: false, answersCount: 0 };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function loadRdapBootstrap(fetchFn: typeof fetch): Promise<RdapBootstrapCache | null> {
  const now = Date.now();
  if (cachedRdapBootstrap && now - cachedRdapBootstrap.fetchedAt < RDAP_BOOTSTRAP_TTL_MS) {
    return cachedRdapBootstrap;
  }
  if (inFlightRdapBootstrap) {
    return inFlightRdapBootstrap;
  }

  inFlightRdapBootstrap = (async () => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), RDAP_TIMEOUT_MS);

    try {
      const res = await fetchFn(IANA_RDAP_BOOTSTRAP_URL, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      if (!res.ok) return cachedRdapBootstrap;

      const json = (await res.json()) as { services?: Array<[string[], string[]]> };
      const tldToBaseUrl = new Map<string, string>();
      for (const entry of json.services ?? []) {
        const tlds = Array.isArray(entry?.[0]) ? entry[0] : [];
        const urls = Array.isArray(entry?.[1]) ? entry[1] : [];
        const httpsBase = urls.find((u) => typeof u === 'string' && u.startsWith('https://'));
        if (!httpsBase) continue;
        const normalizedBase = httpsBase.endsWith('/') ? httpsBase : `${httpsBase}/`;
        for (const tld of tlds) {
          if (typeof tld === 'string' && tld.trim()) {
            tldToBaseUrl.set(tld.trim().toLowerCase(), normalizedBase);
          }
        }
      }

      cachedRdapBootstrap = { fetchedAt: Date.now(), tldToBaseUrl };
      return cachedRdapBootstrap;
    } catch {
      return cachedRdapBootstrap;
    } finally {
      clearTimeout(timeoutId);
      inFlightRdapBootstrap = null;
    }
  })();

  return inFlightRdapBootstrap;
}

interface RdapResponseJson {
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: Array<{
    roles?: string[];
    vcardArray?: [string, Array<[string, Record<string, unknown>, string, unknown]>];
  }>;
}

export async function checkDomainRdapAge(
  hostname: string,
  fetchFn: typeof fetch = fetch,
): Promise<RdapDomainResult> {
  if (net.isIP(hostname) !== 0) {
    return { checked: false };
  }

  const registrableDomain = extractRegistrableDomain(hostname);
  const tld = registrableDomain.split('.').pop()?.toLowerCase();
  if (!tld) {
    return { checked: false };
  }

  const bootstrap = await loadRdapBootstrap(fetchFn);
  const baseUrl = bootstrap?.tldToBaseUrl.get(tld);
  if (!baseUrl) {
    return { checked: false };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), RDAP_TIMEOUT_MS);

  try {
    const res = await fetchFn(`${baseUrl}domain/${encodeURIComponent(registrableDomain)}`, {
      method: 'GET',
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: controller.signal,
    });

    if (!res.ok) {
      return { checked: false };
    }

    const data = (await res.json()) as RdapResponseJson;
    const regEvent = data.events?.find((e) => e.eventAction === 'registration' && e.eventDate);
    let registrationDate: string | undefined;
    let domainAgeDays: number | undefined;

    if (regEvent?.eventDate) {
      const parsedMs = Date.parse(regEvent.eventDate);
      if (!Number.isNaN(parsedMs)) {
        registrationDate = new Date(parsedMs).toISOString().slice(0, 10);
        domainAgeDays = Math.max(0, Math.floor((Date.now() - parsedMs) / (1000 * 60 * 60 * 24)));
      }
    }

    let registrar: string | undefined;
    const registrarEntity = data.entities?.find((e) => e.roles?.includes('registrar'));
    const vcardItems = registrarEntity?.vcardArray?.[1];
    if (Array.isArray(vcardItems)) {
      const fnItem = vcardItems.find((item) => Array.isArray(item) && item[0] === 'fn');
      if (fnItem && typeof fnItem[3] === 'string' && fnItem[3].trim()) {
        registrar = fnItem[3].trim().slice(0, 120);
      }
    }

    return {
      checked: true,
      registrableDomain,
      registrationDate,
      domainAgeDays,
      registrar,
    };
  } catch {
    return { checked: false };
  } finally {
    clearTimeout(timeoutId);
  }
}

export function analyzeUrlStructure(normalizedUrl: string, hostname: string): UrlStructureSignals {
  let protocol = 'https:';
  let pathLower = '';
  try {
    const parsed = new URL(normalizedUrl);
    protocol = parsed.protocol;
    pathLower = parsed.pathname.toLowerCase();
  } catch {
    protocol = normalizedUrl.toLowerCase().startsWith('http://') ? 'http:' : 'https:';
    pathLower = normalizedUrl.toLowerCase();
  }

  const labels = hostname.split('.').filter(Boolean);

  return {
    usesPlainHttp: protocol === 'http:',
    isIpLiteral: net.isIP(hostname) !== 0,
    isPunycode: labels.some((label) => label.toLowerCase().startsWith('xn--')),
    subdomainDepth: Math.max(0, labels.length - 2),
    hasSuspiciousDownloadExt: /\.(exe|msi|scr|bat|cmd|ps1|vbs|apk|dmg|iso)$/i.test(pathLower),
    urlLength: normalizedUrl.length,
  };
}
