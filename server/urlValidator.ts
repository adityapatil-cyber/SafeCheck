import dns from 'node:dns/promises';
import net from 'node:net';
import type { ScanErrorCode } from './types.ts';

export interface UrlValidationResult {
  valid: boolean;
  normalizedUrl?: string;
  hostname?: string;
  errorCode?: ScanErrorCode;
  errorMessage?: string;
}

const MAX_URL_LENGTH = 2048;

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata',
  '0.0.0.0',
]);

function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }

  const [a, b] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;
  // 10.0.0.0/8 (Private)
  if (a === 10) return true;
  // 100.64.0.0/10 (Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (Link-local & Cloud metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (Private)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24 & 192.0.2.0/24
  if (a === 192 && b === 0) return true;
  // 192.168.0.0/16 (Private)
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved / Broadcast)
  if (a >= 224) return true;

  return false;
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const cleaned = ip.replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  const ipVersion = net.isIP(cleaned);

  if (ipVersion === 4) {
    return isPrivateOrReservedIpv4(cleaned);
  }

  if (ipVersion === 6) {
    if (cleaned === '::' || cleaned === '::1') {
      return true;
    }
    // IPv4-mapped IPv6 e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1
    if (cleaned.startsWith('::ffff:')) {
      const mapped = cleaned.slice('::ffff:'.length);
      if (net.isIPv4(mapped)) {
        return isPrivateOrReservedIpv4(mapped);
      }
      // Hex form like ::ffff:7f00:0001
      const hexParts = mapped.split(':');
      if (hexParts.length === 2) {
        const hi = Number.parseInt(hexParts[0], 16);
        const lo = Number.parseInt(hexParts[1], 16);
        if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
          const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
          return isPrivateOrReservedIpv4(ipv4);
        }
      }
      return true;
    }
    // Unique local addresses fc00::/7 (fc00..fdff)
    if (/^f[cd][0-9a-f]{2}:/i.test(cleaned)) {
      return true;
    }
    // Link-local fe80::/10 (fe80..febf)
    if (/^fe[89ab][0-9a-f]:/i.test(cleaned)) {
      return true;
    }
    // Multicast ff00::/8
    if (/^ff[0-9a-f]{2}:/i.test(cleaned)) {
      return true;
    }
    return false;
  }

  return false;
}

export function validateAndNormalizeUrl(rawInput: unknown): UrlValidationResult {
  if (typeof rawInput !== 'string') {
    return {
      valid: false,
      errorCode: 'INVALID_URL',
      errorMessage: 'Please enter a valid website link starting with http:// or https://.',
    };
  }

  const trimmed = rawInput.trim();
  if (!trimmed || trimmed.length > MAX_URL_LENGTH) {
    return {
      valid: false,
      errorCode: 'INVALID_URL',
      errorMessage: 'The website link is empty or exceeds the maximum supported length.',
    };
  }

  // Reject embedded control characters or spaces
  if (/[\s\u0000-\u001f\u007f]/.test(trimmed)) {
    return {
      valid: false,
      errorCode: 'INVALID_URL',
      errorMessage: 'The website link contains invalid spaces or control characters.',
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      valid: false,
      errorCode: 'INVALID_URL',
      errorMessage: 'Please enter a valid website link starting with http:// or https://.',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      errorCode: 'INVALID_URL',
      errorMessage: 'Only HTTP and HTTPS website links are supported.',
    };
  }

  if (parsed.username || parsed.password) {
    return {
      valid: false,
      errorCode: 'INVALID_URL',
      errorMessage: 'Links containing embedded usernames or passwords are not permitted.',
    };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname) {
    return {
      valid: false,
      errorCode: 'INVALID_URL',
      errorMessage: 'The website link does not contain a valid domain name.',
    };
  }

  if (
    BLOCKED_HOSTNAMES.has(hostname) ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    return {
      valid: false,
      errorCode: 'SSRF_BLOCKED',
      errorMessage: 'Internal, loopback, and local network addresses cannot be scanned.',
    };
  }

  const unbracketed = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(unbracketed) !== 0) {
    if (isPrivateOrReservedIp(unbracketed)) {
      return {
        valid: false,
        errorCode: 'SSRF_BLOCKED',
        errorMessage: 'Private or reserved IP addresses cannot be scanned.',
      };
    }
  } else {
    // Public hostnames should have at least one dot and valid domain labels
    const labels = hostname.split('.');
    if (
      labels.length < 2 ||
      labels.some((label) => !label || label.length > 63 || !/^[a-z0-9-]+$/i.test(label))
    ) {
      return {
        valid: false,
        errorCode: 'INVALID_URL',
        errorMessage: 'Please enter a complete website address with a valid domain name.',
      };
    }
  }

  // Strip fragment before sending to reputation lookup; normalize protocol/host casing via URL
  parsed.hash = '';
  return {
    valid: true,
    normalizedUrl: parsed.toString(),
    hostname: unbracketed,
  };
}

export async function verifyPublicHostnameDns(
  hostname: string,
  lookupFn: typeof dns.lookup = dns.lookup,
): Promise<{ safe: boolean; reason?: string }> {
  if (net.isIP(hostname) !== 0) {
    return isPrivateOrReservedIp(hostname)
      ? { safe: false, reason: 'Private or reserved IP addresses cannot be scanned.' }
      : { safe: true };
  }

  try {
    const records = await lookupFn(hostname, { all: true, verbatim: true });
    for (const record of records) {
      if (isPrivateOrReservedIp(record.address)) {
        return {
          safe: false,
          reason: 'This domain resolves to a private or internal network address and cannot be scanned.',
        };
      }
    }
    return { safe: true };
  } catch {
    // DNS failure does not mean private IP; Web Risk lookup can still evaluate historical reputation
    // or report unreachable/clean based on threat lists without making any outbound connection to host.
    return { safe: true };
  }
}
