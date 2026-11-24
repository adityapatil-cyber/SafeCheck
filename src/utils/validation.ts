import type { ScanErrorCode } from '../types/scan.ts';

export const MAX_FILE_SIZE_MB = 25;
export const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

export const ACCEPTED_EXTENSIONS = [
  '.pdf',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  '.zip',
  '.txt',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
] as const;

export function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function normalizeClientUrlInput(rawInput: string): string {
  const trimmed = rawInput.trim();
  if (!trimmed) return '';
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    return trimmed;
  }
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:[/:?#].*)?$/.test(trimmed)) {
    return `https://${trimmed}`;
  }
  return trimmed;
}

export function validateClientUrl(rawInput: string): {
  valid: boolean;
  normalizedInput?: string;
  errorCode?: ScanErrorCode;
} {
  const normalized = normalizeClientUrlInput(rawInput);
  if (!normalized || normalized.length > 2048 || /[\s\u0000-\u001f\u007f]/.test(normalized)) {
    return { valid: false, errorCode: 'INVALID_URL' };
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return { valid: false, errorCode: 'INVALID_URL' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, errorCode: 'INVALID_URL' };
  }

  if (parsed.username || parsed.password || !parsed.hostname) {
    return { valid: false, errorCode: 'INVALID_URL' };
  }

  const host = parsed.hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host === '127.0.0.1' ||
    host === '0.0.0.0' ||
    host === '[::1]'
  ) {
    return { valid: false, errorCode: 'SSRF_BLOCKED' };
  }

  return { valid: true, normalizedInput: parsed.toString() };
}

export function validateClientFile(file: File | null): {
  valid: boolean;
  errorCode?: ScanErrorCode;
} {
  if (!file) {
    return { valid: false, errorCode: 'NO_FILE' };
  }

  if (file.size === 0) {
    return { valid: false, errorCode: 'CORRUPTED_FILE' };
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    return { valid: false, errorCode: 'FILE_TOO_LARGE' };
  }

  const dotIndex = file.name.lastIndexOf('.');
  const ext = dotIndex >= 0 ? file.name.slice(dotIndex).toLowerCase() : '';
  if (!ext || !ACCEPTED_EXTENSIONS.includes(ext as (typeof ACCEPTED_EXTENSIONS)[number])) {
    return { valid: false, errorCode: 'UNSUPPORTED_FILE' };
  }

  return { valid: true };
}
