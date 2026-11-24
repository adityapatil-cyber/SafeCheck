import fs from 'node:fs/promises';
import type { FileScanInfo, ScanResponse } from './types.ts';

const DEFAULT_SCAN_TIMEOUT_MS = 45_000;
const HEALTH_TIMEOUT_MS = 4_000;

interface ClamavServiceResponse {
  status?: 'clean' | 'infected' | 'error';
  signature?: string | null;
  engine?: string;
  message?: string;
}

export function isClamavConfigured(): boolean {
  const url = process.env.CLAMAV_SCANNER_URL?.trim();
  return Boolean(url && /^https?:\/\//i.test(url));
}

function getClamavHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  const token = process.env.CLAMAV_SCANNER_TOKEN?.trim();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export async function checkClamavHealth(
  fetchFn: typeof fetch = fetch,
): Promise<'ready' | 'unconfigured' | 'unreachable'> {
  if (!isClamavConfigured()) {
    return 'unconfigured';
  }

  const baseUrl = process.env.CLAMAV_SCANNER_URL!.trim().replace(/\/+$/, '');
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS);

  try {
    const res = await fetchFn(`${baseUrl}/health`, {
      method: 'GET',
      headers: getClamavHeaders(),
      signal: controller.signal,
    });
    return res.ok ? 'ready' : 'unreachable';
  } catch {
    return 'unreachable';
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function scanFileWithClamav(
  filePath: string,
  fileInfo: FileScanInfo,
  fetchFn: typeof fetch = fetch,
): Promise<ScanResponse> {
  const timestamp = new Date().toISOString();
  const scannerName = 'ClamAV Antivirus Engine';
  const categoriesChecked = ['Malware signatures', 'Trojans & Ransomware', 'Archive & Document exploits'];

  if (!isClamavConfigured()) {
    return {
      status: 'unavailable',
      scanType: 'file',
      scannedItem: fileInfo.fileName,
      scannerName,
      timestamp,
      categoriesChecked,
      fileInfo,
      error: {
        code: 'SERVICE_UNCONFIGURED',
        message:
          'The file-scanning service is currently unavailable because the ClamAV scanner endpoint has not been configured.',
      },
    };
  }

  const baseUrl = process.env.CLAMAV_SCANNER_URL!.trim().replace(/\/+$/, '');
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_SCAN_TIMEOUT_MS);

  try {
    const fileBytes = await fs.readFile(filePath);
    const formData = new FormData();
    const blob = new Blob([fileBytes], { type: 'application/octet-stream' });
    formData.append('file', blob, fileInfo.fileName);

    const response = await fetchFn(`${baseUrl}/scan`, {
      method: 'POST',
      headers: getClamavHeaders(),
      body: formData,
      signal: controller.signal,
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        scanType: 'file',
        scannedItem: fileInfo.fileName,
        scannerName,
        timestamp,
        categoriesChecked,
        fileInfo,
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: `The file-scanning service returned an error (HTTP ${response.status}).`,
        },
      };
    }

    const payload = (await response.json()) as ClamavServiceResponse;
    const engineLabel = payload.engine || scannerName;

    if (payload.status === 'infected') {
      const signature = payload.signature?.trim() || 'Detected by ClamAV signature database';
      return {
        status: 'threat',
        scanType: 'file',
        scannedItem: fileInfo.fileName,
        scannerName: engineLabel,
        timestamp,
        categoriesChecked,
        fileInfo,
        threats: [
          {
            type: 'MALWARE_SIGNATURE',
            description: `Antivirus signature match: ${signature}`,
          },
        ],
        technicalDetails: {
          detectionSignature: signature,
          detectedFormat: fileInfo.detectedType,
          apiResponse: 'Infected file signature reported by ClamAV',
        },
      };
    }

    if (payload.status === 'clean') {
      return {
        status: 'clean',
        scanType: 'file',
        scannedItem: fileInfo.fileName,
        scannerName: engineLabel,
        timestamp,
        categoriesChecked,
        fileInfo,
        technicalDetails: {
          detectedFormat: fileInfo.detectedType,
          apiResponse: 'No malware signatures matched',
        },
      };
    }

    return {
      status: 'unavailable',
      scanType: 'file',
      scannedItem: fileInfo.fileName,
      scannerName: engineLabel,
      timestamp,
      categoriesChecked,
      fileInfo,
      error: {
        code: 'SERVICE_UNAVAILABLE',
        message: payload.message || 'The file-scanning engine could not complete the inspection.',
      },
    };
  } catch (err) {
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return {
      status: 'unavailable',
      scanType: 'file',
      scannedItem: fileInfo.fileName,
      scannerName,
      timestamp,
      categoriesChecked,
      fileInfo,
      error: {
        code: isTimeout ? 'TIMEOUT' : 'SERVICE_UNAVAILABLE',
        message: isTimeout
          ? 'The file scan timed out before the scanning engine finished.'
          : 'Unable to connect to the ClamAV file-scanning service.',
      },
    };
  } finally {
    clearTimeout(timeoutId);
  }
}
