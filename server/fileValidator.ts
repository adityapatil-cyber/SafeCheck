import fs from 'node:fs/promises';
import path from 'node:path';
import type { ScanErrorCode } from './types.ts';

export interface ValidatedFileResult {
  valid: boolean;
  detectedType?: string;
  mimeType?: string;
  extension?: string;
  errorCode?: ScanErrorCode;
  errorMessage?: string;
}

export const SUPPORTED_FORMAT_LABELS = [
  'PDF',
  'DOC',
  'DOCX',
  'XLS',
  'XLSX',
  'PPT',
  'PPTX',
  'ZIP',
  'TXT',
  'PNG',
  'JPG',
  'GIF',
  'WEBP',
] as const;

const ZIP_MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024; // 100 MB decompression cap
const ZIP_MAX_ENTRIES = 2000;

function matchesBytes(buf: Buffer, offset: number, expected: number[]): boolean {
  if (buf.length < offset + expected.length) return false;
  for (let i = 0; i < expected.length; i++) {
    if (buf[offset + i] !== expected[i]) return false;
  }
  return true;
}

function isLikelyPlainText(buf: Buffer): boolean {
  if (buf.length === 0) return false;

  // Reject UTF-16/UTF-32 BOM or binary control bytes
  let nonPrintable = 0;
  const sampleLen = Math.min(buf.length, 8192);

  for (let i = 0; i < sampleLen; i++) {
    const byte = buf[i];
    if (byte === 0x00) {
      return false;
    }
    // Allow tab (9), LF (10), CR (13), and printable ASCII / UTF-8 continuation/leading bytes (>= 32)
    if (byte < 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d) {
      nonPrintable++;
    }
  }

  if (nonPrintable / sampleLen > 0.02) {
    return false;
  }

  // Verify valid UTF-8 decoding
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    decoder.decode(buf.subarray(0, sampleLen));
    return true;
  } catch {
    return false;
  }
}

function inspectZipBuffer(buf: Buffer): {
  valid: boolean;
  subtype: 'DOCX' | 'XLSX' | 'PPTX' | 'ZIP';
  reason?: string;
} {
  // Empty ZIP archive signature PK\x05\x06
  if (matchesBytes(buf, 0, [0x50, 0x4b, 0x05, 0x06])) {
    return { valid: true, subtype: 'ZIP' };
  }

  // Check End of Central Directory (EOCD) from the tail of the buffer for archive bomb protection
  const searchStart = Math.max(0, buf.length - 65557);
  let eocdOffset = -1;
  for (let i = buf.length - 22; i >= searchStart; i--) {
    if (
      buf[i] === 0x50 &&
      buf[i + 1] === 0x4b &&
      buf[i + 2] === 0x05 &&
      buf[i + 3] === 0x06
    ) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset !== -1) {
    const totalEntries = buf.readUInt16LE(eocdOffset + 10);
    if (totalEntries > ZIP_MAX_ENTRIES) {
      return {
        valid: false,
        subtype: 'ZIP',
        reason: 'This archive contains too many internal entries and exceeds safe inspection limits.',
      };
    }

    const centralDirSize = buf.readUInt32LE(eocdOffset + 12);
    const centralDirOffset = buf.readUInt32LE(eocdOffset + 16);
    if (
      centralDirOffset < buf.length &&
      centralDirOffset + centralDirSize <= buf.length
    ) {
      let cursor = centralDirOffset;
      let totalUncompressed = 0;
      let entriesParsed = 0;

      while (cursor + 46 <= centralDirOffset + centralDirSize && entriesParsed < ZIP_MAX_ENTRIES) {
        if (!matchesBytes(buf, cursor, [0x50, 0x4b, 0x01, 0x02])) {
          break;
        }
        const uncompressedSize = buf.readUInt32LE(cursor + 24);
        totalUncompressed += uncompressedSize;
        if (totalUncompressed > ZIP_MAX_UNCOMPRESSED_BYTES) {
          return {
            valid: false,
            subtype: 'ZIP',
            reason: 'The decompressed size of this archive exceeds safe limits.',
          };
        }
        const nameLen = buf.readUInt16LE(cursor + 28);
        const extraLen = buf.readUInt16LE(cursor + 30);
        const commentLen = buf.readUInt16LE(cursor + 32);
        cursor += 46 + nameLen + extraLen + commentLen;
        entriesParsed++;
      }
    }
  }

  // Distinguish OOXML Office documents vs generic ZIP via internal entry markers
  const asciiHeader = buf.subarray(0, Math.min(buf.length, 65536)).toString('latin1');
  if (asciiHeader.includes('word/')) {
    return { valid: true, subtype: 'DOCX' };
  }
  if (asciiHeader.includes('xl/')) {
    return { valid: true, subtype: 'XLSX' };
  }
  if (asciiHeader.includes('ppt/')) {
    return { valid: true, subtype: 'PPTX' };
  }

  return { valid: true, subtype: 'ZIP' };
}

export function validateFileBuffer(buf: Buffer, originalName: string): ValidatedFileResult {
  if (!buf || buf.length === 0) {
    return {
      valid: false,
      errorCode: 'CORRUPTED_FILE',
      errorMessage: 'The uploaded file is empty and cannot be scanned.',
    };
  }

  const ext = path.extname(originalName).toLowerCase();

  // 1. PDF (%PDF-)
  if (matchesBytes(buf, 0, [0x25, 0x50, 0x44, 0x46, 0x2d])) {
    return {
      valid: true,
      detectedType: 'PDF Document',
      mimeType: 'application/pdf',
      extension: 'PDF',
    };
  }

  // 2. PNG (\x89PNG\r\n\x1a\n)
  if (matchesBytes(buf, 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return {
      valid: true,
      detectedType: 'PNG Image',
      mimeType: 'image/png',
      extension: 'PNG',
    };
  }

  // 3. JPEG (\xFF\xD8\xFF)
  if (matchesBytes(buf, 0, [0xff, 0xd8, 0xff])) {
    return {
      valid: true,
      detectedType: 'JPEG Image',
      mimeType: 'image/jpeg',
      extension: 'JPG',
    };
  }

  // 4. GIF (GIF87a or GIF89a)
  if (
    matchesBytes(buf, 0, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) ||
    matchesBytes(buf, 0, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61])
  ) {
    return {
      valid: true,
      detectedType: 'GIF Image',
      mimeType: 'image/gif',
      extension: 'GIF',
    };
  }

  // 5. WEBP (RIFF....WEBP)
  if (
    matchesBytes(buf, 0, [0x52, 0x49, 0x46, 0x46]) &&
    buf.length >= 12 &&
    matchesBytes(buf, 8, [0x57, 0x45, 0x42, 0x50])
  ) {
    return {
      valid: true,
      detectedType: 'WebP Image',
      mimeType: 'image/webp',
      extension: 'WEBP',
    };
  }

  // 6. Legacy MS Office OLE2 Compound Document (\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1)
  if (matchesBytes(buf, 0, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) {
    if (ext === '.xls') {
      return {
        valid: true,
        detectedType: 'Microsoft Excel Document (Legacy XLS)',
        mimeType: 'application/vnd.ms-excel',
        extension: 'XLS',
      };
    }
    if (ext === '.ppt') {
      return {
        valid: true,
        detectedType: 'Microsoft PowerPoint Document (Legacy PPT)',
        mimeType: 'application/vnd.ms-powerpoint',
        extension: 'PPT',
      };
    }
    return {
      valid: true,
      detectedType: 'Microsoft Office Compound Document (DOC/XLS/PPT)',
      mimeType: 'application/msword',
      extension: ext === '.doc' ? 'DOC' : 'OLE2',
    };
  }

  // 7. ZIP & Office Open XML (DOCX, XLSX, PPTX)
  if (
    matchesBytes(buf, 0, [0x50, 0x4b, 0x03, 0x04]) ||
    matchesBytes(buf, 0, [0x50, 0x4b, 0x05, 0x06])
  ) {
    const zipInfo = inspectZipBuffer(buf);
    if (!zipInfo.valid) {
      return {
        valid: false,
        errorCode: 'CORRUPTED_FILE',
        errorMessage: zipInfo.reason ?? 'The archive could not be safely inspected.',
      };
    }

    if (zipInfo.subtype === 'DOCX') {
      return {
        valid: true,
        detectedType: 'Microsoft Word Document (DOCX)',
        mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        extension: 'DOCX',
      };
    }
    if (zipInfo.subtype === 'XLSX') {
      return {
        valid: true,
        detectedType: 'Microsoft Excel Workbook (XLSX)',
        mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        extension: 'XLSX',
      };
    }
    if (zipInfo.subtype === 'PPTX') {
      return {
        valid: true,
        detectedType: 'Microsoft PowerPoint Presentation (PPTX)',
        mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        extension: 'PPTX',
      };
    }
    return {
      valid: true,
      detectedType: 'ZIP Archive',
      mimeType: 'application/zip',
      extension: 'ZIP',
    };
  }

  // 8. Plain Text (.txt) — only accept if content is genuinely valid UTF-8/ASCII text
  if (ext === '.txt' || ext === '') {
    if (isLikelyPlainText(buf)) {
      return {
        valid: true,
        detectedType: 'Plain Text Document (TXT)',
        mimeType: 'text/plain',
        extension: 'TXT',
      };
    }
  }

  return {
    valid: false,
    errorCode: 'UNSUPPORTED_FILE',
    errorMessage:
      'This file format is not supported or its internal signature does not match a supported document, archive, or image format.',
  };
}

export async function validateUploadedFileOnDisk(
  filePath: string,
  originalName: string,
): Promise<ValidatedFileResult> {
  const buf = await fs.readFile(filePath);
  return validateFileBuffer(buf, originalName);
}

export function sanitizeDisplayFilename(rawName: string): string {
  const base = path.basename(rawName || 'uploaded-file');
  const cleaned = base.replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_').trim();
  return cleaned.slice(0, 180) || 'uploaded-file';
}
