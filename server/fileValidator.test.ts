import assert from 'node:assert/strict';
import test from 'node:test';
import { sanitizeDisplayFilename, validateFileBuffer } from './fileValidator.ts';

test('identifies supported binary formats from magic bytes regardless of extension', () => {
  const pdfBuf = Buffer.from('%PDF-1.7\n1 0 obj\n', 'ascii');
  const pdfRes = validateFileBuffer(pdfBuf, 'invoice.exe');
  assert.equal(pdfRes.valid, true);
  assert.equal(pdfRes.detectedType, 'PDF Document');
  assert.equal(pdfRes.mimeType, 'application/pdf');

  const pngBuf = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
  const pngRes = validateFileBuffer(pngBuf, 'photo.png');
  assert.equal(pngRes.valid, true);
  assert.equal(pngRes.extension, 'PNG');

  const jpgBuf = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
  assert.equal(validateFileBuffer(jpgBuf, 'img.jpg').extension, 'JPG');

  const gifBuf = Buffer.from('GIF89a\x01\x00\x01\x00', 'ascii');
  assert.equal(validateFileBuffer(gifBuf, 'anim.gif').extension, 'GIF');

  const webpBuf = Buffer.from('RIFF\x24\x00\x00\x00WEBPVP8 ', 'ascii');
  assert.equal(validateFileBuffer(webpBuf, 'pic.webp').extension, 'WEBP');

  const oleBuf = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0x00]);
  assert.equal(validateFileBuffer(oleBuf, 'report.xls').extension, 'XLS');
});

test('distinguishes OOXML documents from generic ZIP archives', () => {
  const docxZip = Buffer.concat([
    Buffer.from([0x50, 0x4b, 0x03, 0x04]),
    Buffer.from('word/document.xml', 'ascii'),
  ]);
  const res = validateFileBuffer(docxZip, 'contract.docx');
  assert.equal(res.valid, true);
  assert.equal(res.extension, 'DOCX');

  const plainZip = Buffer.concat([
    Buffer.from([0x50, 0x4b, 0x03, 0x04]),
    Buffer.from('readme.md', 'ascii'),
  ]);
  assert.equal(validateFileBuffer(plainZip, 'archive.zip').extension, 'ZIP');
});

test('accepts valid UTF-8 plain text and rejects binary disguised as .txt', () => {
  const txtRes = validateFileBuffer(Buffer.from('Hello SafeCheck!\nLine 2', 'utf8'), 'notes.txt');
  assert.equal(txtRes.valid, true);
  assert.equal(txtRes.extension, 'TXT');

  const exeDisguised = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00', 'latin1');
  const badRes = validateFileBuffer(exeDisguised, 'payload.txt');
  assert.equal(badRes.valid, false);
  assert.equal(badRes.errorCode, 'UNSUPPORTED_FILE');
});

test('rejects empty files and sanitizes display filenames against path traversal', () => {
  const emptyRes = validateFileBuffer(Buffer.alloc(0), 'empty.pdf');
  assert.equal(emptyRes.valid, false);
  assert.equal(emptyRes.errorCode, 'CORRUPTED_FILE');

  assert.equal(sanitizeDisplayFilename('../../etc/passwd'), 'passwd');
  assert.equal(sanitizeDisplayFilename('report\x00<script>.pdf'), 'report__script_.pdf');
});
