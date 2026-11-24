import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import express from 'express';
import multer from 'multer';

const execFileAsync = promisify(execFile);
const app = express();
const port = Number.parseInt(process.env.PORT || '8080', 10);
const maxMb = Number.parseInt(process.env.MAX_FILE_SIZE_MB || '25', 10);
const scannerToken = process.env.CLAMAV_SCANNER_TOKEN?.trim() || '';
const tempDir = path.join(os.tmpdir(), 'clamav-scan-tmp');

app.disable('x-powered-by');

function requireBearerToken(req, res, next) {
  if (!scannerToken) {
    if (process.env.NODE_ENV === 'production') {
      return res.status(503).json({ status: 'error', message: 'Scanner authentication token is not configured.' });
    }
    return next();
  }

  const header = req.headers.authorization || '';
  const expected = `Bearer ${scannerToken}`;
  const headerBuf = Buffer.from(header);
  const expectedBuf = Buffer.from(expected);

  if (headerBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(headerBuf, expectedBuf)) {
    return res.status(401).json({ status: 'error', message: 'Unauthorized' });
  }
  return next();
}

const upload = multer({
  storage: multer.diskStorage({
    destination: async (_req, _file, cb) => {
      try {
        await fs.mkdir(tempDir, { recursive: true, mode: 0o700 });
        cb(null, tempDir);
      } catch (err) {
        cb(err, tempDir);
      }
    },
    filename: (_req, _file, cb) => {
      cb(null, `scan-${crypto.randomUUID()}`);
    },
  }),
  limits: {
    fileSize: maxMb * 1024 * 1024,
    files: 1,
  },
});

app.get('/health', requireBearerToken, async (_req, res) => {
  try {
    const { stdout } = await execFileAsync('clamdscan', ['--ping', '3'], { timeout: 4000 });
    if (stdout.includes('PONG')) {
      return res.status(200).json({ status: 'ok', engine: 'ClamAV' });
    }
    return res.status(503).json({ status: 'error', message: 'ClamAV daemon did not respond.' });
  } catch {
    return res.status(503).json({ status: 'error', message: 'ClamAV daemon unavailable.' });
  }
});

app.post('/scan', requireBearerToken, upload.single('file'), async (req, res) => {
  const filePath = req.file?.path;
  if (!filePath) {
    return res.status(400).json({ status: 'error', message: 'No file provided.' });
  }

  try {
    const resolved = path.resolve(filePath);
    if (!resolved.startsWith(path.resolve(tempDir) + path.sep)) {
      return res.status(400).json({ status: 'error', message: 'Invalid file path.' });
    }

    try {
      await execFileAsync('clamdscan', ['--no-summary', '--fdpass', resolved], {
        timeout: 35000,
        maxBuffer: 1024 * 1024,
      });
      return res.status(200).json({
        status: 'clean',
        signature: null,
        engine: 'ClamAV Antivirus Engine',
      });
    } catch (scanErr) {
      // clamdscan exits with code 1 when a threat signature is found
      if (scanErr && scanErr.code === 1) {
        const output = String(scanErr.stdout || '');
        const match = output.match(/:\s*(.+?)\s+FOUND/);
        const signature = match ? match[1].trim() : 'Malware signature detected';
        return res.status(200).json({
          status: 'infected',
          signature,
          engine: 'ClamAV Antivirus Engine',
        });
      }
      return res.status(502).json({
        status: 'error',
        message: 'ClamAV scan execution failed.',
      });
    }
  } finally {
    await fs.unlink(filePath).catch(() => {});
  }
});

app.use((err, _req, res, _next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      status: 'error',
      message: `File exceeds maximum allowed size of ${maxMb} MB.`,
    });
  }
  return res.status(400).json({
    status: 'error',
    message: 'Unable to process uploaded file.',
  });
});

app.listen(port, '0.0.0.0', () => {
  console.info(`SafeCheck ClamAV scanning service listening on port ${port}`);
});
