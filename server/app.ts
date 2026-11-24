import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import multer from 'multer';
import { checkClamavHealth, scanFileWithClamav } from './clamavClient.ts';
import {
  sanitizeDisplayFilename,
  validateUploadedFileOnDisk,
} from './fileValidator.ts';
import {
  isGeminiBotConfigured,
  scanUrlWithAiBot,
  type GeminiClientLike,
} from './geminiUrlBot.ts';
import type { HealthResponse, ScanResponse, SupportedLanguage } from './types.ts';
import {
  validateAndNormalizeUrl,
  verifyPublicHostnameDns,
} from './urlValidator.ts';
import { isWebRiskConfigured, scanUrlWithWebRisk } from './webRiskClient.ts';

export interface CreateAppOptions {
  uploadDir?: string;
  fetchFn?: typeof fetch;
  aiClient?: GeminiClientLike;
  enableRateLimit?: boolean;
}

export function getMaxFileSizeMb(): number {
  const parsed = Number.parseInt(process.env.MAX_FILE_SIZE_MB || '25', 10);
  if (Number.isNaN(parsed) || parsed < 1 || parsed > 100) {
    return 25;
  }
  return parsed;
}

async function safeUnlink(filePath: string | undefined, allowedDir: string): Promise<void> {
  if (!filePath) return;
  const resolvedBase = path.resolve(allowedDir);
  const resolvedTarget = path.resolve(filePath);
  if (!resolvedTarget.startsWith(resolvedBase + path.sep)) {
    return;
  }
  try {
    await fs.unlink(resolvedTarget);
  } catch {
    // File may already be removed or never created
  }
}

export function createApp(options: CreateAppOptions = {}) {
  const app = express();
  const isProd = process.env.NODE_ENV === 'production';
  const maxFileSizeMb = getMaxFileSizeMb();
  const maxFileSizeBytes = maxFileSizeMb * 1024 * 1024;
  const uploadDir = options.uploadDir ?? path.join(os.tmpdir(), 'safecheck-uploads');
  const fetchFn = options.fetchFn ?? fetch;
  const aiClient = options.aiClient;

  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  // Security headers (frameguard/frame-ancestors/COOP/CORP relaxed for AI Studio iframe preview)
  app.use(
    helmet({
      frameguard: false,
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: isProd ? ["'self'"] : ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
          imgSrc: ["'self'", 'data:', 'blob:'],
          connectSrc: isProd ? ["'self'"] : ["'self'", 'ws:', 'wss:'],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
        },
      },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    }),
  );

  // Strict CORS policy: allow same-origin requests (including Cloud Run Dev/Shared URLs) and configured APP_URL
  const allowedOrigins = new Set<string>([
    'http://localhost:3000',
    'http://127.0.0.1:3000',
  ]);
  if (process.env.APP_URL) {
    try {
      allowedOrigins.add(new URL(process.env.APP_URL).origin);
    } catch {
      // Ignore invalid APP_URL
    }
  }

  app.use(
    cors((req, callback) => {
      const origin = req.header('Origin');
      if (!origin) {
        callback(null, { origin: false });
        return;
      }

      if (allowedOrigins.has(origin)) {
        callback(null, {
          origin: true,
          methods: ['GET', 'POST', 'OPTIONS'],
          allowedHeaders: ['Content-Type'],
          maxAge: 600,
        });
        return;
      }

      const forwardedHost = req.header('X-Forwarded-Host')?.split(',')[0]?.trim();
      const host = forwardedHost || req.header('Host');
      if (host) {
        try {
          const originHost = new URL(origin).host;
          if (originHost === host) {
            callback(null, {
              origin: true,
              methods: ['GET', 'POST', 'OPTIONS'],
              allowedHeaders: ['Content-Type'],
              maxAge: 600,
            });
            return;
          }
        } catch {
          // Malformed Origin header
        }
      }

      callback(new Error('CORS_ORIGIN_NOT_ALLOWED'));
    }),
  );

  app.use(express.json({ limit: '16kb' }));

  const scanLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req: Request, res: Response) => {
      const payload: ScanResponse = {
        status: 'unavailable',
        scanType: 'url',
        scannedItem: '',
        scannerName: 'SafeCheck Request Guard',
        timestamp: new Date().toISOString(),
        categoriesChecked: [],
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many scan requests in a short period. Please wait a minute and try again.',
        },
      };
      res.status(429).json(payload);
    },
  });

  if (options.enableRateLimit !== false) {
    app.use('/api/scan/', scanLimiter);
  }

  // Multer configuration writing to isolated temp storage with UUID filenames
  const storage = multer.diskStorage({
    destination: (_req, _file, cb) => {
      fs.mkdir(uploadDir, { recursive: true, mode: 0o700 })
        .then(() => cb(null, uploadDir))
        .catch((err) => cb(err as Error, uploadDir));
    },
    filename: (_req, _file, cb) => {
      cb(null, `upload-${crypto.randomUUID()}`);
    },
  });

  const upload = multer({
    storage,
    limits: {
      fileSize: maxFileSizeBytes,
      files: 1,
      fields: 4,
    },
  });

  // GET /api/health
  app.get('/api/health', async (_req: Request, res: Response) => {
    const webRiskConfigured = isWebRiskConfigured();
    const geminiBotConfigured = Boolean(aiClient) || isGeminiBotConfigured();
    const clamavStatus = await checkClamavHealth(fetchFn);

    const health: HealthResponse = {
      status:
        (webRiskConfigured || geminiBotConfigured) && clamavStatus === 'ready'
          ? 'ok'
          : 'degraded',
      timestamp: new Date().toISOString(),
      maxFileSizeMb: getMaxFileSizeMb(),
      services: {
        webRisk: {
          configured: webRiskConfigured,
          status: webRiskConfigured ? 'ready' : 'unconfigured',
        },
        geminiBot: {
          configured: geminiBotConfigured,
          status: geminiBotConfigured ? 'ready' : 'unconfigured',
        },
        clamav: {
          configured: clamavStatus !== 'unconfigured',
          status: clamavStatus,
        },
      },
    };

    res.status(200).json(health);
  });

  // POST /api/scan/url
  app.post('/api/scan/url', async (req: Request, res: Response) => {
    const rawUrl = req.body?.url;
    const rawLanguage = req.body?.language;
    const language: SupportedLanguage =
      rawLanguage === 'hi' || rawLanguage === 'gu' ? rawLanguage : 'en';

    const validation = validateAndNormalizeUrl(rawUrl);

    if (!validation.valid || !validation.normalizedUrl || !validation.hostname) {
      const errorResponse: ScanResponse = {
        status: 'unavailable',
        scanType: 'url',
        scannedItem: typeof rawUrl === 'string' ? rawUrl.trim().slice(0, 256) : '',
        scannerName: 'SafeCheck Link Scanner',
        timestamp: new Date().toISOString(),
        categoriesChecked: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        error: {
          code: validation.errorCode ?? 'INVALID_URL',
          message: validation.errorMessage ?? 'Invalid website link.',
        },
      };
      res.status(400).json(errorResponse);
      return;
    }

    const dnsCheck = await verifyPublicHostnameDns(validation.hostname);
    if (!dnsCheck.safe) {
      const ssrfResponse: ScanResponse = {
        status: 'unavailable',
        scanType: 'url',
        scannedItem: validation.normalizedUrl,
        scannerName: 'SafeCheck Link Scanner',
        timestamp: new Date().toISOString(),
        categoriesChecked: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        error: {
          code: 'SSRF_BLOCKED',
          message: dnsCheck.reason ?? 'Private or internal network addresses cannot be scanned.',
        },
      };
      res.status(400).json(ssrfResponse);
      return;
    }

    let result: ScanResponse;
    if (isWebRiskConfigured()) {
      const webRiskResult = await scanUrlWithWebRisk(validation.normalizedUrl, fetchFn);
      if (webRiskResult.status === 'clean' || webRiskResult.status === 'threat') {
        result = webRiskResult;
      } else {
        // Automatically fall back to SafeCheck AI Security Bot + public threat feeds
        result = await scanUrlWithAiBot({
          normalizedUrl: validation.normalizedUrl,
          hostname: validation.hostname,
          language,
          fetchFn,
          aiClient,
          fallbackReason: webRiskResult.error?.code,
        });
      }
    } else {
      result = await scanUrlWithAiBot({
        normalizedUrl: validation.normalizedUrl,
        hostname: validation.hostname,
        language,
        fetchFn,
        aiClient,
      });
    }

    console.info(
      JSON.stringify({
        event: 'url_scan_completed',
        status: result.status,
        scanner: result.scannerName,
        detailCode: result.error?.code ?? 'OK',
        timestamp: result.timestamp,
      }),
    );

    res.status(200).json(result);
  });

  // POST /api/scan/file
  app.post('/api/scan/file', (req: Request, res: Response) => {
    const singleUpload = upload.single('file');

    singleUpload(req, res, async (uploadErr: unknown) => {
      const tempFilePath = req.file?.path;
      const displayFileName = sanitizeDisplayFilename(req.file?.originalname || '');

      try {
        if (uploadErr) {
          const isSizeLimit =
            uploadErr instanceof multer.MulterError && uploadErr.code === 'LIMIT_FILE_SIZE';
          const errorResponse: ScanResponse = {
            status: 'unavailable',
            scanType: 'file',
            scannedItem: displayFileName || 'Uploaded file',
            scannerName: 'ClamAV Antivirus Engine',
            timestamp: new Date().toISOString(),
            categoriesChecked: ['Malware signatures', 'Trojans & Ransomware', 'Archive & Document exploits'],
            error: {
              code: isSizeLimit ? 'FILE_TOO_LARGE' : 'INTERNAL_ERROR',
              message: isSizeLimit
                ? `The uploaded file exceeds the maximum allowed size of ${getMaxFileSizeMb()} MB.`
                : 'Unable to process the uploaded file safely.',
            },
          };
          res.status(isSizeLimit ? 413 : 400).json(errorResponse);
          return;
        }

        if (!req.file || !tempFilePath) {
          const noFileResponse: ScanResponse = {
            status: 'unavailable',
            scanType: 'file',
            scannedItem: '',
            scannerName: 'ClamAV Antivirus Engine',
            timestamp: new Date().toISOString(),
            categoriesChecked: ['Malware signatures', 'Trojans & Ransomware', 'Archive & Document exploits'],
            error: {
              code: 'NO_FILE',
              message: 'Please select a file before starting a scan.',
            },
          };
          res.status(400).json(noFileResponse);
          return;
        }

        const validation = await validateUploadedFileOnDisk(tempFilePath, displayFileName);
        if (!validation.valid || !validation.detectedType || !validation.mimeType) {
          const invalidFileResponse: ScanResponse = {
            status: 'unavailable',
            scanType: 'file',
            scannedItem: displayFileName,
            scannerName: 'ClamAV Antivirus Engine',
            timestamp: new Date().toISOString(),
            categoriesChecked: ['Malware signatures', 'Trojans & Ransomware', 'Archive & Document exploits'],
            fileInfo: {
              fileName: displayFileName,
              sizeBytes: req.file.size,
              detectedType: 'Unsupported or invalid format',
              mimeType: 'application/octet-stream',
            },
            error: {
              code: validation.errorCode ?? 'UNSUPPORTED_FILE',
              message:
                validation.errorMessage ??
                'This file format is not supported for scanning.',
            },
          };
          res.status(400).json(invalidFileResponse);
          return;
        }

        const fileInfo = {
          fileName: displayFileName,
          sizeBytes: req.file.size,
          detectedType: validation.detectedType,
          mimeType: validation.mimeType,
        };

        const scanResult = await scanFileWithClamav(tempFilePath, fileInfo, fetchFn);
        console.info(
          JSON.stringify({
            event: 'file_scan_completed',
            status: scanResult.status,
            detectedType: fileInfo.detectedType,
            sizeBytes: fileInfo.sizeBytes,
            detailCode: scanResult.error?.code ?? 'OK',
            timestamp: scanResult.timestamp,
          }),
        );

        res.status(200).json(scanResult);
      } catch {
        const failResponse: ScanResponse = {
          status: 'unavailable',
          scanType: 'file',
          scannedItem: displayFileName || 'Uploaded file',
          scannerName: 'ClamAV Antivirus Engine',
          timestamp: new Date().toISOString(),
          categoriesChecked: ['Malware signatures', 'Trojans & Ransomware', 'Archive & Document exploits'],
          error: {
            code: 'INTERNAL_ERROR',
            message: 'An unexpected error occurred while processing the file scan.',
          },
        };
        res.status(500).json(failResponse);
      } finally {
        await safeUnlink(tempFilePath, uploadDir);
      }
    });
  });

  // Return structured JSON 404 for unknown API routes instead of SPA HTML
  app.use('/api', (_req: Request, res: Response) => {
    res.status(404).json({
      status: 'unavailable',
      error: {
        code: 'API_ERROR',
        message: 'Requested API endpoint does not exist.',
      },
    });
  });

  // Safe global error handler (never leaks stack traces or internal config)
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    if (err.message === 'CORS_ORIGIN_NOT_ALLOWED') {
      res.status(403).json({
        status: 'unavailable',
        error: {
          code: 'API_ERROR',
          message: 'Cross-origin request blocked by security policy.',
        },
      });
      return;
    }

    res.status(500).json({
      status: 'unavailable',
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected server error occurred.',
      },
    });
  });

  return app;
}
