# SafeCheck — Online Link & File Security Checker

SafeCheck is a privacy-first, account-free web application that lets anyone check suspicious website links and files for known security threats in plain, everyday language (available in English, Hindi, and Gujarati).

## Architecture

- **Frontend**: React 19 + TypeScript + Tailwind CSS v4 (`src/`)
- **Backend API**: Node.js + Express + TypeScript (`server.ts`, `server/`)
- **Website URL Scanning**: Google Web Risk Lookup API (`uris:search`) via server-side adapter (`server/webRiskClient.ts`)
- **File Scanning**: Isolated ClamAV antivirus service (`clamav-service/`) deployed separately on Google Cloud Run and accessed via authenticated adapter (`server/clamavClient.ts`)
- **No Accounts / No History**: Zero user registration, zero personal data storage, and automatic temporary file deletion after scanning.

---

## Environment Variables

Copy `.env.example` to `.env` for local development or configure secrets in Google Cloud Secret Manager / AI Studio Secrets:

| Variable | Required | Description |
| --- | --- | --- |
| `WEBRISK_API_KEY` | Yes (for URL scans) | Server-side Google Web Risk API key. Never exposed to the browser. |
| `CLAMAV_SCANNER_URL` | Yes (for file scans) | Base URL of the separate ClamAV Cloud Run service (e.g. `https://safecheck-clamav-xxxx.run.app`). |
| `CLAMAV_SCANNER_TOKEN` | Recommended (required in prod) | Shared bearer token sent by the main backend to authenticate with the ClamAV service. |
| `MAX_FILE_SIZE_MB` | Optional (default `25`) | Maximum allowed uploaded file size in megabytes. |
| `APP_URL` | Optional | Public URL of the app used for strict CORS origin matching. |

> **Honest Fallback Behavior**: If `WEBRISK_API_KEY` or `CLAMAV_SCANNER_URL` is not configured, SafeCheck never simulates or fakes a "safe" scan. It returns an `"unavailable"` status and displays **"Unable to Complete Scan"** with a clear explanation.

---

## Local Setup

1. Install dependencies:
   ```bash
   npm install
   ```
2. Configure environment variables in `.env` (see `.env.example`).
3. Start the full-stack development server (port 3000):
   ```bash
   npm run dev
   ```
4. Run unit and integration tests:
   ```bash
   npm test
   ```
5. Build for production:
   ```bash
   npm run build
   npm start
   ```

---

## Google Web Risk Setup

1. In Google Cloud Console, select your project and enable the **Web Risk API** (`webrisk.googleapis.com`).
2. Create an API key under **APIs & Services → Credentials** and restrict it by **API** to the **Web Risk API** (do **not** set HTTP referrer restrictions, as SafeCheck calls Web Risk strictly from the Node.js backend).
3. Store the key securely in **Google Cloud Secret Manager** (or AI Studio Secrets) as `WEBRISK_API_KEY`.
4. SafeCheck checks `MALWARE`, `SOCIAL_ENGINEERING`, and `UNWANTED_SOFTWARE` using `GET https://webrisk.googleapis.com/v1/uris:search`.
5. Keep usage within free/budgeted quotas using GCP Billing Alerts and SafeCheck's built-in `/api/scan/*` rate limiter.

---

## ClamAV Scanner Service Setup (Separate Cloud Run Service)

The separate ClamAV service lives in `/clamav-service/`.

1. **Build and deploy the ClamAV service** (restricting ingress or requiring authentication):
   ```bash
   cd clamav-service
   gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/safecheck-clamav
   gcloud run deploy safecheck-clamav \
     --image gcr.io/YOUR_PROJECT_ID/safecheck-clamav \
     --region asia-east1 \
     --memory 2Gi \
     --cpu 1 \
     --concurrency 4 \
     --timeout 60 \
     --no-allow-unauthenticated \
     --set-secrets CLAMAV_SCANNER_TOKEN=CLAMAV_SCANNER_TOKEN:latest
   ```
   *(If deploying with `--allow-unauthenticated` for service-to-service bearer auth, ensure `CLAMAV_SCANNER_TOKEN` is a high-entropy secret stored in Secret Manager so unauthorized callers receive HTTP 401.)*

2. **Scheduled Signature Updates (`freshclam` & Cloud Scheduler)**:
   - On startup, the container runs `freshclam` before launching `clamd`.
   - For long-lived warm instances or scheduled refreshes, configure a **Cloud Scheduler** job that triggers a lightweight Cloud Run Job or periodic container revision/restart so `freshclam` pulls updated signatures daily without hitting mirror rate limits.

3. **Temporary File Storage (Optional Private Cloud Storage Bucket)**:
   - By default, SafeCheck streams uploads through isolated `os.tmpdir()` files with UUID names and deletes them in a `finally` block.
   - If you expand to asynchronous scanning with Google Cloud Storage, create a **private** bucket (`--public-access-prevention`) with a **1-day Object Lifecycle Delete rule** and uniform bucket-level access so temporary objects are never publicly reachable or permanently retained.

---

## Main Application Deployment (Google Cloud Run)

1. Build and deploy the main SafeCheck web app:
   ```bash
   gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/safecheck-web
   gcloud run deploy safecheck-web \
     --image gcr.io/YOUR_PROJECT_ID/safecheck-web \
     --region asia-east1 \
     --port 3000 \
     --allow-unauthenticated \
     --set-env-vars MAX_FILE_SIZE_MB=25,NODE_ENV=production \
     --set-secrets WEBRISK_API_KEY=WEBRISK_API_KEY:latest,CLAMAV_SCANNER_URL=CLAMAV_SCANNER_URL:latest,CLAMAV_SCANNER_TOKEN=CLAMAV_SCANNER_TOKEN:latest
   ```

---

## API Documentation

### `GET /api/health`
Returns operational readiness for the web server, Web Risk configuration, and ClamAV service connectivity (without exposing secrets or internal URLs).

### `POST /api/scan/url`
Validates and normalizes an HTTP/HTTPS URL, blocks private/loopback/metadata addresses (SSRF protection), and checks Google Web Risk.
- **Request**: `{ "url": "https://example.com" }`
- **Response**:
  ```json
  {
    "status": "clean | threat | unavailable",
    "scanType": "url",
    "scannedItem": "https://example.com/",
    "scannerName": "Google Web Risk Lookup API",
    "timestamp": "2026-11-24T12:00:00.000Z",
    "categoriesChecked": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
    "threats": [],
    "error": { "code": "...", "message": "..." }
  }
  ```

### `POST /api/scan/file`
Accepts a `multipart/form-data` upload (`file` field), verifies file size (`<= MAX_FILE_SIZE_MB`), validates magic-byte file signatures and ZIP decompression limits, forwards to ClamAV, and unconditionally deletes the temporary file.

---

## Error-Handling Reference

| Code | HTTP | Meaning |
| --- | --- | --- |
| `INVALID_URL` | 400 | URL is malformed or uses a scheme other than `http:` / `https:`. |
| `SSRF_BLOCKED` | 400 | Localhost, private IP ranges, or cloud metadata addresses are blocked. |
| `NO_FILE` | 400 | No file was attached to `/api/scan/file`. |
| `UNSUPPORTED_FILE` | 400 | Magic-byte file signature does not match a supported format. |
| `CORRUPTED_FILE` | 400 | File is empty or exceeds safe archive entry/decompression limits. |
| `FILE_TOO_LARGE` | 413 | File exceeds `MAX_FILE_SIZE_MB`. |
| `RATE_LIMITED` | 429 | Client exceeded per-minute scan limit. |
| `SERVICE_UNCONFIGURED` | 200 (status `unavailable`) | Required `WEBRISK_API_KEY` or `CLAMAV_SCANNER_URL` is not configured or invalid. |
| `API_QUOTA_EXCEEDED` | 200 (status `unavailable`) | Upstream API quota temporarily exhausted. |
| `TIMEOUT` / `SERVICE_UNAVAILABLE` | 200 (status `unavailable`) | Upstream scanner timed out or could not be reached. |
