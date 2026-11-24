# SafeCheck ClamAV Scanning Service

Standalone HTTP scanning service wrapping `clamd` / `clamdscan` for SafeCheck on Google Cloud Run.

## Endpoints

- `GET /health` — Runs `clamdscan --ping 3` to verify the ClamAV daemon and signature database are loaded.
- `POST /scan` — Accepts a single `multipart/form-data` file (`file` field), writes to an isolated UUID temp file, scans via `clamdscan --no-summary --fdpass`, deletes the temp file in `finally`, and returns:
  - Clean: `{ "status": "clean", "signature": null, "engine": "ClamAV Antivirus Engine" }`
  - Infected: `{ "status": "infected", "signature": "<signature-name>", "engine": "ClamAV Antivirus Engine" }`

## Security Controls

- **Bearer Authentication**: Set `CLAMAV_SCANNER_TOKEN` in Cloud Run Secret Manager. In production (`NODE_ENV=production`), requests without a matching `Authorization: Bearer <token>` header are rejected.
- **No Shell Execution**: Uses `execFile('clamdscan', ...)` directly with resolved temp paths confined to `os.tmpdir()/clamav-scan-tmp`.
- **Archive Bomb Limits**: `clamd.conf` enforces `MaxFileSize 30M`, `MaxScanSize 100M`, `MaxRecursion 10`, and `MaxFiles 2000`.
- **Signature Updates**: `freshclam` updates malware definitions at image build and container startup. Schedule daily Cloud Run redeployments or Cloud Run Jobs via Cloud Scheduler to keep signatures current.
