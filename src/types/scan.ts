export type ScanStatus = 'clean' | 'warning' | 'threat' | 'unavailable';

export type ScanType = 'url' | 'file';

export type ScanErrorCode =
  | 'INVALID_URL'
  | 'SSRF_BLOCKED'
  | 'SERVICE_UNCONFIGURED'
  | 'API_KEY_INVALID'
  | 'SERVICE_UNAVAILABLE'
  | 'API_ERROR'
  | 'API_QUOTA_EXCEEDED'
  | 'TIMEOUT'
  | 'FILE_TOO_LARGE'
  | 'UNSUPPORTED_FILE'
  | 'CORRUPTED_FILE'
  | 'NO_FILE'
  | 'RATE_LIMITED'
  | 'INTERNAL_ERROR';

export interface ThreatDetail {
  type: string;
  description: string;
  expireTime?: string;
}

export interface FileScanInfo {
  fileName: string;
  sizeBytes: number;
  detectedType: string;
  mimeType: string;
}

export interface ScanErrorInfo {
  code: ScanErrorCode;
  message: string;
}

export interface GroundingSource {
  title: string;
  url: string;
}

export interface BotAnalysisInfo {
  summary: string;
  findings: string[];
  sources: GroundingSource[];
  feedsChecked: string[];
}

export interface ScanResponse {
  status: ScanStatus;
  scanType: ScanType;
  scannedItem: string;
  scannerName: string;
  timestamp: string;
  categoriesChecked: string[];
  threats?: ThreatDetail[];
  fileInfo?: FileScanInfo;
  botAnalysis?: BotAnalysisInfo;
  technicalDetails?: Record<string, string>;
  error?: ScanErrorInfo;
}

export type AppPage = 'home' | 'how-it-works' | 'about' | 'privacy';

export type SupportedLanguage = 'en' | 'hi' | 'gu';
