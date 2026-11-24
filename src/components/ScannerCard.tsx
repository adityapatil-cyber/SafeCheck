import { AlertCircle, FileText, Link2, Upload, X } from 'lucide-react';
import { useRef, useState, type DragEvent, type FormEvent } from 'react';
import { useTranslation } from '../i18n/index.tsx';
import type { ScanErrorCode, ScanType } from '../types/scan.ts';
import {
  ACCEPTED_EXTENSIONS,
  formatFileSize,
  validateClientFile,
  validateClientUrl,
} from '../utils/validation.ts';

interface ScannerCardProps {
  activeTab: ScanType;
  onTabChange: (tab: ScanType) => void;
  urlInput: string;
  onUrlChange: (value: string) => void;
  selectedFile: File | null;
  onFileSelect: (file: File | null) => void;
  onScanUrl: (url: string) => void;
  onScanFile: (file: File) => void;
  isScanning: boolean;
}

export function ScannerCard({
  activeTab,
  onTabChange,
  urlInput,
  onUrlChange,
  selectedFile,
  onFileSelect,
  onScanUrl,
  onScanFile,
  isScanning,
}: ScannerCardProps) {
  const { t } = useTranslation();
  const [validationError, setValidationError] = useState<ScanErrorCode | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleTabSwitch = (tab: ScanType) => {
    setValidationError(null);
    onTabChange(tab);
  };

  const handleUrlSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (isScanning) return;

    const check = validateClientUrl(urlInput);
    if (!check.valid || !check.normalizedInput) {
      setValidationError(check.errorCode ?? 'INVALID_URL');
      return;
    }

    onUrlChange(check.normalizedInput);
    setValidationError(null);
    onScanUrl(check.normalizedInput);
  };

  const handleFileChosen = (file: File | null) => {
    if (!file) {
      onFileSelect(null);
      setValidationError(null);
      return;
    }
    const check = validateClientFile(file);
    if (!check.valid) {
      onFileSelect(null);
      setValidationError(check.errorCode ?? 'UNSUPPORTED_FILE');
      return;
    }
    setValidationError(null);
    onFileSelect(file);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (isScanning) return;
    const droppedFile = e.dataTransfer.files?.[0] ?? null;
    handleFileChosen(droppedFile);
  };

  const handleFileSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (isScanning) return;
    const check = validateClientFile(selectedFile);
    if (!check.valid || !selectedFile) {
      setValidationError(check.errorCode ?? 'NO_FILE');
      return;
    }
    setValidationError(null);
    onScanFile(selectedFile);
  };

  const getFileExtensionLabel = (file: File): string => {
    const idx = file.name.lastIndexOf('.');
    if (idx >= 0) {
      return file.name.slice(idx + 1).toUpperCase();
    }
    return file.type || 'Unknown';
  };

  return (
    <section
      aria-label="Security scanner"
      className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs sm:p-8"
    >
      {/* Segmented Tab Switcher */}
      <div
        role="tablist"
        aria-label="Scan mode"
        className="grid grid-cols-2 gap-1.5 rounded-xl bg-slate-100 p-1.5"
      >
        <button
          type="button"
          role="tab"
          id="tab-url"
          aria-selected={activeTab === 'url'}
          aria-controls="panel-url"
          disabled={isScanning}
          onClick={() => handleTabSwitch('url')}
          className={`flex min-h-11 items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold whitespace-nowrap transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 ${
            activeTab === 'url'
              ? 'bg-white text-slate-900 shadow-xs'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <Link2 className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{t.scanner.tabUrl}</span>
        </button>

        <button
          type="button"
          role="tab"
          id="tab-file"
          aria-selected={activeTab === 'file'}
          aria-controls="panel-file"
          disabled={isScanning}
          onClick={() => handleTabSwitch('file')}
          className={`flex min-h-11 items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold whitespace-nowrap transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 ${
            activeTab === 'file'
              ? 'bg-white text-slate-900 shadow-xs'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <Upload className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{t.scanner.tabFile}</span>
        </button>
      </div>

      {/* TAB 1: Website Link */}
      {activeTab === 'url' && (
        <form
          id="panel-url"
          role="tabpanel"
          aria-labelledby="tab-url"
          onSubmit={handleUrlSubmit}
          noValidate
          className="mt-6 space-y-4"
        >
          <div>
            <label
              htmlFor="safecheck-url-input"
              className="mb-2 block text-sm font-medium text-slate-800"
            >
              {t.scanner.urlLabel}
            </label>
            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                id="safecheck-url-input"
                type="url"
                inputMode="url"
                autoComplete="off"
                spellCheck={false}
                value={urlInput}
                onChange={(e) => {
                  onUrlChange(e.target.value);
                  if (validationError) setValidationError(null);
                }}
                placeholder={t.scanner.urlPlaceholder}
                aria-invalid={validationError ? 'true' : 'false'}
                aria-describedby={validationError ? 'scanner-validation-error' : 'url-helper-text'}
                disabled={isScanning}
                className="min-h-13 w-full flex-1 rounded-xl border border-slate-300 bg-white px-4 py-3 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900/10 disabled:bg-slate-50"
              />
              <button
                type="submit"
                disabled={isScanning}
                className="inline-flex min-h-13 shrink-0 items-center justify-center rounded-xl bg-slate-900 px-6 py-3 text-sm font-semibold text-white whitespace-nowrap transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isScanning ? t.scanner.scanningButton : t.scanner.checkLinkButton}
              </button>
            </div>
          </div>

          {validationError && (
            <div
              id="scanner-validation-error"
              role="alert"
              className="flex items-start gap-2.5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" aria-hidden="true" />
              <span>{t.errors[validationError]}</span>
            </div>
          )}

          <div id="url-helper-text" className="space-y-1.5 text-sm text-slate-600">
            <p>{t.scanner.urlHelper}</p>
            <p className="text-xs leading-relaxed text-slate-500">{t.scanner.urlDownloadNote}</p>
          </div>
        </form>
      )}

      {/* TAB 2: Upload a File */}
      {activeTab === 'file' && (
        <form
          id="panel-file"
          role="tabpanel"
          aria-labelledby="tab-file"
          onSubmit={handleFileSubmit}
          noValidate
          className="mt-6 space-y-5"
        >
          <div
            onDragOver={(e) => {
              e.preventDefault();
              if (!isScanning) setIsDragOver(true);
            }}
            onDragLeave={(e) => {
              if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
                setIsDragOver(false);
              }
            }}
            onDrop={handleDrop}
            className={`rounded-xl border-2 border-dashed p-6 text-center transition-colors sm:p-8 ${
              isDragOver
                ? 'border-slate-900 bg-slate-50'
                : 'border-slate-300 bg-slate-50/50 hover:border-slate-400'
            }`}
          >
            <input
              ref={fileInputRef}
              id="safecheck-file-input"
              type="file"
              tabIndex={-1}
              aria-hidden="true"
              accept={ACCEPTED_EXTENSIONS.join(',')}
              disabled={isScanning}
              onChange={(e) => {
                const file = e.target.files?.[0] ?? null;
                handleFileChosen(file);
                e.currentTarget.value = '';
              }}
              className="sr-only"
            />

            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-700">
              <Upload className="h-5 w-5" aria-hidden="true" />
            </div>

            <p className="mt-3 text-base font-medium text-slate-900">{t.scanner.dropzoneTitle}</p>

            <div className="mt-3">
              <button
                type="button"
                disabled={isScanning}
                onClick={() => fileInputRef.current?.click()}
                className="inline-flex min-h-11 items-center justify-center rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-800 whitespace-nowrap transition-colors hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 disabled:opacity-60"
              >
                {t.scanner.dropzoneBrowse}
              </button>
            </div>

            <div className="mt-4 space-y-1 text-xs text-slate-500">
              <p>
                <span className="font-medium text-slate-600">{t.scanner.acceptedFormatsLabel}</span>{' '}
                {t.scanner.acceptedFormatsList}
              </p>
              <p>{t.scanner.maxFileSizeLabel}</p>
            </div>
          </div>

          {selectedFile && (
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex min-w-0 items-start gap-3">
                  <FileText className="mt-0.5 h-5 w-5 shrink-0 text-slate-700" aria-hidden="true" />
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-500">
                      {t.scanner.selectedFileLabel}
                    </p>
                    <p className="mt-0.5 truncate font-mono text-sm font-medium text-slate-900">
                      {selectedFile.name}
                    </p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-600 tabular-nums">
                      <span>
                        {t.scanner.fileSizeLabel}: {formatFileSize(selectedFile.size)}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>
                        {t.scanner.fileTypeLabel}: {getFileExtensionLabel(selectedFile)}
                      </span>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  disabled={isScanning}
                  onClick={() => {
                    onFileSelect(null);
                    if (fileInputRef.current) fileInputRef.current.value = '';
                  }}
                  aria-label={t.scanner.removeFileLabel}
                  className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-slate-500 transition-colors hover:bg-slate-200/70 hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>
            </div>
          )}

          {validationError && (
            <div
              id="scanner-validation-error"
              role="alert"
              className="flex items-start gap-2.5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" aria-hidden="true" />
              <span>{t.errors[validationError]}</span>
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={isScanning || !selectedFile}
              className="inline-flex min-h-12 w-full items-center justify-center rounded-xl bg-slate-900 px-6 py-3 text-sm font-semibold text-white whitespace-nowrap transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
            >
              {isScanning ? t.scanner.scanningButton : t.scanner.scanFileButton}
            </button>
          </div>
        </form>
      )}
    </section>
  );
}
