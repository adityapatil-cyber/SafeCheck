import {
  AlertOctagon,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ExternalLink,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { useTranslation } from '../i18n/index.tsx';
import type { ScanResponse } from '../types/scan.ts';
import { formatFileSize } from '../utils/validation.ts';

interface ScanResultProps {
  result: ScanResponse;
  onRetry: () => void;
  onReset: () => void;
}

function isSafeHttpUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

export function ScanResult({ result, onRetry, onReset }: ScanResultProps) {
  const { language, t } = useTranslation();

  const formattedTime = new Intl.DateTimeFormat(
    language === 'hi' ? 'hi-IN' : language === 'gu' ? 'gu-IN' : 'en-US',
    {
      dateStyle: 'medium',
      timeStyle: 'medium',
    },
  ).format(new Date(result.timestamp));

  const statusConfig = {
    clean: {
      heading: t.results.cleanHeading,
      description: t.results.cleanDescription,
      statusText: t.results.statusClean,
      containerClass: 'border-emerald-200 bg-emerald-50/70',
      iconWrapperClass: 'bg-emerald-100 text-emerald-700',
      titleClass: 'text-emerald-950',
      descClass: 'text-emerald-900/90',
      Icon: ShieldCheck,
    },
    warning: {
      heading: t.results.warningHeading,
      description: t.results.warningDescription,
      statusText: t.results.statusWarning,
      containerClass: 'border-orange-200 bg-orange-50/80',
      iconWrapperClass: 'bg-orange-100 text-orange-700',
      titleClass: 'text-orange-950',
      descClass: 'text-orange-900/90',
      Icon: ShieldAlert,
    },
    threat: {
      heading: t.results.threatHeading,
      description: t.results.threatDescription,
      statusText: t.results.statusThreat,
      containerClass: 'border-red-200 bg-red-50/80',
      iconWrapperClass: 'bg-red-100 text-red-700',
      titleClass: 'text-red-950',
      descClass: 'text-red-900/90',
      Icon: AlertOctagon,
    },
    unavailable: {
      heading: t.results.unavailableHeading,
      description: t.results.unavailableDescription,
      statusText: t.results.statusUnavailable,
      containerClass: 'border-amber-200 bg-amber-50/70',
      iconWrapperClass: 'bg-amber-100 text-amber-800',
      titleClass: 'text-slate-900',
      descClass: 'text-slate-700',
      Icon: AlertTriangle,
    },
  }[result.status];

  const StatusIcon = statusConfig.Icon;

  const nextSteps =
    result.status === 'clean'
      ? result.scanType === 'url'
        ? t.results.nextStepsCleanUrl
        : t.results.nextStepsCleanFile
      : result.status === 'warning'
        ? t.results.nextStepsWarningUrl
        : result.status === 'threat'
          ? result.scanType === 'url'
            ? t.results.nextStepsThreatUrl
            : t.results.nextStepsThreatFile
          : t.results.nextStepsUnavailable;

  const translatedCategories = result.categoriesChecked.map(
    (cat) => t.results.categoryLabels[cat] ?? cat,
  );

  const errorReasonText =
    result.error?.code === 'SERVICE_UNCONFIGURED'
      ? result.scanType === 'url'
        ? t.results.unconfiguredUrlReason
        : t.results.unconfiguredFileReason
      : result.error?.code
        ? t.errors[result.error.code] ?? result.error.message
        : result.error?.message;

  const safeSources = (result.botAnalysis?.sources ?? []).filter((src) => isSafeHttpUrl(src.url));

  return (
    <section
      aria-live="polite"
      className="space-y-6 rounded-2xl border border-slate-200 bg-white p-5 shadow-xs sm:p-8"
    >
      {/* 1. Security Status */}
      <div>
        <h2 className="text-sm font-semibold text-slate-900">
          {t.results.sectionSecurityStatus}
        </h2>

        <div
          className={`mt-3 rounded-xl border p-5 sm:p-6 ${statusConfig.containerClass}`}
        >
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
            <div
              className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl ${statusConfig.iconWrapperClass}`}
            >
              <StatusIcon className="h-6 w-6" aria-hidden="true" />
            </div>
            <div className="min-w-0 flex-1">
              <h3 className={`text-xl font-bold sm:text-2xl ${statusConfig.titleClass}`}>
                {statusConfig.heading}
              </h3>
              <p className={`mt-2 text-sm leading-relaxed sm:text-base ${statusConfig.descClass}`}>
                {statusConfig.description}
              </p>

              {result.status === 'unavailable' && errorReasonText && (
                <p className="mt-3 border-t border-amber-200/70 pt-3 text-sm font-medium text-slate-800">
                  <span className="text-slate-600">{t.results.labelReason}: </span>
                  {errorReasonText}
                </p>
              )}

              {(result.status === 'threat' || result.status === 'warning') &&
                result.threats &&
                result.threats.length > 0 && (
                  <ul
                    className={`mt-3 space-y-1.5 border-t pt-3 text-sm ${
                      result.status === 'threat'
                        ? 'border-red-200/70 text-red-950'
                        : 'border-orange-200/70 text-orange-950'
                    }`}
                  >
                    {result.threats.map((threat, idx) => (
                      <li key={`${threat.type}-${idx}`} className="flex flex-wrap gap-x-2">
                        <span className="font-semibold">
                          {t.results.categoryLabels[threat.type] ?? threat.type}:
                        </span>
                        <span>{threat.description}</span>
                      </li>
                    ))}
                  </ul>
                )}
            </div>
          </div>
        </div>
      </div>

      {/* 1b. AI Web Search & Threat-Feed Analysis */}
      {result.botAnalysis && (
        <div className="border-t border-slate-100 pt-5">
          <h2 className="text-sm font-semibold text-slate-900">
            {t.results.sectionBotAnalysis}
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-slate-700">
            {result.botAnalysis.summary}
          </p>

          {result.botAnalysis.findings.length > 0 && (
            <ul className="mt-3 space-y-1.5 text-sm text-slate-700">
              {result.botAnalysis.findings.map((finding, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span
                    className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-400"
                    aria-hidden="true"
                  />
                  <span>{finding}</span>
                </li>
              ))}
            </ul>
          )}

          {result.botAnalysis.feedsChecked.length > 0 && (
            <div className="mt-4">
              <p className="text-xs font-medium text-slate-500">{t.results.labelFeedsChecked}</p>
              <p className="mt-1 text-xs text-slate-700 sm:text-sm">
                {result.botAnalysis.feedsChecked.join(' · ')}
              </p>
            </div>
          )}

          {safeSources.length > 0 && (
            <div className="mt-4">
              <p className="text-xs font-medium text-slate-500">{t.results.labelSourcesChecked}</p>
              <ul className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1.5">
                {safeSources.map((src) => (
                  <li key={src.url}>
                    <a
                      href={src.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 underline decoration-slate-300 underline-offset-2 transition-colors hover:text-slate-950 hover:decoration-slate-600 sm:text-sm"
                    >
                      <span>{src.title}</span>
                      <ExternalLink className="h-3 w-3 shrink-0 text-slate-400" aria-hidden="true" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* 2. What Was Checked */}
      <div className="border-t border-slate-100 pt-5">
        <h2 className="text-sm font-semibold text-slate-900">
          {t.results.sectionWhatChecked}
        </h2>
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          <div>
            <p className="text-xs font-medium text-slate-500">{t.results.labelScannerUsed}</p>
            <p className="mt-1 text-sm font-medium text-slate-900">{result.scannerName}</p>
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500">
              {t.results.labelCategoriesChecked}
            </p>
            <p className="mt-1 text-sm text-slate-800">
              {translatedCategories.length > 0 ? translatedCategories.join(' · ') : '—'}
            </p>
          </div>
        </div>
      </div>

      {/* 3. Technical Information */}
      <div className="border-t border-slate-100 pt-5">
        <h2 className="text-sm font-semibold text-slate-900">
          {t.results.sectionTechnicalInfo}
        </h2>
        <dl className="mt-3 divide-y divide-slate-100 border-t border-b border-slate-100">
          <div className="grid grid-cols-1 gap-1 py-3 sm:grid-cols-3 sm:gap-4">
            <dt className="text-xs font-medium text-slate-500">{t.results.labelScannedItem}</dt>
            <dd className="break-all font-mono text-xs text-slate-900 sm:col-span-2 sm:text-sm">
              {result.scannedItem || '—'}
            </dd>
          </div>

          <div className="grid grid-cols-1 gap-1 py-3 sm:grid-cols-3 sm:gap-4">
            <dt className="text-xs font-medium text-slate-500">{t.results.labelScanStatus}</dt>
            <dd className="text-sm font-medium text-slate-900 sm:col-span-2">
              {statusConfig.statusText}
            </dd>
          </div>

          <div className="grid grid-cols-1 gap-1 py-3 sm:grid-cols-3 sm:gap-4">
            <dt className="text-xs font-medium text-slate-500">{t.results.labelScanTime}</dt>
            <dd className="text-sm text-slate-800 tabular-nums sm:col-span-2">
              {formattedTime}
            </dd>
          </div>

          {result.fileInfo && (
            <>
              <div className="grid grid-cols-1 gap-1 py-3 sm:grid-cols-3 sm:gap-4">
                <dt className="text-xs font-medium text-slate-500">{t.results.labelFileType}</dt>
                <dd className="text-sm text-slate-800 sm:col-span-2">
                  {result.fileInfo.detectedType}
                </dd>
              </div>
              <div className="grid grid-cols-1 gap-1 py-3 sm:grid-cols-3 sm:gap-4">
                <dt className="text-xs font-medium text-slate-500">{t.results.labelFileSize}</dt>
                <dd className="text-sm text-slate-800 tabular-nums sm:col-span-2">
                  {formatFileSize(result.fileInfo.sizeBytes)}
                </dd>
              </div>
            </>
          )}

          {result.threats && result.threats.length > 0 && (
            <div className="grid grid-cols-1 gap-1 py-3 sm:grid-cols-3 sm:gap-4">
              <dt className="text-xs font-medium text-slate-500">
                {t.results.labelDetectedCategory}
              </dt>
              <dd className="font-mono text-xs text-red-700 sm:col-span-2 sm:text-sm">
                {result.threats.map((th) => th.type).join(', ')}
              </dd>
            </div>
          )}

          {result.technicalDetails?.apiResponse && (
            <div className="grid grid-cols-1 gap-1 py-3 sm:grid-cols-3 sm:gap-4">
              <dt className="text-xs font-medium text-slate-500">
                {t.results.labelScannerResponse}
              </dt>
              <dd className="font-mono text-xs text-slate-700 sm:col-span-2 sm:text-sm">
                {result.technicalDetails.apiResponse}
              </dd>
            </div>
          )}
        </dl>
      </div>

      {/* 4. What Should I Do Next? */}
      <div className="border-t border-slate-100 pt-5">
        <h2 className="text-sm font-semibold text-slate-900">{t.results.sectionNextSteps}</h2>
        <ul className="mt-3 space-y-2.5">
          {nextSteps.map((step) => (
            <li key={step} className="flex items-start gap-2.5 text-sm leading-relaxed text-slate-700">
              <CheckCircle2
                className="mt-0.5 h-4 w-4 shrink-0 text-slate-400"
                aria-hidden="true"
              />
              <span>{step}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-5">
        {result.status === 'unavailable' && (
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white whitespace-nowrap transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
          >
            <RotateCcw className="h-4 w-4" aria-hidden="true" />
            <span>{t.results.tryAgainButton}</span>
          </button>
        )}

        <button
          type="button"
          onClick={onReset}
          className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-5 py-2.5 text-sm font-semibold whitespace-nowrap transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 ${
            result.status === 'unavailable'
              ? 'border border-slate-300 bg-white text-slate-800 hover:bg-slate-50'
              : 'bg-slate-900 text-white hover:bg-slate-800'
          }`}
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          <span>{t.results.scanAnotherButton}</span>
        </button>
      </div>
    </section>
  );
}
