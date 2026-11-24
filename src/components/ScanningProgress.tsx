import { Check, Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from '../i18n/index.tsx';
import type { ScanType } from '../types/scan.ts';

interface ScanningProgressProps {
  scanType: ScanType;
  targetLabel: string;
}

export function ScanningProgress({ scanType, targetLabel }: ScanningProgressProps) {
  const { t } = useTranslation();
  const [activeStageIndex, setActiveStageIndex] = useState(0);
  const [takingLonger, setTakingLonger] = useState(false);

  const stages = [
    t.loading.stageValidating,
    t.loading.stageConnecting,
    t.loading.stageChecking,
    t.loading.stagePreparing,
  ];

  useEffect(() => {
    setActiveStageIndex(0);
    setTakingLonger(false);

    // Advance only up to stage 2 ("Checking for threats") while waiting on network,
    // never pretending stage 4 ("Preparing report") finished before the server responds.
    const t1 = setTimeout(() => setActiveStageIndex(1), 350);
    const t2 = setTimeout(() => setActiveStageIndex(2), 950);
    const tLong = setTimeout(() => setTakingLonger(true), 4500);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(tLong);
    };
  }, [scanType, targetLabel]);

  return (
    <section
      aria-live="polite"
      aria-busy="true"
      className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs sm:p-8"
    >
      <div className="flex items-start gap-4">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-slate-50">
          <Loader2 className="h-5 w-5 animate-spin text-slate-900" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="text-xl font-semibold text-slate-900">
            {scanType === 'url' ? t.loading.headingUrl : t.loading.headingFile}
          </h2>
          <p className="mt-1 truncate font-mono text-sm text-slate-600">{targetLabel}</p>
        </div>
      </div>

      <ol className="mt-6 space-y-3 border-t border-slate-100 pt-5">
        {stages.map((label, idx) => {
          const isCompleted = idx < activeStageIndex;
          const isCurrent = idx === activeStageIndex;

          return (
            <li key={label} className="flex items-center gap-3 text-sm">
              <span
                className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-xs font-medium ${
                  isCompleted
                    ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                    : isCurrent
                      ? 'border-slate-900 bg-slate-900 text-white'
                      : 'border-slate-200 bg-white text-slate-400'
                }`}
              >
                {isCompleted ? (
                  <Check className="h-3.5 w-3.5" aria-hidden="true" />
                ) : isCurrent ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                ) : (
                  <span className="tabular-nums">{idx + 1}</span>
                )}
              </span>
              <span
                className={
                  isCompleted || isCurrent ? 'font-medium text-slate-900' : 'text-slate-400'
                }
              >
                {label}
              </span>
            </li>
          );
        })}
      </ol>

      {takingLonger && (
        <p className="mt-5 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
          {t.loading.takingLonger}
        </p>
      )}
    </section>
  );
}
