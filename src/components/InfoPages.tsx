import { ArrowLeft } from 'lucide-react';
import { useTranslation } from '../i18n/index.tsx';
import type { AppPage } from '../types/scan.ts';

interface SubPageProps {
  onNavigate: (page: AppPage) => void;
}

export function HowItWorksPage({ onNavigate }: SubPageProps) {
  const { t } = useTranslation();

  const steps = [
    { title: t.howItWorks.urlStepTitle, body: t.howItWorks.urlStepBody },
    { title: t.howItWorks.fileStepTitle, body: t.howItWorks.fileStepBody },
    { title: t.howItWorks.honestStepTitle, body: t.howItWorks.honestStepBody },
  ];

  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs sm:p-10">
      <h1 className="text-2xl font-bold tracking-tight text-slate-900 sm:text-3xl">
        {t.howItWorks.heading}
      </h1>
      <p className="mt-3 max-w-2xl text-base leading-relaxed text-slate-600">
        {t.howItWorks.intro}
      </p>

      <div className="mt-8 space-y-6 border-t border-slate-100 pt-6">
        {steps.map((step) => (
          <section key={step.title} className="space-y-2">
            <h2 className="text-lg font-semibold text-slate-900">{step.title}</h2>
            <p className="max-w-2xl text-sm leading-relaxed text-slate-600 sm:text-base">
              {step.body}
            </p>
          </section>
        ))}
      </div>

      <div className="mt-8 border-t border-slate-100 pt-6">
        <button
          type="button"
          onClick={() => onNavigate('home')}
          className="inline-flex min-h-11 items-center gap-2 rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white whitespace-nowrap transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          <span>{t.howItWorks.backToScanner}</span>
        </button>
      </div>
    </article>
  );
}

export function AboutPage({ onNavigate }: SubPageProps) {
  const { t } = useTranslation();

  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs sm:p-10">
      <h1 className="text-2xl font-bold tracking-tight text-slate-900 sm:text-3xl">
        {t.about.heading}
      </h1>
      <p className="mt-4 max-w-2xl text-base leading-relaxed text-slate-700">{t.about.lead}</p>
      <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-600 sm:text-base">
        {t.about.layerParagraph}
      </p>

      <div className="mt-8 border-t border-slate-100 pt-6">
        <h2 className="text-lg font-semibold text-slate-900">{t.about.principlesHeading}</h2>
        <div className="mt-4 grid gap-5 sm:grid-cols-3">
          {t.about.principles.map((item) => (
            <div key={item.title} className="rounded-xl border border-slate-200 bg-slate-50/50 p-4">
              <h3 className="text-sm font-semibold text-slate-900">{item.title}</h3>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-600 sm:text-sm">
                {item.body}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-8 border-t border-slate-100 pt-6">
        <button
          type="button"
          onClick={() => onNavigate('home')}
          className="inline-flex min-h-11 items-center gap-2 rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white whitespace-nowrap transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          <span>{t.about.backToScanner}</span>
        </button>
      </div>
    </article>
  );
}

export function PrivacyPage({ onNavigate }: SubPageProps) {
  const { t } = useTranslation();

  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs sm:p-10">
      <h1 className="text-2xl font-bold tracking-tight text-slate-900 sm:text-3xl">
        {t.privacy.heading}
      </h1>
      <p className="mt-3 max-w-2xl text-base leading-relaxed text-slate-600">{t.privacy.intro}</p>

      <div className="mt-8 space-y-6 border-t border-slate-100 pt-6">
        {t.privacy.items.map((item) => (
          <section key={item.title} className="space-y-1.5">
            <h2 className="text-base font-semibold text-slate-900">{item.title}</h2>
            <p className="max-w-2xl text-sm leading-relaxed text-slate-600 sm:text-base">
              {item.body}
            </p>
          </section>
        ))}
      </div>

      <div className="mt-8 border-t border-slate-100 pt-6">
        <button
          type="button"
          onClick={() => onNavigate('home')}
          className="inline-flex min-h-11 items-center gap-2 rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white whitespace-nowrap transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          <span>{t.privacy.backToScanner}</span>
        </button>
      </div>
    </article>
  );
}
