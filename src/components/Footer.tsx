import { ShieldCheck } from 'lucide-react';
import { useTranslation } from '../i18n/index.tsx';
import type { AppPage } from '../types/scan.ts';

interface FooterProps {
  onNavigate: (page: AppPage) => void;
}

export function Footer({ onNavigate }: FooterProps) {
  const { t } = useTranslation();

  return (
    <footer className="mt-16 border-t border-slate-200 bg-white">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
        <div className="flex flex-col justify-between gap-6 sm:flex-row sm:items-center">
          <div className="inline-flex items-center gap-2 text-slate-900">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            <span className="text-base font-bold tracking-tight">{t.brandName}</span>
          </div>

          <nav aria-label="Footer navigation" className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-slate-600">
            <button
              type="button"
              onClick={() => onNavigate('about')}
              className="min-h-9 whitespace-nowrap hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
            >
              {t.footer.about}
            </button>
            <button
              type="button"
              onClick={() => onNavigate('privacy')}
              className="min-h-9 whitespace-nowrap hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
            >
              {t.footer.privacy}
            </button>
            <button
              type="button"
              onClick={() => onNavigate('how-it-works')}
              className="min-h-9 whitespace-nowrap hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
            >
              {t.footer.howItWorks}
            </button>
            <span className="whitespace-nowrap text-slate-500">
              {t.footer.contactLabel}{' '}
              <span className="font-mono text-xs text-slate-700">{t.footer.contactEmail}</span>
            </span>
          </nav>
        </div>

        <p className="mt-6 border-t border-slate-100 pt-5 text-xs leading-relaxed text-slate-500">
          {t.footer.disclaimer}
        </p>
      </div>
    </footer>
  );
}
