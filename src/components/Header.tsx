import { Globe, ShieldCheck } from 'lucide-react';
import { LANGUAGE_OPTIONS, useTranslation } from '../i18n/index.tsx';
import type { AppPage, SupportedLanguage } from '../types/scan.ts';

interface HeaderProps {
  currentPage: AppPage;
  onNavigate: (page: AppPage) => void;
}

export function Header({ currentPage, onNavigate }: HeaderProps) {
  const { language, setLanguage, t } = useTranslation();

  const navItems: Array<{ page: AppPage; label: string }> = [
    { page: 'home', label: t.nav.scanner },
    { page: 'how-it-works', label: t.nav.howItWorks },
    { page: 'about', label: t.nav.about },
    { page: 'privacy', label: t.nav.privacy },
  ];

  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4 px-4 py-3.5 sm:px-6 md:flex-nowrap md:gap-8">
        {/* Zone 1: Brand mark */}
        <button
          type="button"
          onClick={() => onNavigate('home')}
          className="inline-flex min-h-10 shrink-0 items-center gap-2.5 rounded-lg px-1 text-left text-slate-900 transition-colors hover:text-slate-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 whitespace-nowrap"
        >
          <ShieldCheck className="h-6 w-6 text-slate-900" aria-hidden="true" />
          <span className="text-lg font-bold tracking-tight">{t.brandName}</span>
        </button>

        {/* Zone 2: Navigation links */}
        <nav
          aria-label="Primary navigation"
          className="order-3 flex w-full items-center gap-5 overflow-x-auto border-t border-slate-100 pt-2.5 text-sm font-medium text-slate-600 md:order-2 md:w-auto md:border-t-0 md:pt-0"
        >
          {navItems.map((item) => {
            const isActive = currentPage === item.page;
            return (
              <button
                key={item.page}
                type="button"
                onClick={() => onNavigate(item.page)}
                aria-current={isActive ? 'page' : undefined}
                className={`min-h-9 shrink-0 whitespace-nowrap border-b-2 px-0.5 py-1 transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 ${
                  isActive
                    ? 'border-slate-900 font-semibold text-slate-900'
                    : 'border-transparent text-slate-600 hover:border-slate-300 hover:text-slate-900'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Language selector */}
        <div className="order-2 flex shrink-0 items-center gap-2 md:order-3">
          <Globe className="h-4 w-4 text-slate-500" aria-hidden="true" />
          <label htmlFor="safecheck-language-select" className="sr-only">
            {t.nav.languageLabel}
          </label>
          <select
            id="safecheck-language-select"
            value={language}
            onChange={(e) => setLanguage(e.target.value as SupportedLanguage)}
            aria-label={t.nav.languageLabel}
            className="min-h-10 cursor-pointer rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-800 transition-colors hover:border-slate-300 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
          >
            {LANGUAGE_OPTIONS.map((opt) => (
              <option key={opt.code} value={opt.code}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>
    </header>
  );
}
