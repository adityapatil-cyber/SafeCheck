import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import type { SupportedLanguage } from '../types/scan.ts';
import { en } from './en.ts';
import { gu } from './gu.ts';
import { hi } from './hi.ts';
import type { TranslationDictionary } from './types.ts';

export const DICTIONARIES: Record<SupportedLanguage, TranslationDictionary> = {
  en,
  hi,
  gu,
};

export const LANGUAGE_OPTIONS: Array<{ code: SupportedLanguage; label: string }> = [
  { code: 'en', label: 'English' },
  { code: 'hi', label: 'हिन्दी (Hindi)' },
  { code: 'gu', label: 'ગુજરાતી (Gujarati)' },
];

interface I18nContextValue {
  language: SupportedLanguage;
  setLanguage: (lang: SupportedLanguage) => void;
  t: TranslationDictionary;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<SupportedLanguage>('en');

  const setLanguage = (lang: SupportedLanguage) => {
    setLanguageState(lang);
  };

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  const value: I18nContextValue = {
    language,
    setLanguage,
    t: DICTIONARIES[language],
  };

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useTranslation(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error('useTranslation must be used inside I18nProvider');
  }
  return ctx;
}
