/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import { Footer } from './components/Footer.tsx';
import { Header } from './components/Header.tsx';
import { AboutPage, HowItWorksPage, PrivacyPage } from './components/InfoPages.tsx';
import { ScannerCard } from './components/ScannerCard.tsx';
import { ScanningProgress } from './components/ScanningProgress.tsx';
import { ScanResult } from './components/ScanResult.tsx';
import { TrustIndicators } from './components/TrustIndicators.tsx';
import { I18nProvider, useTranslation } from './i18n/index.tsx';
import type { AppPage, ScanResponse, ScanType } from './types/scan.ts';

const PAGE_PATHS: Record<AppPage, string> = {
  home: '/',
  'how-it-works': '/how-it-works',
  about: '/about',
  privacy: '/privacy',
};

function getPageFromPathname(pathname: string): AppPage {
  const clean = pathname.replace(/\/+$/, '') || '/';
  if (clean === '/how-it-works') return 'how-it-works';
  if (clean === '/about') return 'about';
  if (clean === '/privacy') return 'privacy';
  return 'home';
}

function SafeCheckApp() {
  const { language, t } = useTranslation();
  const [currentPage, setCurrentPage] = useState<AppPage>(() =>
    getPageFromPathname(window.location.pathname),
  );
  const [activeTab, setActiveTab] = useState<ScanType>('url');
  const [urlInput, setUrlInput] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const [isScanning, setIsScanning] = useState(false);
  const [scanningTarget, setScanningTarget] = useState('');
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [lastRequest, setLastRequest] = useState<
    { type: 'url'; url: string } | { type: 'file'; file: File } | null
  >(null);

  useEffect(() => {
    const onPopState = () => {
      setCurrentPage(getPageFromPathname(window.location.pathname));
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const navigateTo = (page: AppPage) => {
    setCurrentPage(page);
    const targetPath = PAGE_PATHS[page];
    if (window.location.pathname !== targetPath) {
      window.history.pushState({ page }, '', targetPath);
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const executeUrlScan = async (targetUrl: string) => {
    if (isScanning) return;
    setIsScanning(true);
    setScanningTarget(targetUrl);
    setScanResult(null);
    setLastRequest({ type: 'url', url: targetUrl });

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 25_000);

    try {
      const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, language }),
        signal: controller.signal,
      });

      const data = (await response.json()) as ScanResponse;
      setScanResult(data);
    } catch (err) {
      const isTimeout = err instanceof Error && err.name === 'AbortError';
      setScanResult({
        status: 'unavailable',
        scanType: 'url',
        scannedItem: targetUrl,
        scannerName: 'SafeCheck Link Scanner',
        timestamp: new Date().toISOString(),
        categoriesChecked: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        error: {
          code: isTimeout ? 'TIMEOUT' : 'SERVICE_UNAVAILABLE',
          message: isTimeout ? t.errors.TIMEOUT : t.errors.SERVICE_UNAVAILABLE,
        },
      });
    } finally {
      window.clearTimeout(timeoutId);
      setIsScanning(false);
    }
  };

  const executeFileScan = async (file: File) => {
    if (isScanning) return;
    setIsScanning(true);
    setScanningTarget(file.name);
    setScanResult(null);
    setLastRequest({ type: 'file', file });

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 50_000);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/scan/file', {
        method: 'POST',
        body: formData,
        signal: controller.signal,
      });

      if (response.status === 413) {
        let payload: ScanResponse | null = null;
        try {
          payload = (await response.json()) as ScanResponse;
        } catch {
          payload = null;
        }
        setScanResult(
          payload ?? {
            status: 'unavailable',
            scanType: 'file',
            scannedItem: file.name,
            scannerName: 'ClamAV Antivirus Engine',
            timestamp: new Date().toISOString(),
            categoriesChecked: ['Malware signatures', 'Trojans & Ransomware', 'Archive & Document exploits'],
            error: {
              code: 'FILE_TOO_LARGE',
              message: t.errors.FILE_TOO_LARGE,
            },
          },
        );
        return;
      }

      const data = (await response.json()) as ScanResponse;
      setScanResult(data);
    } catch (err) {
      const isTimeout = err instanceof Error && err.name === 'AbortError';
      setScanResult({
        status: 'unavailable',
        scanType: 'file',
        scannedItem: file.name,
        scannerName: 'ClamAV Antivirus Engine',
        timestamp: new Date().toISOString(),
        categoriesChecked: ['Malware signatures', 'Trojans & Ransomware', 'Archive & Document exploits'],
        error: {
          code: isTimeout ? 'TIMEOUT' : 'SERVICE_UNAVAILABLE',
          message: isTimeout ? t.errors.TIMEOUT : t.errors.SERVICE_UNAVAILABLE,
        },
      });
    } finally {
      window.clearTimeout(timeoutId);
      setIsScanning(false);
    }
  };

  const handleRetry = () => {
    if (!lastRequest || isScanning) return;
    if (lastRequest.type === 'url') {
      void executeUrlScan(lastRequest.url);
    } else {
      void executeFileScan(lastRequest.file);
    }
  };

  const handleReset = () => {
    setScanResult(null);
    setScanningTarget('');
  };

  return (
    <div className="flex min-h-screen flex-col bg-slate-50 text-slate-900">
      <Header currentPage={currentPage} onNavigate={navigateTo} />

      <main className="mx-auto w-full max-w-3xl flex-1 px-4 pt-10 pb-6 sm:px-6 sm:pt-14">
        {currentPage === 'home' && (
          <div>
            <div className="mb-8 text-center sm:mb-10">
              <h1
                className="mx-auto max-w-2xl text-3xl font-bold tracking-tight text-slate-900 sm:text-5xl"
                style={{ textWrap: 'balance' }}
              >
                {t.hero.title}
              </h1>
              <p className="mx-auto mt-4 max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
                {t.hero.subtitle}
              </p>
            </div>

            {isScanning ? (
              <ScanningProgress scanType={activeTab} targetLabel={scanningTarget} />
            ) : scanResult ? (
              <ScanResult result={scanResult} onRetry={handleRetry} onReset={handleReset} />
            ) : (
              <ScannerCard
                activeTab={activeTab}
                onTabChange={setActiveTab}
                urlInput={urlInput}
                onUrlChange={setUrlInput}
                selectedFile={selectedFile}
                onFileSelect={setSelectedFile}
                onScanUrl={(url) => void executeUrlScan(url)}
                onScanFile={(file) => void executeFileScan(file)}
                isScanning={isScanning}
              />
            )}

            <TrustIndicators />
          </div>
        )}

        {currentPage === 'how-it-works' && <HowItWorksPage onNavigate={navigateTo} />}
        {currentPage === 'about' && <AboutPage onNavigate={navigateTo} />}
        {currentPage === 'privacy' && <PrivacyPage onNavigate={navigateTo} />}
      </main>

      <Footer onNavigate={navigateTo} />
    </div>
  );
}

export default function App() {
  return (
    <I18nProvider>
      <SafeCheckApp />
    </I18nProvider>
  );
}
