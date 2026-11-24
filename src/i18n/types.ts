import type { ScanErrorCode, SupportedLanguage } from '../types/scan.ts';

export interface TranslationDictionary {
  languageCode: SupportedLanguage;
  languageName: string;
  brandName: string;
  nav: {
    scanner: string;
    howItWorks: string;
    about: string;
    privacy: string;
    languageLabel: string;
  };
  hero: {
    title: string;
    subtitle: string;
  };
  scanner: {
    tabUrl: string;
    tabFile: string;
    urlLabel: string;
    urlPlaceholder: string;
    checkLinkButton: string;
    urlHelper: string;
    urlDownloadNote: string;
    dropzoneTitle: string;
    dropzoneBrowse: string;
    acceptedFormatsLabel: string;
    acceptedFormatsList: string;
    maxFileSizeLabel: string;
    selectedFileLabel: string;
    fileNameLabel: string;
    fileSizeLabel: string;
    fileTypeLabel: string;
    removeFileLabel: string;
    scanFileButton: string;
    scanningButton: string;
  };
  trust: {
    noAccountTitle: string;
    noAccountDesc: string;
    tempProcessTitle: string;
    tempProcessDesc: string;
    clearReportsTitle: string;
    clearReportsDesc: string;
    disclaimer: string;
  };
  loading: {
    headingUrl: string;
    headingFile: string;
    stageValidating: string;
    stageConnecting: string;
    stageChecking: string;
    stagePreparing: string;
    takingLonger: string;
  };
  results: {
    sectionSecurityStatus: string;
    sectionBotAnalysis: string;
    sectionWhatChecked: string;
    sectionTechnicalInfo: string;
    sectionNextSteps: string;
    cleanHeading: string;
    cleanDescription: string;
    warningHeading: string;
    warningDescription: string;
    threatHeading: string;
    threatDescription: string;
    unavailableHeading: string;
    unavailableDescription: string;
    tryAgainButton: string;
    scanAnotherButton: string;
    labelScannedItem: string;
    labelScannerUsed: string;
    labelScanTime: string;
    labelFileType: string;
    labelFileSize: string;
    labelScanStatus: string;
    labelCategoriesChecked: string;
    labelDetectedCategory: string;
    labelScannerResponse: string;
    labelFeedsChecked: string;
    labelSourcesChecked: string;
    labelReason: string;
    statusClean: string;
    statusWarning: string;
    statusThreat: string;
    statusUnavailable: string;
    unconfiguredUrlReason: string;
    unconfiguredFileReason: string;
    nextStepsCleanUrl: string[];
    nextStepsWarningUrl: string[];
    nextStepsCleanFile: string[];
    nextStepsThreatUrl: string[];
    nextStepsThreatFile: string[];
    nextStepsUnavailable: string[];
    categoryLabels: Record<string, string>;
  };
  errors: Record<ScanErrorCode, string>;
  howItWorks: {
    heading: string;
    intro: string;
    urlStepTitle: string;
    urlStepBody: string;
    fileStepTitle: string;
    fileStepBody: string;
    honestStepTitle: string;
    honestStepBody: string;
    backToScanner: string;
  };
  about: {
    heading: string;
    lead: string;
    layerParagraph: string;
    principlesHeading: string;
    principles: Array<{ title: string; body: string }>;
    backToScanner: string;
  };
  privacy: {
    heading: string;
    intro: string;
    items: Array<{ title: string; body: string }>;
    backToScanner: string;
  };
  footer: {
    about: string;
    privacy: string;
    howItWorks: string;
    contactLabel: string;
    contactEmail: string;
    disclaimer: string;
  };
}
