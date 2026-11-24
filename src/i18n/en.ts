import type { TranslationDictionary } from './types.ts';

export const en: TranslationDictionary = {
  languageCode: 'en',
  languageName: 'English',
  brandName: 'SafeCheck',
  nav: {
    scanner: 'Scanner',
    howItWorks: 'How It Works',
    about: 'About',
    privacy: 'Privacy',
    languageLabel: 'Select language',
  },
  hero: {
    title: 'Check Before You Click.',
    subtitle:
      'Scan suspicious links and files to find potential security threats. Simple, private and easy to understand.',
  },
  scanner: {
    tabUrl: 'Website Link',
    tabFile: 'Upload a File',
    urlLabel: 'Website link to check',
    urlPlaceholder: 'Paste a website link here...',
    checkLinkButton: 'Check Link',
    urlHelper: "We'll check the link against known online security threats.",
    urlDownloadNote:
      'Note: Checking a link evaluates the website address only. If the link points to a downloadable file, download it cautiously and scan the file separately.',
    dropzoneTitle: 'Drop your file here or browse files.',
    dropzoneBrowse: 'Browse files',
    acceptedFormatsLabel: 'Accepted formats:',
    acceptedFormatsList: 'PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, ZIP, TXT, PNG, JPG, GIF, WEBP',
    maxFileSizeLabel: 'Maximum file size: 25 MB',
    selectedFileLabel: 'Selected file ready to scan',
    fileNameLabel: 'File name',
    fileSizeLabel: 'Size',
    fileTypeLabel: 'Format',
    removeFileLabel: 'Remove selected file',
    scanFileButton: 'Scan File',
    scanningButton: 'Scanning...',
  },
  trust: {
    noAccountTitle: 'No account required',
    noAccountDesc: 'Check links and files immediately without signing up or sharing your email.',
    tempProcessTitle: 'Files are temporarily processed',
    tempProcessDesc: 'Uploaded files are checked in isolated temporary storage and deleted right after.',
    clearReportsTitle: 'Clear and understandable reports',
    clearReportsDesc: 'Plain-language findings and practical next steps without confusing jargon.',
    disclaimer:
      'No security scanner can guarantee complete protection. Always remain cautious with unexpected messages or attachments.',
  },
  loading: {
    headingUrl: 'Checking Website Link',
    headingFile: 'Scanning Uploaded File',
    stageValidating: 'Validating input',
    stageConnecting: 'Connecting to the scanning service',
    stageChecking: 'Checking for threats',
    stagePreparing: 'Preparing the report',
    takingLonger:
      'This check is taking a little longer than usual. The security service is still processing your request.',
  },
  results: {
    sectionSecurityStatus: 'Security status',
    sectionBotAnalysis: 'AI web search & threat-feed summary',
    sectionWhatChecked: 'What was checked',
    sectionTechnicalInfo: 'Technical information',
    sectionNextSteps: 'What should I do next?',
    cleanHeading: 'No Known Threats Detected',
    cleanDescription:
      'Our security check did not identify a known threat. However, this does not guarantee that the link or file is completely safe.',
    warningHeading: 'Suspicious Signals Detected',
    warningDescription:
      'Our security check found cautionary reputation signals or suspicious patterns. Verify the source carefully before trusting this link.',
    threatHeading: 'Potential Security Threat Detected',
    threatDescription:
      'Our scanning service identified a possible security threat. Avoid opening or downloading this item.',
    unavailableHeading: 'Unable to Complete Scan',
    unavailableDescription:
      "We couldn't complete this security check. This does not mean the item is safe.",
    tryAgainButton: 'Try Again',
    scanAnotherButton: 'Check Another Link or File',
    labelScannedItem: 'Scanned item',
    labelScannerUsed: 'Security engine used',
    labelScanTime: 'Scan date and time',
    labelFileType: 'File format',
    labelFileSize: 'File size',
    labelScanStatus: 'Scan status',
    labelCategoriesChecked: 'Threat categories checked',
    labelDetectedCategory: 'Detection category',
    labelScannerResponse: 'Scanner response',
    labelFeedsChecked: 'Feeds & checks run',
    labelSourcesChecked: 'Third-party references found',
    labelReason: 'Reason',
    statusClean: 'No known threats found',
    statusWarning: 'Caution advised (suspicious signals)',
    statusThreat: 'Threat detected',
    statusUnavailable: 'Scan incomplete or unavailable',
    unconfiguredUrlReason:
      'Website link reputation scanning is not configured on this server yet.',
    unconfiguredFileReason:
      'File antivirus scanning is currently unavailable because the ClamAV scanner service (CLAMAV_SCANNER_URL) is not configured.',
    nextStepsCleanUrl: [
      'Confirm that the website address matches the official organization you expect before entering passwords or payment details.',
      'Be cautious of brand-new phishing pages that may not yet appear on public threat lists.',
      'If this link downloads a document or installer, upload the file here separately before opening it.',
    ],
    nextStepsWarningUrl: [
      'Do not enter passwords, OTP codes, or payment information unless you independently verify the official website.',
      'Check the domain spelling carefully for subtle lookalike characters or unfamiliar extensions.',
      'Contact the organization through an official phone number or bookmarked website instead of following this link.',
    ],
    nextStepsCleanFile: [
      'Only open files from people or organizations you recognize and expected to receive.',
      'Keep your device operating system and built-in antivirus protection up to date.',
      'Avoid enabling editing or macros in Office documents unless you fully trust the sender.',
    ],
    nextStepsThreatUrl: [
      'Avoid opening this link or visiting the website.',
      'Do not enter passwords, bank details, or personal information if you already visited the page.',
      'Delete the message containing this link and contact the sender through a trusted channel if needed.',
    ],
    nextStepsThreatFile: [
      'Do not open, extract, or share this file with anyone.',
      'Delete the file from your device and empty your Trash or Recycle Bin.',
      'If you already opened the file, run a full antivirus scan on your device and change important passwords from a clean device.',
    ],
    nextStepsUnavailable: [
      'Treat the link or file with caution until it can be verified.',
      'Try running the check again in a moment, or use another trusted security scanner.',
      'Ask a trusted technical professional or your IT support team before opening the item.',
    ],
    categoryLabels: {
      MALWARE: 'Malware',
      SOCIAL_ENGINEERING: 'Phishing & Social Engineering',
      UNWANTED_SOFTWARE: 'Unwanted Software',
      SUSPICIOUS_REPUTATION: 'Suspicious Reputation',
      MALWARE_SIGNATURE: 'Malware Signature',
    },
  },
  errors: {
    INVALID_URL: 'Please enter a valid website link starting with http:// or https://.',
    SSRF_BLOCKED: 'Local, private network, and internal addresses cannot be checked.',
    SERVICE_UNCONFIGURED: 'Scanning service is not configured on this server yet.',
    API_KEY_INVALID:
      'The configured Google Web Risk API key (WEBRISK_API_KEY) was rejected as invalid. Verify the key and ensure the Web Risk API is enabled.',
    SERVICE_UNAVAILABLE: 'Scanning service unavailable. Please try again later.',
    API_ERROR: 'The security provider returned an unexpected error.',
    API_QUOTA_EXCEEDED: 'API quota exceeded. Please wait and try again later.',
    TIMEOUT: 'Request timed out before the scanning service responded.',
    FILE_TOO_LARGE: 'File exceeds the 25 MB size limit.',
    UNSUPPORTED_FILE:
      'Unsupported file format. Please upload PDF, Office documents, ZIP, TXT, or common image files.',
    CORRUPTED_FILE: 'This file appears empty, corrupted, or unsafe to inspect.',
    NO_FILE: 'Please select a file before starting a scan.',
    RATE_LIMITED: 'Too many requests in a short time. Please wait a minute and try again.',
    INTERNAL_ERROR: 'An unexpected error occurred while running the check.',
  },
  howItWorks: {
    heading: 'How SafeCheck Works',
    intro:
      'SafeCheck uses dedicated security checks for links and files without ever opening or executing suspicious content on your behalf.',
    urlStepTitle: '1. Website Link Reputation Checks',
    urlStepBody:
      'Submitted HTTP and HTTPS links are validated for format and checked against Google Web Risk (when configured) as well as SafeCheck’s AI Security Bot, which searches third-party reputation reports, OpenPhish feeds, and public DNS records without visiting the website directly.',
    fileStepTitle: '2. Content-Based File Scanning',
    fileStepBody:
      'Uploaded files are checked by inspecting their internal file signatures (not just the filename extension) and scanned inside an isolated ClamAV antivirus engine with archive size limits.',
    honestStepTitle: '3. Honest, Account-Free Reporting',
    honestStepBody:
      'If a scanning service is offline, unconfigured, or times out, SafeCheck clearly states that the check could not be completed—it never guesses or pretends an unscanned item is safe.',
    backToScanner: 'Back to Scanner',
  },
  about: {
    heading: 'About SafeCheck',
    lead:
      'SafeCheck helps people make more informed decisions before opening unfamiliar links or files. It uses security-scanning technologies to identify known threats and presents the results in simple language.',
    layerParagraph:
      'SafeCheck is designed as an accessible additional layer of protection, not a replacement for dedicated device antivirus software or careful online behaviour.',
    principlesHeading: 'Core Principles',
    principles: [
      {
        title: 'Built for everyday clarity',
        body: 'Security warnings should not require technical training. Every report explains what was checked, what was found, and practical steps to take next.',
      },
      {
        title: 'No accounts or tracking barriers',
        body: 'Anyone can check a suspicious link or attachment immediately without creating an account, verifying an email address, or sharing personal details.',
      },
      {
        title: 'Strict honesty on scan coverage',
        body: 'Checking a link does not scan downloadable files behind it, and unavailable scanners are never masked as safe results.',
      },
    ],
    backToScanner: 'Back to Scanner',
  },
  privacy: {
    heading: 'Privacy Policy',
    intro:
      'SafeCheck is designed to minimize data exposure while helping you check suspicious links and files.',
    items: [
      {
        title: 'No account or registration required',
        body: 'You do not need to sign in, provide an email address, or enter any personal information to use SafeCheck.',
      },
      {
        title: 'Temporary file processing and automatic deletion',
        body: 'Uploaded files are processed in isolated temporary storage strictly for antivirus inspection and are automatically deleted immediately after scanning completes—even if a scan fails.',
      },
      {
        title: 'No public sharing or permanent file retention',
        body: 'Uploaded files are never made publicly accessible, never logged by content, and are not intentionally shared with public file-scanning websites.',
      },
      {
        title: 'No personal scan history retained',
        body: 'SafeCheck does not retain your personal browsing or scan history by default.',
      },
      {
        title: 'How website link checks are processed',
        body: 'When you check a website link, the URL is evaluated from our server using Google Web Risk or SafeCheck’s search-grounded AI Security Bot and public threat feeds. Security providers process submitted queries according to their privacy policies.',
      },
      {
        title: 'Limits of automated scanning',
        body: 'No automated scan can guarantee complete security against brand-new or targeted threats. Always exercise caution before opening unfamiliar links or attachments.',
      },
    ],
    backToScanner: 'Back to Scanner',
  },
  footer: {
    about: 'About',
    privacy: 'Privacy Policy',
    howItWorks: 'How It Works',
    contactLabel: 'Contact:',
    contactEmail: 'security@safecheck.example',
    disclaimer:
      'SafeCheck provides security checks based on available threat intelligence and antivirus signatures. No security check is perfect. A result showing no known threats does not guarantee that a file or website is safe.',
  },
};
