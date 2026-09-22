/**
 * app.js — Phishing Inspector Frontend Engine (v3 — Prize-Winning Edition)
 *
 * Features:
 *   - 3 Input Modes: File Upload (PDF/Image OCR), Text Paste, URL Inspector
 *   - One-Click Evaluation Demos
 *   - Dynamic SVG Gauge Animation & Explainable Threat Breakdown
 *   - Smooth Scroll Navigation
 */

'use strict';

/* ── DOM References ─────────────────────────────────────────── */
// Navigation & Sections
const navLinks        = document.querySelectorAll('.nav-link, .cta-header-btn, .skip-link, .brand');
// Tabs
const tabFileBtn      = document.getElementById('tab-file');
const tabTextBtn      = document.getElementById('tab-text');
const tabUrlBtn       = document.getElementById('tab-url');
const panelFile       = document.getElementById('panel-file');
const panelText       = document.getElementById('panel-text');
const panelUrl        = document.getElementById('panel-url');

// File upload
const dropZone            = document.getElementById('drop-zone');
const fileInput           = document.getElementById('file-input');
const fileSelectedDisplay = document.getElementById('file-selected-display');
const fileTypeIcon        = document.getElementById('file-type-icon');
const fileNameDisplay     = document.getElementById('file-name-display');
const fileSizeDisplay     = document.getElementById('file-size-display');
const fileClearBtn        = document.getElementById('file-clear-btn');
const visionNotice        = document.getElementById('vision-notice');

// Text & URL inputs
const textInput   = document.getElementById('text-input');
const urlInput    = document.getElementById('url-input');
const charNum     = document.getElementById('char-num');

// One-Click Demo Buttons
const demoScamTextBtn  = document.getElementById('demo-scam-text');
const demoScamUrlBtn   = document.getElementById('demo-scam-url');
const demoLegitTextBtn = document.getElementById('demo-legit-text');

// Form controls
const scanForm    = document.getElementById('scan-form');
const scanBtn     = document.getElementById('scan-btn');
const btnText     = document.getElementById('btn-text');
const btnLoading  = document.getElementById('btn-loading');
const formError   = document.getElementById('form-error');
const truncNotice = document.getElementById('truncation-notice');

// Loading section
const loadingSection = document.getElementById('loading-section');
const loadingStep    = document.getElementById('loading-step');

// Results section
const resultsSection   = document.getElementById('results-section');
const gaugeArc         = document.getElementById('gauge-arc');
const gaugeScore       = document.getElementById('gauge-score');
const riskBadge        = document.getElementById('risk-badge');
const riskEmoji        = document.getElementById('risk-emoji');
const riskLevelText    = document.getElementById('risk-level-text');
const riskDescription  = document.getElementById('risk-description');
const scoreMethodology = document.getElementById('score-methodology');
const fileInfoBanner   = document.getElementById('file-info-banner');
const sbStatus         = document.getElementById('sb-status');
const domainCard       = document.getElementById('domain-card');
const domainInfoList   = document.getElementById('domain-info-list');
const extractedSection = document.getElementById('extracted-text-section');
const extractedPreview = document.getElementById('extracted-text-preview');
const signalCountBadge = document.getElementById('signal-count-badge');
const signalsContainer = document.getElementById('signals-container');
const noSignalsMsg     = document.getElementById('no-signals-msg');
const recSection       = document.getElementById('recommendations-section');
const recList          = document.getElementById('recommendations-list');
const disclaimerText   = document.getElementById('disclaimer-text');
const scanAgainBtn     = document.getElementById('scan-again-btn');

/* ── Constants ──────────────────────────────────────────────── */
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 90; // ≈ 565.49

const RISK_CLASS = {
  Low:      'risk-low',
  Moderate: 'risk-moderate',
  High:     'risk-high',
  Critical: 'risk-critical',
};

const RISK_COLOUR = {
  Low:      '#10b981',
  Moderate: '#f59e0b',
  High:     '#f97316',
  Critical: '#ef4444',
};

const ALLOWED_FILE_TYPES = new Set([
  'application/pdf',
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/webp',
]);
const IMAGE_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/png', 'image/webp']);
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

/* ── State ──────────────────────────────────────────────────── */
let currentMode  = 'file'; // 'file' | 'text' | 'url'
let selectedFile = null;

/* ─────────────────────────────────────────────────────────────
   Tab Switching
   ───────────────────────────────────────────────────────────── */
const tabs = [
  { btn: tabFileBtn, panel: panelFile, mode: 'file' },
  { btn: tabTextBtn, panel: panelText, mode: 'text' },
  { btn: tabUrlBtn,  panel: panelUrl,  mode: 'url'  },
];

function activateTab(mode) {
  currentMode = mode;
  tabs.forEach(({ btn, panel, mode: m }) => {
    const active = m === mode;
    if (btn) {
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
      btn.classList.toggle('tab-active', active);
    }
    if (panel) {
      panel.classList.toggle('hidden', !active);
      panel.setAttribute('aria-hidden', active ? 'false' : 'true');
    }
  });

  clearError();
  hideResults();
}

tabs.forEach(({ btn, mode: m }, idx, arr) => {
  if (!btn) return;
  btn.addEventListener('click', () => activateTab(m));
  btn.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      const next = arr[(idx + 1) % arr.length];
      if (next?.btn) { next.btn.click(); next.btn.focus(); }
    }
    if (e.key === 'ArrowLeft') {
      e.preventDefault();
      const prev = arr[(idx - 1 + arr.length) % arr.length];
      if (prev?.btn) { prev.btn.click(); prev.btn.focus(); }
    }
  });
});

/* ─────────────────────────────────────────────────────────────
   File Upload Handling
   ───────────────────────────────────────────────────────────── */
if (dropZone && fileInput) {
  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  dropZone.addEventListener('dragenter', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragover',  (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', (e) => {
    if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('drag-over');
  });
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer?.files?.[0];
    if (file) handleFileSelect(file);
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files?.[0]) handleFileSelect(fileInput.files[0]);
  });
}

if (fileClearBtn) {
  fileClearBtn.addEventListener('click', () => {
    selectedFile    = null;
    if (fileInput) fileInput.value = '';
    if (fileSelectedDisplay) fileSelectedDisplay.classList.add('hidden');
    if (visionNotice) visionNotice.classList.add('hidden');
    if (dropZone) dropZone.classList.remove('has-file');
    clearError();
  });
}

function handleFileSelect(file) {
  clearError();

  const isAllowed = ALLOWED_FILE_TYPES.has(file.type) ||
                    /\.(pdf|jpg|jpeg|png|webp)$/i.test(file.name);

  if (!isAllowed) {
    showError('Unsupported file format. Please upload a PDF or image file (JPG, PNG, WebP).');
    return;
  }
  if (file.size > MAX_FILE_SIZE) {
    showError('File too large. Maximum allowed size is 10 MB.');
    return;
  }

  selectedFile = file;

  const isImg = IMAGE_TYPES.has(file.type) || /\.(jpg|jpeg|png|webp)$/i.test(file.name);
  if (fileTypeIcon) fileTypeIcon.textContent = isImg ? '🖼️' : '📄';
  if (fileNameDisplay) fileNameDisplay.textContent = file.name;
  if (fileSizeDisplay) fileSizeDisplay.textContent = formatFileSize(file.size);
  if (fileSelectedDisplay) fileSelectedDisplay.classList.remove('hidden');
  if (dropZone) dropZone.classList.add('has-file');

  if (visionNotice) {
    if (isImg) visionNotice.classList.remove('hidden');
    else visionNotice.classList.add('hidden');
  }
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

if (textInput && charNum) {
  textInput.addEventListener('input', () => {
    charNum.textContent = textInput.value.length.toLocaleString();
  });
}

/* ─────────────────────────────────────────────────────────────
   One-Click Live Demo Presets
   ───────────────────────────────────────────────────────────── */
const SAMPLE_SCAM_TEXT =
`CONFIDENTIAL APPOINTMENT & JOB OFFER LETTER
Company: Apex Global Technologies Ltd.
Date: September 22, 2026

Dear Alex Morgan,
We are pleased to offer you the remote position of Senior Cloud Engineer. Your starting salary will be $9,200/month.

EQUIPMENT & SECURITY DEPOSIT REQUIREMENT:
To finalize your onboarding and dispatch your company laptop and workstation hardware, you are required to pay a mandatory refundable equipment security deposit of $450 USD prior to your start date.

Please send $450 via Zelle, CashApp, or Apple Gift Cards to onboarding-finance@apex-globaltech-jobs.com within 24 hours. Failure to pay will result in immediate offer cancellation.`;

const SAMPLE_LEGIT_TEXT =
`EMPLOYMENT OFFER LETTER
Company: Veritas Health Systems Inc.
Date: September 22, 2026

Dear Sarah Connor,
On behalf of Veritas Health Systems, we are excited to offer you the position of Senior Systems Analyst at our Austin office with an annual base salary of $115,000 USD.

Benefits include full healthcare coverage, 401(k) matching up to 5%, and 20 days paid PTO.
All equipment will be provided directly by our IT department upon your start date at zero cost to you. We never request payments or security deposits.`;

const SAMPLE_SCAM_URL = 'http://192.168.1.1/apex-globaltech/login.php';

if (demoScamTextBtn) {
  demoScamTextBtn.addEventListener('click', () => {
    activateTab('text');
    if (textInput) textInput.value = SAMPLE_SCAM_TEXT;
    if (charNum) charNum.textContent = SAMPLE_SCAM_TEXT.length.toLocaleString();
    scrollToScanner();
    triggerFormScan();
  });
}

if (demoScamUrlBtn) {
  demoScamUrlBtn.addEventListener('click', () => {
    activateTab('url');
    if (urlInput) urlInput.value = SAMPLE_SCAM_URL;
    scrollToScanner();
    triggerFormScan();
  });
}

if (demoLegitTextBtn) {
  demoLegitTextBtn.addEventListener('click', () => {
    activateTab('text');
    if (textInput) textInput.value = SAMPLE_LEGIT_TEXT;
    if (charNum) charNum.textContent = SAMPLE_LEGIT_TEXT.length.toLocaleString();
    scrollToScanner();
    triggerFormScan();
  });
}

function scrollToScanner() {
  const sec = document.getElementById('scanner-section');
  if (sec) sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function triggerFormScan() {
  setTimeout(() => {
    if (scanForm) scanForm.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
  }, 300);
}

/* ─────────────────────────────────────────────────────────────
   Form Submission
   ───────────────────────────────────────────────────────────── */
if (scanForm) {
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError();
    hideResults();

    let fetchOptions;
    let apiUrl = '/api/analyze';

    if (currentMode === 'file') {
      if (!selectedFile) {
        showError('Please select or drag-and-drop a PDF or image file to analyse.');
        if (dropZone) dropZone.focus();
        return;
      }
      const formData = new FormData();
      formData.append('file', selectedFile);
      fetchOptions = { method: 'POST', body: formData };
      apiUrl = '/api/analyze/file';

    } else if (currentMode === 'text') {
      const content = textInput ? textInput.value : '';
      if (!content.trim()) {
        showError('Please paste some text to analyse.');
        if (textInput) textInput.focus();
        return;
      }
      fetchOptions = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'text', content: content.trim() }),
      };

    } else if (currentMode === 'url') {
      const content = urlInput ? urlInput.value : '';
      if (!content.trim()) {
        showError('Please enter a URL to analyse.');
        if (urlInput) urlInput.focus();
        return;
      }
      fetchOptions = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'url', content: content.trim() }),
      };
    }

    setScanningState(true);
    showLoading(true);

    const fileSteps = [
      'Reading file stream…',
      'Extracting text & OCR…',
      'Scanning scam red flags…',
      'Calculating Scam Threat Index…',
    ];
    const genericSteps = [
      'Scanning for risk signals…',
      'Running regex heuristics…',
      'Calculating Scam Threat Index…',
    ];
    const steps = currentMode === 'file' ? fileSteps : genericSteps;
    let stepIdx = 0;
    const stepInterval = setInterval(() => {
      stepIdx = (stepIdx + 1) % steps.length;
      if (loadingStep) loadingStep.textContent = steps[stepIdx];
    }, 600);

    try {
      const response = await fetch(apiUrl, fetchOptions);
      clearInterval(stepInterval);

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error?.message || data.error || 'Analysis failed. Please try again.');
      }

      showLoading(false);
      setScanningState(false);
      renderResults(data);

    } catch (err) {
      clearInterval(stepInterval);
      showLoading(false);
      setScanningState(false);
      showError(err.message || 'Network error occurred. Please check your connection and try again.');
    }
  });
}

/* ─────────────────────────────────────────────────────────────
   Results Rendering
   ───────────────────────────────────────────────────────────── */
function renderResults(data) {
  if (!resultsSection) return;

  const score   = Math.min(100, Math.max(0, Number(data.scamThreatIndex) || 0));
  const level   = data.riskLevel || 'Low';
  const desc    = data.riskDescription || '';
  const signals = Array.isArray(data.detectedSignals) ? data.detectedSignals : [];
  const recs    = Array.isArray(data.recommendations) ? data.recommendations : [];
  const meta    = data.scoreBreakdown || {};

  // 1. Gauge animation
  if (gaugeArc && gaugeScore && riskBadge && riskEmoji && riskLevelText && riskDescription) {
    const offset = GAUGE_CIRCUMFERENCE * (1 - score / 100);
    gaugeArc.style.strokeDasharray  = `${GAUGE_CIRCUMFERENCE}`;
    gaugeArc.style.strokeDashoffset = `${offset}`;
    gaugeArc.style.stroke           = RISK_COLOUR[level] || RISK_COLOUR.Low;

    animateScoreCount(score);

    riskBadge.className = `risk-badge ${RISK_CLASS[level] || 'risk-low'}`;
    const emojis = { Low: '✅', Moderate: '⚠️', High: '🚨', Critical: '⛔' };
    riskEmoji.textContent     = emojis[level] || '🛡️';
    riskLevelText.textContent = `${level} Risk`;
    riskDescription.textContent = desc;
  }

  // 2. Methodology explanation
  if (scoreMethodology) {
    scoreMethodology.textContent =
      `Score is dynamically calculated based on ${meta.totalSignalsCount || 0} signal(s) ` +
      `(${meta.criticalCount || 0} critical, ${meta.warningCount || 0} warning).`;
  }

  // 3. File info banner
  if (fileInfoBanner) {
    if (data.mode === 'file' && data.extractedTextLength) {
      fileInfoBanner.classList.remove('hidden');
      fileInfoBanner.textContent = `📄 Analyzed file text (${data.extractedTextLength.toLocaleString()} characters extracted)`;
    } else {
      fileInfoBanner.classList.add('hidden');
    }
  }

  // 4. Safe Browsing status
  if (sbStatus) {
    if (data.mode === 'url' && data.safeBrowsing) {
      sbStatus.classList.remove('hidden');
      sbStatus.className = `sb-status ${data.safeBrowsing.isListed ? 'sb-malicious' : 'sb-safe'}`;
      sbStatus.textContent = data.safeBrowsing.isListed
        ? '🚨 Listed in Google Safe Browsing threat database!'
        : '✅ Not listed in Google Safe Browsing threat database.';
    } else {
      sbStatus.classList.add('hidden');
    }
  }

  // 5. Domain info
  if (domainCard && domainInfoList) {
    if (data.mode === 'url' && data.domainInfo) {
      domainCard.classList.remove('hidden');
      domainInfoList.innerHTML = '';
      const info = data.domainInfo;
      const items = [
        { label: 'Domain Name', value: info.domain || 'N/A' },
        { label: 'Estimated Age', value: info.ageInDays != null ? `${info.ageInDays} days` : (info.ageMessage || 'Unknown') },
        { label: 'Suspicious TLD', value: info.isSuspiciousTld ? 'Yes ⚠️' : 'No' },
        { label: 'IP Address Host', value: info.isIpHost ? 'Yes ⚠️' : 'No' },
      ];
      items.forEach(({ label, value }) => {
        const dt = document.createElement('dt');
        dt.textContent = label;
        const dd = document.createElement('dd');
        dd.textContent = value;
        domainInfoList.appendChild(dt);
        domainInfoList.appendChild(dd);
      });
    } else {
      domainCard.classList.add('hidden');
    }
  }

  // 6. Extracted Text Preview
  if (extractedSection && extractedPreview) {
    if (data.extractedText) {
      extractedSection.classList.remove('hidden');
      extractedPreview.textContent = data.extractedText;
    } else {
      extractedSection.classList.add('hidden');
    }
  }

  // 7. Detected Signals List
  if (signalCountBadge) signalCountBadge.textContent = `${signals.length}`;
  if (signalsContainer) {
    signalsContainer.innerHTML = '';

    if (signals.length === 0) {
      if (noSignalsMsg) noSignalsMsg.classList.remove('hidden');
    } else {
      if (noSignalsMsg) noSignalsMsg.classList.add('hidden');

      signals.forEach((sig) => {
        const card = document.createElement('article');
        card.className = `signal-card signal-severity-${sig.severity || 'low'}`;

        const header = document.createElement('div');
        header.className = 'signal-header';

        const nameSpan = document.createElement('span');
        nameSpan.className = 'signal-name';
        nameSpan.textContent = sig.name || 'Detected Signal';

        const sevSpan = document.createElement('span');
        sevSpan.className = `signal-severity-badge sev-${sig.severity || 'low'}`;
        sevSpan.textContent = (sig.severity || 'low').toUpperCase();

        header.appendChild(nameSpan);
        header.appendChild(sevSpan);

        const descP = document.createElement('p');
        descP.className = 'signal-desc';
        descP.textContent = sig.description || '';

        card.appendChild(header);
        card.appendChild(descP);

        if (sig.evidence) {
          const evDiv = document.createElement('div');
          evDiv.className = 'signal-evidence';

          const evLabel = document.createElement('span');
          evLabel.className = 'evidence-label';
          evLabel.textContent = 'Evidence matched: ';

          const evCode = document.createElement('code');
          evCode.className = 'evidence-code';
          evCode.textContent = sig.evidence;

          evDiv.appendChild(evLabel);
          evDiv.appendChild(evCode);
          card.appendChild(evDiv);
        }

        signalsContainer.appendChild(card);
      });
    }
  }

  // 8. Recommendations
  if (recSection && recList) {
    if (recs.length > 0) {
      recSection.classList.remove('hidden');
      recList.innerHTML = '';
      recs.forEach((rec) => {
        const li = document.createElement('li');
        li.textContent = rec;
        recList.appendChild(li);
      });
    } else {
      recSection.classList.add('hidden');
    }
  }

  // 9. Disclaimer
  if (disclaimerText) {
    disclaimerText.textContent = data.disclaimer ||
      'This scanner provides an automated risk assessment based on pattern matching and domain signals. ' +
      'It is not a legal guarantee. Always verify job offers directly with official company HR departments.';
  }

  resultsSection.classList.remove('hidden');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  resultsSection.focus();
}

function animateScoreCount(target) {
  if (!gaugeScore) return;
  let current = 0;
  const step = Math.max(1, Math.floor(target / 25));
  const interval = setInterval(() => {
    current += step;
    if (current >= target) {
      current = target;
      clearInterval(interval);
    }
    gaugeScore.textContent = current;
  }, 20);
}

function setScanningState(loading) {
  if (!scanBtn || !btnText || !btnLoading) return;
  scanBtn.disabled = loading;
  scanBtn.setAttribute('aria-busy', loading ? 'true' : 'false');
  btnText.classList.toggle('hidden', loading);
  btnLoading.classList.toggle('hidden', !loading);
}

function showLoading(show) {
  if (!loadingSection) return;
  loadingSection.classList.toggle('hidden', !show);
  if (show && loadingStep) loadingStep.textContent = 'Scanning for risk signals…';
}

function hideResults() {
  if (resultsSection) resultsSection.classList.add('hidden');
}

function showError(message) {
  if (!formError) return;
  formError.textContent = message;
  formError.classList.remove('hidden');
  formError.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function clearError() {
  if (formError) {
    formError.textContent = '';
    formError.classList.add('hidden');
  }
}

if (scanAgainBtn) {
  scanAgainBtn.addEventListener('click', () => {
    hideResults();
    clearError();
    scrollToScanner();
  });
}
