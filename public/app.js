/**
 * app.js — Phishing Inspector frontend (v2 — three-tab layout)
 *
 * Modes:
 *   - file  → drag-and-drop / file picker → POST /api/analyze/file (multipart)
 *   - text  → textarea paste              → POST /api/analyze      (JSON)
 *   - url   → URL input                   → POST /api/analyze      (JSON)
 *
 * Security: All user-supplied content rendered via textContent (never innerHTML).
 */

'use strict';

/* ── DOM references ─────────────────────────────────────────── */
// Tabs
const tabFileBtn  = document.getElementById('tab-file');
const tabTextBtn  = document.getElementById('tab-text');
const tabUrlBtn   = document.getElementById('tab-url');
const panelFile   = document.getElementById('panel-file');
const panelText   = document.getElementById('panel-text');
const panelUrl    = document.getElementById('panel-url');
// File upload
const dropZone          = document.getElementById('drop-zone');
const fileInput         = document.getElementById('file-input');
const fileSelectedDisplay = document.getElementById('file-selected-display');
const fileTypeIcon      = document.getElementById('file-type-icon');
const fileNameDisplay   = document.getElementById('file-name-display');
const fileSizeDisplay   = document.getElementById('file-size-display');
const fileClearBtn      = document.getElementById('file-clear-btn');
const visionNotice      = document.getElementById('vision-notice');
// Text / URL inputs
const textInput   = document.getElementById('text-input');
const urlInput    = document.getElementById('url-input');
const charNum     = document.getElementById('char-num');
// Form
const scanForm    = document.getElementById('scan-form');
const scanBtn     = document.getElementById('scan-btn');
const btnText     = document.getElementById('btn-text');
const btnLoading  = document.getElementById('btn-loading');
const formError   = document.getElementById('form-error');
const truncNotice = document.getElementById('truncation-notice');
// Loading
const loadingSection = document.getElementById('loading-section');
const loadingStep    = document.getElementById('loading-step');
// Results
const resultsSection    = document.getElementById('results-section');
const gaugeArc          = document.getElementById('gauge-arc');
const gaugeScore        = document.getElementById('gauge-score');
const riskBadge         = document.getElementById('risk-badge');
const riskEmoji         = document.getElementById('risk-emoji');
const riskLevelText     = document.getElementById('risk-level-text');
const riskDescription   = document.getElementById('risk-description');
const scoreMethodology  = document.getElementById('score-methodology');
const fileInfoBanner    = document.getElementById('file-info-banner');
const sbStatus          = document.getElementById('sb-status');
const domainCard        = document.getElementById('domain-card');
const domainInfoList    = document.getElementById('domain-info-list');
const extractedSection  = document.getElementById('extracted-text-section');
const extractedPreview  = document.getElementById('extracted-text-preview');
const signalCountBadge  = document.getElementById('signal-count-badge');
const signalsContainer  = document.getElementById('signals-container');
const noSignalsMsg      = document.getElementById('no-signals-msg');
const recSection        = document.getElementById('recommendations-section');
const recList           = document.getElementById('recommendations-list');
const disclaimerText    = document.getElementById('disclaimer-text');
const scanAgainBtn      = document.getElementById('scan-again-btn');

/* ── Constants ──────────────────────────────────────────────── */
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 90; // ≈ 565.49

const RISK_CLASS = {
  Low:      'risk-low',
  Moderate: 'risk-moderate',
  High:     'risk-high',
  Critical: 'risk-critical',
};

const RISK_COLOUR = {
  Low:      '#22c55e',
  Moderate: '#eab308',
  High:     '#f97316',
  Critical: '#ef4444',
};

const ALLOWED_FILE_TYPES = new Set([
  'application/pdf', 'image/jpeg', 'image/jpg', 'image/png', 'image/webp',
]);
const IMAGE_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/png', 'image/webp']);
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

/* ── State ──────────────────────────────────────────────────── */
let currentMode  = 'file'; // 'file' | 'text' | 'url'
let selectedFile = null;

/* ─────────────────────────────────────────────────────────────
   Tab switching
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
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
    btn.classList.toggle('tab-active', active);
    panel.classList.toggle('hidden', !active);
    panel.setAttribute('aria-hidden', active ? 'false' : 'true');
  });

  clearError();
  hideResults();
}

tabs.forEach(({ btn, mode: m }, idx, arr) => {
  btn.addEventListener('click', () => activateTab(m));
  // Arrow key navigation per ARIA tabs pattern
  btn.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      const next = arr[(idx + 1) % arr.length];
      next.btn.click(); next.btn.focus();
    }
    if (e.key === 'ArrowLeft') {
      e.preventDefault();
      const prev = arr[(idx - 1 + arr.length) % arr.length];
      prev.btn.click(); prev.btn.focus();
    }
  });
});

/* ─────────────────────────────────────────────────────────────
   File upload — drop zone interactions
   ───────────────────────────────────────────────────────────── */
// Open file picker on click or Enter/Space
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    fileInput.click();
  }
});

// Drag-over: visual feedback
dropZone.addEventListener('dragenter', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragover',  (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', (e) => {
  // Only remove class if actually leaving the zone (not entering a child)
  if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('drag-over');
});
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer?.files?.[0];
  if (file) handleFileSelect(file);
});

// File picker change
fileInput.addEventListener('change', () => {
  if (fileInput.files?.[0]) handleFileSelect(fileInput.files[0]);
});

// Clear selected file
fileClearBtn.addEventListener('click', () => {
  selectedFile      = null;
  fileInput.value   = '';
  fileSelectedDisplay.classList.add('hidden');
  visionNotice.classList.add('hidden');
  dropZone.classList.remove('has-file');
  clearError();
});

/**
 * Validates and registers a selected file.
 * @param {File} file
 */
function handleFileSelect(file) {
  clearError();

  if (!ALLOWED_FILE_TYPES.has(file.type)) {
    showError('Unsupported file type. Please upload a PDF, JPG, PNG, or WebP file.');
    return;
  }
  if (file.size > MAX_FILE_SIZE) {
    showError('File too large. Maximum allowed size is 10 MB.');
    return;
  }

  selectedFile = file;

  // Update display
  fileTypeIcon.textContent      = IMAGE_TYPES.has(file.type) ? '🖼️' : '📄';
  fileNameDisplay.textContent   = file.name;
  fileSizeDisplay.textContent   = formatFileSize(file.size);
  fileSelectedDisplay.classList.remove('hidden');
  dropZone.classList.add('has-file');

  // Show Vision API notice for image files
  if (IMAGE_TYPES.has(file.type)) {
    visionNotice.classList.remove('hidden');
  } else {
    visionNotice.classList.add('hidden');
  }
}

/** Formats bytes into a human-readable size string */
function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

/* ─────────────────────────────────────────────────────────────
   Character counter for textarea
   ───────────────────────────────────────────────────────────── */
textInput.addEventListener('input', () => {
  charNum.textContent = textInput.value.length.toLocaleString();
});

/* ─────────────────────────────────────────────────────────────
   Form submission
   ───────────────────────────────────────────────────────────── */
scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearError();
  hideResults();

  // ── Build request based on mode ───────────────────────────
  let fetchOptions;
  let apiUrl = '/api/analyze';

  if (currentMode === 'file') {
    if (!selectedFile) {
      showError('Please select or drag-and-drop a file to analyse.');
      dropZone.focus();
      return;
    }
    const formData = new FormData();
    formData.append('file', selectedFile);
    fetchOptions = { method: 'POST', body: formData };
    apiUrl = '/api/analyze/file';

  } else if (currentMode === 'text') {
    const content = textInput.value;
    if (!content.trim()) {
      showError('Please paste some text to analyse.');
      textInput.focus();
      return;
    }
    fetchOptions = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'text', content: content.trim() }),
    };

  } else if (currentMode === 'url') {
    const content = urlInput.value;
    if (!content.trim()) {
      showError('Please enter a URL to analyse.');
      urlInput.focus();
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

  // Animate the loading step text
  const fileSteps = [
    'Reading file…',
    'Extracting text…',
    'Detecting payment red flags…',
    'Calculating Scam Threat Index…',
  ];
  const genericSteps = [
    'Parsing content…',
    'Checking payment red flags…',
    'Analysing signals…',
    'Calculating Scam Threat Index…',
  ];
  const urlSteps = [
    'Parsing URL structure…',
    'Checking domain age…',
    'Querying Google Safe Browsing…',
    'Calculating Scam Threat Index…',
  ];
  const steps = currentMode === 'file' ? fileSteps : currentMode === 'url' ? urlSteps : genericSteps;
  let stepIdx = 0;
  loadingStep.textContent = steps[0];
  const stepInterval = setInterval(() => {
    if (++stepIdx < steps.length) loadingStep.textContent = steps[stepIdx];
    else clearInterval(stepInterval);
  }, 900);

  try {
    const response = await fetch(apiUrl, fetchOptions);
    clearInterval(stepInterval);

    if (!response.ok) {
      let msg = 'Analysis failed. Please try again.';
      try {
        const errData = await response.json();
        if (errData?.message) msg = errData.message;
      } catch { /* ignore */ }
      throw new Error(msg);
    }

    const result = await response.json();
    showLoading(false);
    setScanningState(false);
    renderResult(result);

  } catch (err) {
    clearInterval(stepInterval);
    showLoading(false);
    setScanningState(false);
    showError(err.message || 'Unable to reach the analysis service. Please check your connection.');
  }
});

/* ─────────────────────────────────────────────────────────────
   UI helpers
   ───────────────────────────────────────────────────────────── */
function setScanningState(active) {
  scanBtn.disabled = active;
  btnText.classList.toggle('hidden', active);
  btnLoading.classList.toggle('hidden', !active);
}

function showLoading(show) {
  loadingSection.classList.toggle('hidden', !show);
}

function showError(message) {
  formError.textContent = message;
  formError.classList.remove('hidden');
}

function clearError() {
  formError.textContent = '';
  formError.classList.add('hidden');
  truncNotice.classList.add('hidden');
}

function hideResults() {
  resultsSection.classList.add('hidden');
}

/* ─────────────────────────────────────────────────────────────
   Render results
   ───────────────────────────────────────────────────────────── */
function renderResult(result) {
  if (result.truncated) truncNotice.classList.remove('hidden');

  // ── Gauge ─────────────────────────────────────────────────
  const score     = Math.min(100, Math.max(0, result.score));
  const offset    = GAUGE_CIRCUMFERENCE * (1 - score / 100);
  const arcColour = RISK_COLOUR[result.riskLevel] || '#3b82f6';

  gaugeArc.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  gaugeArc.style.stroke           = arcColour;
  gaugeScore.style.color          = arcColour;
  gaugeScore.textContent          = '0';

  requestAnimationFrame(() => requestAnimationFrame(() => {
    gaugeArc.style.strokeDashoffset = offset;
    animateNumber(gaugeScore, 0, score, 900);
  }));

  // ── Risk badge ─────────────────────────────────────────────
  riskBadge.className       = 'risk-badge ' + (RISK_CLASS[result.riskLevel] || '');
  riskEmoji.textContent     = result.riskEmoji || '';
  riskLevelText.textContent = (result.riskLevel || '') + ' Risk';
  riskDescription.textContent  = result.riskDescription  || '';
  scoreMethodology.textContent = result.methodology || '';

  // ── File info banner (file mode) ───────────────────────────
  if (result.mode === 'file' && result.fileName) {
    const parts = [];
    parts.push('📎 ' + result.fileName);
    if (result.fileSize)  parts.push(formatFileSize(result.fileSize));
    if (result.pageCount) parts.push(result.pageCount + ' page' + (result.pageCount !== 1 ? 's' : ''));
    fileInfoBanner.textContent = parts.join('  ·  ');
    fileInfoBanner.classList.remove('hidden');
  } else {
    fileInfoBanner.classList.add('hidden');
  }

  // ── Safe Browsing status (URL mode) ───────────────────────
  renderSafeBrowsingStatus(result);

  // ── Domain info (URL mode) ────────────────────────────────
  if (result.mode === 'url' && result.domainInfo) {
    renderDomainInfo(result.domainInfo);
    domainCard.classList.remove('hidden');
  } else {
    domainCard.classList.add('hidden');
  }

  // ── Extracted text preview (file mode) ───────────────────
  if (result.mode === 'file' && result.extractedTextPreview) {
    extractedPreview.textContent = result.extractedTextPreview +
      (result.truncated ? '\n\n[… text was trimmed for analysis …]' : '');
    extractedSection.classList.remove('hidden');
  } else {
    extractedSection.classList.add('hidden');
  }

  // ── Signals ───────────────────────────────────────────────
  signalsContainer.innerHTML = '';
  signalCountBadge.textContent = result.signals.length;
  if (result.signals.length > 0) {
    noSignalsMsg.classList.add('hidden');
    result.signals.forEach((s) => signalsContainer.appendChild(buildSignalCard(s)));
  } else {
    noSignalsMsg.classList.remove('hidden');
  }

  // ── Recommendations ───────────────────────────────────────
  recList.innerHTML = '';
  if (result.recommendations?.length > 0) {
    recSection.classList.remove('hidden');
    result.recommendations.forEach((rec) => {
      const li = document.createElement('li');
      li.className = 'rec-item';
      const icon = document.createElement('span');
      icon.className = 'rec-icon'; icon.setAttribute('aria-hidden', 'true');
      icon.textContent = '👉';
      const txt = document.createElement('span');
      txt.textContent = rec;
      li.appendChild(icon); li.appendChild(txt);
      recList.appendChild(li);
    });
  } else {
    recSection.classList.add('hidden');
  }

  // ── Disclaimer ────────────────────────────────────────────
  disclaimerText.textContent = result.disclaimer || '';

  // ── Show and focus ────────────────────────────────────────
  resultsSection.classList.remove('hidden');
  resultsSection.focus();
}

/**
 * Renders the Safe Browsing status banner.
 */
function renderSafeBrowsingStatus(result) {
  if (result.mode !== 'url') { sbStatus.classList.add('hidden'); return; }
  sbStatus.classList.remove('hidden', 'sb-hit', 'sb-clean', 'sb-unavail');
  if (result.safeBrowsingUnavailable) {
    sbStatus.className = 'sb-status sb-unavail';
    sbStatus.textContent = 'ℹ️ Google Safe Browsing check was not available for this scan.';
  } else if (result.safeBrowsingChecked) {
    const hit = result.signals.find((s) => s.id === 'safe_browsing_hit');
    if (hit) {
      sbStatus.className = 'sb-status sb-hit';
      sbStatus.textContent = '🚨 Google Safe Browsing: This URL is flagged as a known threat. Do not visit it.';
    } else {
      sbStatus.className = 'sb-status sb-clean';
      sbStatus.textContent = '✅ Google Safe Browsing: No known threats detected for this URL.';
    }
  } else {
    sbStatus.classList.add('hidden');
  }
}

/**
 * Renders the domain info card.
 */
function renderDomainInfo(info) {
  domainInfoList.innerHTML = '';
  const addRow = (term, def) => {
    const dt = document.createElement('dt'); dt.textContent = term;
    const dd = document.createElement('dd'); dd.textContent = def;
    domainInfoList.appendChild(dt); domainInfoList.appendChild(dd);
  };
  if (info.domain)    addRow('Domain',    info.domain);
  if (info.registrar) addRow('Registrar', info.registrar);
  if (info.ageUnavailable) {
    addRow('Registration Age', 'Unavailable (' + (info.unavailableReason || 'WHOIS lookup failed') + ')');
  } else {
    if (info.createdDate) addRow('Registered On', info.createdDate);
    if (info.ageInDays != null) addRow('Domain Age', formatAge(info.ageInDays));
  }
}

/** Formats days into human-readable age. */
function formatAge(days) {
  if (days < 30)  return days + ' day' + (days !== 1 ? 's' : '') + ' (very new)';
  if (days < 365) { const m = Math.floor(days / 30); return m + ' month' + (m !== 1 ? 's' : ''); }
  const y = Math.floor(days / 365);
  const m = Math.floor((days % 365) / 30);
  return y + ' year' + (y !== 1 ? 's' : '') + (m > 0 ? ', ' + m + ' month' + (m !== 1 ? 's' : '') : '');
}

/**
 * Builds a signal card element (XSS-safe: all textContent).
 */
function buildSignalCard(signal) {
  const card = document.createElement('article');
  card.className = 'signal-card';
  card.setAttribute('aria-label', 'Risk signal: ' + signal.label);

  const header = document.createElement('div'); header.className = 'signal-header';
  const label  = document.createElement('span'); label.className = 'signal-label';
  label.textContent = signal.label;
  const weight = document.createElement('span'); weight.className = 'signal-weight';
  weight.textContent = '+' + signal.weight + ' pts';
  header.appendChild(label); header.appendChild(weight);

  const evidence = document.createElement('p'); evidence.className = 'signal-evidence';
  evidence.textContent = signal.evidence || '(no snippet)';

  const explanation = document.createElement('p'); explanation.className = 'signal-explanation';
  explanation.textContent = signal.explanation || '';

  card.appendChild(header); card.appendChild(evidence); card.appendChild(explanation);
  return card;
}

/**
 * Animates a counter number with ease-out cubic.
 */
function animateNumber(el, start, end, duration) {
  const startTime = performance.now();
  const range = end - start;
  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + range * eased);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ─────────────────────────────────────────────────────────────
   Scan Again
   ───────────────────────────────────────────────────────────── */
scanAgainBtn.addEventListener('click', () => {
  hideResults();
  clearError();
  textInput.value         = '';
  urlInput.value          = '';
  charNum.textContent     = '0';
  selectedFile            = null;
  fileInput.value         = '';
  fileSelectedDisplay.classList.add('hidden');
  visionNotice.classList.add('hidden');
  dropZone.classList.remove('has-file');
  // Return focus to primary input of current mode
  if (currentMode === 'file') dropZone.focus();
  else if (currentMode === 'text') textInput.focus();
  else urlInput.focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});
