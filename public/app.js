/**
 * app.js — Phishing Inspector frontend
 *
 * Responsibilities:
 *   - Tab switching (Text / URL modes)
 *   - Character counter for textarea
 *   - Form submission → POST /api/analyze
 *   - Rendering the Scam Threat Index result
 *   - Animated SVG gauge
 *   - Accessible state management (aria-live, focus, alerts)
 *
 * Security: All user-supplied text is inserted via textContent,
 * never innerHTML, preventing XSS injection in the UI.
 */

'use strict';

/* ── DOM references ─────────────────────────────────────────── */
const tabTextBtn        = document.getElementById('tab-text');
const tabUrlBtn         = document.getElementById('tab-url');
const panelText         = document.getElementById('panel-text');
const panelUrl          = document.getElementById('panel-url');
const textInput         = document.getElementById('text-input');
const urlInput          = document.getElementById('url-input');
const charNum           = document.getElementById('char-num');
const scanForm          = document.getElementById('scan-form');
const scanBtn           = document.getElementById('scan-btn');
const btnText           = document.getElementById('btn-text');
const btnLoading        = document.getElementById('btn-loading');
const formError         = document.getElementById('form-error');
const truncationNotice  = document.getElementById('truncation-notice');
const loadingSection    = document.getElementById('loading-section');
const loadingStep       = document.getElementById('loading-step');
const resultsSection    = document.getElementById('results-section');
const scanAgainBtn      = document.getElementById('scan-again-btn');

// Score card elements
const gaugeArc          = document.getElementById('gauge-arc');
const gaugeScore        = document.getElementById('gauge-score');
const riskBadge         = document.getElementById('risk-badge');
const riskEmoji         = document.getElementById('risk-emoji');
const riskLevelText     = document.getElementById('risk-level-text');
const riskDescription   = document.getElementById('risk-description');
const scoreMethodology  = document.getElementById('score-methodology');
const sbStatus          = document.getElementById('sb-status');
const domainCard        = document.getElementById('domain-card');
const domainInfoList    = document.getElementById('domain-info-list');

// Signal / recommendation elements
const signalCountBadge  = document.getElementById('signal-count-badge');
const signalsContainer  = document.getElementById('signals-container');
const noSignalsMsg      = document.getElementById('no-signals-msg');
const recommendationsSec = document.getElementById('recommendations-section');
const recommendationsList = document.getElementById('recommendations-list');
const disclaimerText    = document.getElementById('disclaimer-text');

/* ── SVG gauge constants ────────────────────────────────────── */
const GAUGE_RADIUS        = 90;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS; // ≈ 565.49

/* ── Risk level → CSS class mapping ─────────────────────────── */
const RISK_CLASS = {
  Low:      'risk-low',
  Moderate: 'risk-moderate',
  High:     'risk-high',
  Critical: 'risk-critical',
};

/* ── Risk level → gauge stroke colour ───────────────────────── */
const RISK_COLOUR = {
  Low:      '#22c55e',
  Moderate: '#eab308',
  High:     '#f97316',
  Critical: '#ef4444',
};

/* ── State ──────────────────────────────────────────────────── */
let currentMode = 'text'; // 'text' | 'url'

/* ─────────────────────────────────────────────────────────────
   Tab switching
   ───────────────────────────────────────────────────────────── */
function activateTab(mode) {
  currentMode = mode;

  if (mode === 'text') {
    tabTextBtn.setAttribute('aria-selected', 'true');
    tabTextBtn.classList.add('tab-active');
    tabUrlBtn.setAttribute('aria-selected', 'false');
    tabUrlBtn.classList.remove('tab-active');

    panelText.classList.remove('hidden');
    panelText.removeAttribute('aria-hidden');
    panelUrl.classList.add('hidden');
    panelUrl.setAttribute('aria-hidden', 'true');
  } else {
    tabUrlBtn.setAttribute('aria-selected', 'true');
    tabUrlBtn.classList.add('tab-active');
    tabTextBtn.setAttribute('aria-selected', 'false');
    tabTextBtn.classList.remove('tab-active');

    panelUrl.classList.remove('hidden');
    panelUrl.removeAttribute('aria-hidden');
    panelText.classList.add('hidden');
    panelText.setAttribute('aria-hidden', 'true');
  }

  clearError();
  hideResults();
}

tabTextBtn.addEventListener('click', () => activateTab('text'));
tabUrlBtn.addEventListener('click',  () => activateTab('url'));

// Keyboard: arrow keys navigate between tabs (ARIA tabs pattern)
[tabTextBtn, tabUrlBtn].forEach((btn, index, arr) => {
  btn.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      const next = arr[(index + 1) % arr.length];
      next.click();
      next.focus();
    }
    if (e.key === 'ArrowLeft') {
      e.preventDefault();
      const prev = arr[(index - 1 + arr.length) % arr.length];
      prev.click();
      prev.focus();
    }
  });
});

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

  // Gather input
  const content = currentMode === 'text'
    ? textInput.value
    : urlInput.value;

  // Client-side quick validation (server validates definitively)
  if (!content || !content.trim()) {
    showError(
      currentMode === 'text'
        ? 'Please enter some text to analyse.'
        : 'Please enter a URL to analyse.',
    );
    (currentMode === 'text' ? textInput : urlInput).focus();
    return;
  }

  setScanningState(true);
  showLoading(true);

  try {
    const steps = ['Parsing content…', 'Checking for payment red flags…', 'Analysing domain signals…', 'Calculating Scam Threat Index…'];
    let stepIndex = 0;
    const stepInterval = setInterval(() => {
      if (stepIndex < steps.length) {
        loadingStep.textContent = steps[stepIndex++];
      } else {
        clearInterval(stepInterval);
      }
    }, 700);

    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: currentMode, content: content.trim() }),
    });

    clearInterval(stepInterval);

    // Handle server errors
    if (!response.ok) {
      let errorMsg = 'Analysis failed. Please try again.';
      try {
        const errData = await response.json();
        if (errData && errData.message) errorMsg = errData.message;
      } catch {
        // JSON parse failed — use default message
      }
      throw new Error(errorMsg);
    }

    const result = await response.json();

    showLoading(false);
    setScanningState(false);
    renderResult(result);

  } catch (err) {
    showLoading(false);
    setScanningState(false);

    // Network failure vs API error
    const message = err.message || 'Unable to reach the analysis service. Please check your connection and try again.';
    showError(message);
  }
});

/* ─────────────────────────────────────────────────────────────
   UI state helpers
   ───────────────────────────────────────────────────────────── */
function setScanningState(isScanning) {
  scanBtn.disabled = isScanning;
  btnText.classList.toggle('hidden', isScanning);
  btnLoading.classList.toggle('hidden', !isScanning);
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
  truncationNotice.classList.add('hidden');
}

function hideResults() {
  resultsSection.classList.add('hidden');
}

/* ─────────────────────────────────────────────────────────────
   Render results
   ───────────────────────────────────────────────────────────── */
function renderResult(result) {
  // Truncation notice
  if (result.truncated) {
    truncationNotice.classList.remove('hidden');
  }

  // ── Gauge animation ──────────────────────────────────────
  const score      = Math.min(100, Math.max(0, result.score));
  const offset     = GAUGE_CIRCUMFERENCE * (1 - score / 100);
  const arcColour  = RISK_COLOUR[result.riskLevel] || '#3b82f6';

  // Reset (so animation replays on subsequent scans)
  gaugeArc.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  gaugeArc.style.stroke           = arcColour;
  gaugeScore.style.color          = arcColour;
  gaugeScore.textContent          = '0';

  // Trigger animation after a frame
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      gaugeArc.style.strokeDashoffset = offset;
      animateNumber(gaugeScore, 0, score, 900);
    });
  });

  // ── Risk badge ───────────────────────────────────────────
  const riskClass = RISK_CLASS[result.riskLevel] || '';
  riskBadge.className = 'risk-badge ' + riskClass;
  riskEmoji.textContent = result.riskEmoji || '';
  riskLevelText.textContent = result.riskLevel + ' Risk';

  // ── Descriptions ─────────────────────────────────────────
  riskDescription.textContent  = result.riskDescription || '';
  scoreMethodology.textContent = result.methodology     || '';

  // ── Safe Browsing status ─────────────────────────────────
  renderSafeBrowsingStatus(result);

  // ── Domain info (URL mode) ───────────────────────────────
  if (result.mode === 'url' && result.domainInfo) {
    renderDomainInfo(result.domainInfo);
    domainCard.classList.remove('hidden');
  } else {
    domainCard.classList.add('hidden');
  }

  // ── Signals ──────────────────────────────────────────────
  signalsContainer.innerHTML = ''; // Clear previous results (static content only)
  signalCountBadge.textContent = result.signals.length;

  if (result.signals.length > 0) {
    noSignalsMsg.classList.add('hidden');
    result.signals.forEach((signal) => {
      signalsContainer.appendChild(buildSignalCard(signal));
    });
  } else {
    noSignalsMsg.classList.remove('hidden');
  }

  // ── Recommendations ──────────────────────────────────────
  recommendationsList.innerHTML = '';
  if (result.recommendations && result.recommendations.length > 0) {
    recommendationsSec.classList.remove('hidden');
    result.recommendations.forEach((rec) => {
      const li  = document.createElement('li');
      li.className = 'rec-item';

      const icon = document.createElement('span');
      icon.className = 'rec-icon';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = '👉';

      const text = document.createElement('span');
      text.textContent = rec; // Safe: textContent, not innerHTML

      li.appendChild(icon);
      li.appendChild(text);
      recommendationsList.appendChild(li);
    });
  } else {
    recommendationsSec.classList.add('hidden');
  }

  // ── Disclaimer ───────────────────────────────────────────
  disclaimerText.textContent = result.disclaimer || '';

  // ── Show results & move focus for accessibility ──────────
  resultsSection.classList.remove('hidden');
  // Move focus to results section so screen readers announce it
  resultsSection.focus();
}

/**
 * Renders the Google Safe Browsing check status banner.
 */
function renderSafeBrowsingStatus(result) {
  if (result.mode !== 'url') {
    sbStatus.classList.add('hidden');
    return;
  }

  sbStatus.classList.remove('hidden', 'sb-hit', 'sb-clean', 'sb-unavailable');

  if (result.safeBrowsingUnavailable) {
    sbStatus.className = 'sb-status sb-unavailable';
    sbStatus.textContent = 'ℹ️ Google Safe Browsing check was unavailable for this scan (API not configured or network issue).';
  } else if (result.safeBrowsingChecked) {
    // Find the safe browsing signal in the signals list
    const sbSignal = result.signals.find((s) => s.id === 'safe_browsing_hit');
    if (sbSignal) {
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
 * Renders the domain information card.
 * @param {{ domain, ageInDays, createdDate, registrar, ageUnavailable, unavailableReason }} info
 */
function renderDomainInfo(info) {
  domainInfoList.innerHTML = '';

  const addRow = (term, definition) => {
    const dt = document.createElement('dt');
    dt.textContent = term;

    const dd = document.createElement('dd');
    dd.textContent = definition; // Safe: textContent

    domainInfoList.appendChild(dt);
    domainInfoList.appendChild(dd);
  };

  if (info.domain)    addRow('Domain',     info.domain);
  if (info.registrar) addRow('Registrar',  info.registrar);

  if (info.ageUnavailable) {
    addRow('Registration Age', 'Unavailable (' + (info.unavailableReason || 'WHOIS lookup failed') + ')');
  } else {
    if (info.createdDate) addRow('Registered On', info.createdDate);
    if (info.ageInDays !== null && info.ageInDays !== undefined) {
      addRow('Domain Age', formatAge(info.ageInDays));
    }
  }
}

/**
 * Formats domain age in days into a human-readable string.
 * @param {number} days
 * @returns {string}
 */
function formatAge(days) {
  if (days < 30)  return `${days} day${days !== 1 ? 's' : ''} (very new)`;
  if (days < 365) return `${Math.floor(days / 30)} month${Math.floor(days / 30) !== 1 ? 's' : ''}`;
  const years = Math.floor(days / 365);
  const months = Math.floor((days % 365) / 30);
  return `${years} year${years !== 1 ? 's' : ''}${months > 0 ? `, ${months} month${months !== 1 ? 's' : ''}` : ''}`;
}

/**
 * Builds a DOM element for a detected signal card.
 * All user-derived text is inserted via textContent (XSS-safe).
 *
 * @param {{ id, label, weight, evidence, explanation }} signal
 * @returns {HTMLElement}
 */
function buildSignalCard(signal) {
  const card = document.createElement('article');
  card.className = 'signal-card';
  card.setAttribute('aria-label', 'Risk signal: ' + signal.label);

  // Header row: label + weight badge
  const header = document.createElement('div');
  header.className = 'signal-header';

  const label = document.createElement('span');
  label.className = 'signal-label';
  label.textContent = signal.label; // textContent — safe

  const weightBadge = document.createElement('span');
  weightBadge.className = 'signal-weight';
  weightBadge.textContent = '+' + signal.weight + ' pts';

  header.appendChild(label);
  header.appendChild(weightBadge);

  // Evidence (quoted text from the scanned content)
  const evidence = document.createElement('p');
  evidence.className = 'signal-evidence';
  evidence.textContent = signal.evidence || '(no snippet available)'; // textContent — safe

  // Explanation
  const explanation = document.createElement('p');
  explanation.className = 'signal-explanation';
  explanation.textContent = signal.explanation || ''; // textContent — safe

  card.appendChild(header);
  card.appendChild(evidence);
  card.appendChild(explanation);

  return card;
}

/**
 * Animates a number from start to end over duration ms.
 *
 * @param {HTMLElement} element - Target element
 * @param {number} start
 * @param {number} end
 * @param {number} duration - ms
 */
function animateNumber(element, start, end, duration) {
  const startTime = performance.now();
  const range     = end - start;

  function step(currentTime) {
    const elapsed  = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Ease-out cubic
    const eased    = 1 - Math.pow(1 - progress, 3);
    element.textContent = Math.round(start + range * eased);
    if (progress < 1) requestAnimationFrame(step);
  }

  requestAnimationFrame(step);
}

/* ─────────────────────────────────────────────────────────────
   Scan Again button
   ───────────────────────────────────────────────────────────── */
scanAgainBtn.addEventListener('click', () => {
  hideResults();
  clearError();
  textInput.value  = '';
  urlInput.value   = '';
  charNum.textContent = '0';
  truncationNotice.classList.add('hidden');
  // Return focus to the appropriate input
  if (currentMode === 'text') {
    textInput.focus();
  } else {
    urlInput.focus();
  }
  // Scroll back to top smoothly
  window.scrollTo({ top: 0, behavior: 'smooth' });
});
