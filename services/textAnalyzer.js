'use strict';

// ============================================================
// textAnalyzer.js
// Analyses free-form text for scam and phishing signals.
// Returns an array of detected signals with evidence snippets.
//
// Design: purely deterministic pattern matching — no external
// API calls. Every detected signal includes a quoted evidence
// snippet from the original text so the user can verify it.
// ============================================================

const { TEXT_SIGNALS } = require('../utils/constants');

/**
 * Extracts a short evidence snippet centred around a regex match.
 *
 * @param {string} text     - Full text being analysed
 * @param {string} matchStr - The matched substring
 * @param {number} padding  - Characters of context on each side
 * @returns {string}
 */
function extractSnippet(text, matchStr, padding = 40) {
  const idx = text.toLowerCase().indexOf(matchStr.toLowerCase());
  if (idx === -1) return `"...${matchStr.substring(0, 80)}..."`;

  const start = Math.max(0, idx - padding);
  const end = Math.min(text.length, idx + matchStr.length + padding);
  const raw = text.substring(start, end).replace(/\s+/g, ' ').trim();

  return `"${start > 0 ? '...' : ''}${raw}${end < text.length ? '...' : ''}"`;
}

/**
 * Detects spam-style formatting (all-caps abuse, excessive exclamation marks).
 *
 * @param {string} text
 * @returns {{ detected: boolean, evidence: string }}
 */
function detectSpamFormatting(text) {
  // Only consider alphabetic characters for caps ratio
  const letters = text.match(/[a-zA-Z]/g) || [];
  const capsLetters = text.match(/[A-Z]/g) || [];
  const capsRatio = letters.length > 20 ? capsLetters.length / letters.length : 0;
  const exclamationCount = (text.match(/!/g) || []).length;

  const triggered = capsRatio > 0.45 || exclamationCount >= 5;
  if (!triggered) return { detected: false, evidence: '' };

  const parts = [];
  if (capsRatio > 0.45) parts.push(`${Math.round(capsRatio * 100)}% of letters are uppercase`);
  if (exclamationCount >= 5) parts.push(`${exclamationCount} exclamation marks`);

  return { detected: true, evidence: parts.join('; ') };
}

/**
 * Analyses text for scam and phishing signals.
 *
 * @param {string} text - Sanitised text (from inputValidator)
 * @returns {{ detectedSignals: Array<Object> }}
 */
function analyzeText(text) {
  const detectedSignals = [];

  for (const signal of TEXT_SIGNALS) {
    // spam_formatting uses custom logic, not patterns array
    if (signal.id === 'spam_formatting') {
      const { detected, evidence } = detectSpamFormatting(text);
      if (detected) {
        detectedSignals.push({ ...signal, patterns: undefined, evidence });
      }
      continue;
    }

    // Test each regex pattern; report signal on first match
    for (const pattern of signal.patterns) {
      const match = text.match(pattern);
      if (match) {
        const evidence = extractSnippet(text, match[0]);
        // Clone signal without the patterns array (not needed in response)
        detectedSignals.push({
          id: signal.id,
          label: signal.label,
          weight: signal.weight,
          explanation: signal.explanation,
          evidence,
        });
        break; // Each signal type is reported at most once
      }
    }
  }

  return { detectedSignals };
}

module.exports = { analyzeText };
