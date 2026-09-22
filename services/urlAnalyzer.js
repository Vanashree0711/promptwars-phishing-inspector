'use strict';

// ============================================================
// urlAnalyzer.js
// Analyses the structure of a URL for risk signals.
//
// SECURITY NOTE: This module NEVER fetches the user-supplied
// URL. It only inspects the URL's components using the WHATWG
// URL API, which eliminates SSRF risk entirely.
// ============================================================

const { URL_SIGNALS, KNOWN_URL_SHORTENERS, SUSPICIOUS_TLDS, KNOWN_BRANDS } = require('../utils/constants');

/**
 * Computes the Levenshtein edit distance between two strings.
 * Used for lookalike / typosquatting domain detection.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;

  // Build m+1 × n+1 DP table
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/**
 * Safely finds a signal definition by id.
 *
 * @param {string} id
 * @returns {Object}
 */
function getSignal(id) {
  return URL_SIGNALS.find((s) => s.id === id);
}

/**
 * Analyses a parsed URL object for structural risk signals.
 * Called with a WHATWG URL object produced by inputValidator.
 *
 * @param {URL}    parsedUrl - Validated URL object
 * @param {string} original  - Original user-supplied string (for display)
 * @returns {{ detectedSignals: Array<Object>, domainName: string }}
 */
function analyzeUrl(parsedUrl, original) {
  const detectedSignals = [];
  const hostname = parsedUrl.hostname.toLowerCase();
  const fullUrl   = parsedUrl.href;

  // Decompose hostname into parts
  const parts   = hostname.split('.');
  const tld     = parts[parts.length - 1];                      // e.g. "com"
  const sld     = parts.length >= 2 ? parts[parts.length - 2] : hostname; // e.g. "example"
  const fullHost = hostname;

  // ── 1. Insecure HTTP ─────────────────────────────────────────
  if (parsedUrl.protocol === 'http:') {
    const sig = getSignal('insecure_protocol');
    detectedSignals.push({ ...sig, evidence: `Protocol used: HTTP (not HTTPS)` });
  }

  // ── 2. IP-based URL ─────────────────────────────────────────
  const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Re = /^\[?[0-9a-fA-F:]+\]?$/;
  if (ipv4Re.test(hostname) || ipv6Re.test(hostname)) {
    const sig = getSignal('ip_based_url');
    detectedSignals.push({ ...sig, evidence: `Host: ${hostname}` });
  }

  // ── 3. URL shortener ────────────────────────────────────────
  if (KNOWN_URL_SHORTENERS.has(fullHost) || KNOWN_URL_SHORTENERS.has(`${sld}.${tld}`)) {
    const sig = getSignal('url_shortener');
    detectedSignals.push({ ...sig, evidence: `Shortener domain: ${fullHost}` });
  }

  // ── 4. Suspicious TLD ───────────────────────────────────────
  if (SUSPICIOUS_TLDS.has(tld)) {
    const sig = getSignal('suspicious_tld');
    detectedSignals.push({ ...sig, evidence: `Top-level domain: .${tld}` });
  }

  // ── 5. Lookalike / typosquatting domain ─────────────────────
  // Compare the second-level domain against known brand names.
  // Only flag if edit distance is 1–2 AND the names are not identical.
  let lookalikeBrand = null;
  for (const brand of KNOWN_BRANDS) {
    if (sld === brand) break; // Exact match — not a lookalike
    const dist = levenshteinDistance(sld.toLowerCase(), brand.toLowerCase());
    if (dist >= 1 && dist <= 2) {
      lookalikeBrand = brand;
      break;
    }
  }
  if (lookalikeBrand) {
    const sig = getSignal('lookalike_domain');
    detectedSignals.push({
      ...sig,
      evidence: `Domain "${sld}" is ${levenshteinDistance(sld, lookalikeBrand)} character(s) away from known brand "${lookalikeBrand}"`,
    });
  }

  // ── 6. Excessive subdomains ─────────────────────────────────
  // More than 3 labels in the hostname (excluding TLD and SLD)
  if (parts.length > 4) {
    const sig = getSignal('excessive_subdomains');
    detectedSignals.push({ ...sig, evidence: `${parts.length} domain levels found: ${fullHost}` });
  }

  // ── 7. Numeric / obfuscated subdomain ───────────────────────
  if (parts.length > 2) {
    const subdomains = parts.slice(0, -2); // Everything except SLD + TLD
    const numericSub = subdomains.find((p) => p.length > 1 && /\d/.test(p));
    if (numericSub) {
      const sig = getSignal('numeric_subdomain');
      detectedSignals.push({ ...sig, evidence: `Numeric subdomain: "${numericSub}" in ${fullHost}` });
    }
  }

  // ── 8. Excessively long URL ──────────────────────────────────
  if (fullUrl.length > 150) {
    const sig = getSignal('long_url');
    detectedSignals.push({ ...sig, evidence: `URL length: ${fullUrl.length} characters` });
  }

  return { detectedSignals, domainName: hostname };
}

module.exports = { analyzeUrl };
