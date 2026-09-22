'use strict';

// ============================================================
// inputValidator.js
// Validates and sanitises all user input before it reaches
// any analysis or external-service code.
// All validation is performed server-side — client-side checks
// are UX only and not trusted.
// ============================================================

const { INPUT_LIMITS } = require('./constants');

/**
 * Validates and sanitises free-form text input.
 *
 * @param {unknown} text - Raw value received from the request body
 * @returns {{ valid: boolean, sanitized?: string, truncated?: boolean, error?: string }}
 */
function validateText(text) {
  if (typeof text !== 'string') {
    return { valid: false, error: 'Text input must be a string.' };
  }

  const trimmed = text.trim();

  if (trimmed.length === 0) {
    return { valid: false, error: 'Please enter some text to analyse.' };
  }

  if (trimmed.length < 10) {
    return { valid: false, error: 'Please enter at least 10 characters for a meaningful analysis.' };
  }

  let sanitized = trimmed;
  let truncated = false;

  if (sanitized.length > INPUT_LIMITS.maxTextLength) {
    sanitized = sanitized.substring(0, INPUT_LIMITS.maxTextLength);
    truncated = true;
  }

  return { valid: true, sanitized, truncated };
}

/**
 * Validates and parses a URL string.
 * Uses the WHATWG URL API (built into Node ≥ 10) — safe, no eval.
 * The server never fetches the URL; it only parses its structure.
 *
 * @param {unknown} url - Raw value received from the request body
 * @returns {{ valid: boolean, parsed?: URL, original?: string, error?: string }}
 */
function validateUrl(url) {
  if (typeof url !== 'string') {
    return { valid: false, error: 'URL input must be a string.' };
  }

  const trimmed = url.trim();

  if (trimmed.length === 0) {
    return { valid: false, error: 'Please enter a URL to analyse.' };
  }

  if (trimmed.length > INPUT_LIMITS.maxUrlLength) {
    return { valid: false, error: `URL must be ${INPUT_LIMITS.maxUrlLength} characters or fewer.` };
  }

  // Prepend https:// if the user omitted the protocol
  let urlString = trimmed;
  if (!/^https?:\/\//i.test(urlString)) {
    urlString = 'https://' + urlString;
  }

  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return { valid: false, error: 'Please enter a valid URL (e.g., https://example.com).' };
  }

  // Accept only http and https — block file://, ftp://, javascript:, etc.
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, error: 'Only HTTP and HTTPS URLs are supported.' };
  }

  // Reject empty hostname (e.g. "https://")
  if (!parsed.hostname || parsed.hostname.length < 1) {
    return { valid: false, error: 'URL must contain a valid hostname.' };
  }

  return { valid: true, parsed, original: trimmed };
}

/**
 * Validates the analysis mode.
 *
 * @param {unknown} mode - Value received from the request body
 * @returns {boolean}
 */
function validateMode(mode) {
  return mode === 'text' || mode === 'url';
}

module.exports = { validateText, validateUrl, validateMode };
