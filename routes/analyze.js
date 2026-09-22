'use strict';

// ============================================================
// routes/analyze.js
// POST /api/analyze — main analysis endpoint.
//
// Flow:
//   1. Validate mode (text | url)
//   2. Validate and sanitise input
//   3. Run appropriate analyser(s)
//   4. For URLs: run domain check + Safe Browsing in parallel
//   5. Calculate and return the Scam Threat Index result
// ============================================================

const express = require('express');

const { validateText, validateUrl, validateMode } = require('../utils/inputValidator');
const { createError }      = require('../utils/errorHandler');
const { analyzeText }      = require('../services/textAnalyzer');
const { analyzeUrl }       = require('../services/urlAnalyzer');
const { checkDomainAge }   = require('../services/domainChecker');
const { checkSafeBrowsing } = require('../services/safeBrowsing');
const { calculateScore }   = require('../services/scoreCalculator');

const router = express.Router();

/**
 * POST /api/analyze
 *
 * Request body:
 *   { mode: 'text' | 'url', content: string }
 *
 * Response:
 *   Full Scam Threat Index result object (see scoreCalculator.js)
 */
router.post('/', async (req, res, next) => {
  try {
    const { mode, content } = req.body;

    // ── Step 1: Validate mode ─────────────────────────────────
    if (!validateMode(mode)) {
      return next(createError('Invalid analysis mode. Use "text" or "url".', 400));
    }

    // ── Step 2a: Text analysis ────────────────────────────────
    if (mode === 'text') {
      const validation = validateText(content);
      if (!validation.valid) {
        return next(createError(validation.error, 400));
      }

      const { detectedSignals } = analyzeText(validation.sanitized);

      const result = calculateScore({
        textSignals:       detectedSignals,
        urlSignals:        [],
        domainInfo:        null,
        safeBrowsingResult: null,
        mode:              'text',
      });

      return res.json({
        ...result,
        mode:      'text',
        truncated: validation.truncated || false,
      });
    }

    // ── Step 2b: URL analysis ─────────────────────────────────
    if (mode === 'url') {
      const validation = validateUrl(content);
      if (!validation.valid) {
        return next(createError(validation.error, 400));
      }

      const { parsed } = validation;
      const urlString  = parsed.href;
      const domain     = parsed.hostname;

      // Structural URL analysis (synchronous, no network calls)
      const { detectedSignals: urlSignals } = analyzeUrl(parsed, validation.original);

      // Domain-age check and Safe Browsing run concurrently
      // If either fails, the other still completes (Promise.allSettled not needed —
      // both functions handle their own errors and always resolve, never reject)
      const [domainInfo, safeBrowsingResult] = await Promise.all([
        checkDomainAge(domain).then((info) => ({ ...info, domain })),
        checkSafeBrowsing(urlString),
      ]);

      const result = calculateScore({
        textSignals:        [],
        urlSignals,
        domainInfo,
        safeBrowsingResult,
        mode:               'url',
      });

      return res.json({
        ...result,
        mode:        'url',
        analyzedUrl: urlString,
      });
    }
  } catch (err) {
    // Unexpected errors go to the centralised error handler
    next(err);
  }
});

module.exports = router;
