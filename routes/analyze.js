'use strict';

// ============================================================
// routes/analyze.js
// Analysis API routes.
//
//  POST /api/analyze        — JSON body (text or URL modes)
//  POST /api/analyze/file   — multipart/form-data (file upload)
// ============================================================

const express = require('express');
const multer  = require('multer');

const { validateText, validateUrl, validateMode } = require('../utils/inputValidator');
const { createError }      = require('../utils/errorHandler');
const { analyzeText }      = require('../services/textAnalyzer');
const { analyzeUrl }       = require('../services/urlAnalyzer');
const { checkDomainAge }   = require('../services/domainChecker');
const { checkSafeBrowsing } = require('../services/safeBrowsing');
const { calculateScore }   = require('../services/scoreCalculator');
const { extractText }      = require('../services/fileExtractor');

const router = express.Router();

// ── Multer configuration ──────────────────────────────────────
// Memory storage: file bytes are kept in req.file.buffer;
// nothing is written to disk, eliminating path-traversal risk.
const ALLOWED_MIME_TYPES = new Set([
  'application/pdf',
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/webp',
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB hard limit
  fileFilter: (req, file, cb) => {
    const isAllowed = ALLOWED_MIME_TYPES.has(file.mimetype) ||
                      /\.(pdf|jpg|jpeg|png|webp)$/i.test(file.originalname || '');
    if (isAllowed) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type. Please upload a PDF, JPG, PNG, or WebP file.'));
    }
  },
});

// ── POST /api/analyze  (JSON — text or URL) ───────────────────
router.post('/', async (req, res, next) => {
  try {
    const { mode, content } = req.body;

    if (!validateMode(mode)) {
      return next(createError('Invalid analysis mode. Use "text" or "url".', 400));
    }

    // ─ Text analysis ─────────────────────────────────────────
    if (mode === 'text') {
      const validation = validateText(content);
      if (!validation.valid) return next(createError(validation.error, 400));

      const { detectedSignals } = analyzeText(validation.sanitized);
      const result = calculateScore({ textSignals: detectedSignals, urlSignals: [], domainInfo: null, safeBrowsingResult: null, mode: 'text' });

      return res.json({ ...result, mode: 'text', truncated: validation.truncated || false });
    }

    // ─ URL analysis ──────────────────────────────────────────
    if (mode === 'url') {
      const validation = validateUrl(content);
      if (!validation.valid) return next(createError(validation.error, 400));

      const { parsed } = validation;
      const { detectedSignals: urlSignals } = analyzeUrl(parsed, validation.original);

      const [domainInfo, safeBrowsingResult] = await Promise.all([
        checkDomainAge(parsed.hostname).then((info) => ({ ...info, domain: parsed.hostname })),
        checkSafeBrowsing(parsed.href),
      ]);

      const result = calculateScore({ textSignals: [], urlSignals, domainInfo, safeBrowsingResult, mode: 'url' });

      return res.json({ ...result, mode: 'url', analyzedUrl: parsed.href });
    }
  } catch (err) {
    next(err);
  }
});

// ── POST /api/analyze/file  (multipart — file upload) ─────────
router.post('/file', (req, res, next) => {
  // Wrap multer to intercept its errors and return proper 400 responses
  upload.single('file')(req, res, async (multerErr) => {
    if (multerErr) {
      if (multerErr.code === 'LIMIT_FILE_SIZE') {
        return next(createError('File is too large. Maximum allowed size is 10 MB.', 400));
      }
      return next(createError(multerErr.message || 'File upload failed.', 400));
    }

    if (!req.file) {
      return next(createError('No file was received. Please select a PDF or image file.', 400));
    }

    try {
      const { buffer, mimetype, originalname, size } = req.file;

      // Extract text from the file (PDF → pdf-parse, image → Vision API)
      const extraction = await extractText(buffer, mimetype);

      if (!extraction.text) {
        return next(createError(extraction.error || 'Could not extract readable text from this file.', 422));
      }

      // Validate and sanitise the extracted text
      const validation = validateText(extraction.text);
      if (!validation.valid) {
        return next(
          createError(
            'The extracted text is too short for analysis. ' +
              'The file may be blank or contain only graphics.',
            422,
          ),
        );
      }

      // Run text analysis on the extracted content
      const { detectedSignals } = analyzeText(validation.sanitized);

      const result = calculateScore({
        textSignals:        detectedSignals,
        urlSignals:         [],
        domainInfo:         null,
        safeBrowsingResult: null,
        mode:               'file',
      });

      return res.json({
        ...result,
        mode:                 'file',
        fileName:             originalname,
        fileSize:             size,
        fileType:             mimetype,
        pageCount:            extraction.pageCount ?? null,
        extractedTextPreview: validation.sanitized.substring(0, 600).trim(),
        truncated:            validation.truncated || false,
      });
    } catch (err) {
      next(err);
    }
  });
});

module.exports = router;
