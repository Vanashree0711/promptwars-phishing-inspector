'use strict';

// ============================================================
// services/fileExtractor.js
// Extracts readable text from uploaded PDF and image files.
//
// PDF files  → pdf-parse (no API key required)
// Image files → Google Cloud Vision API v1 (DOCUMENT_TEXT_DETECTION)
//               Graceful degradation if API key not configured.
//
// SECURITY: Files are processed in-memory (Buffer) only.
// Nothing is written to disk. Nothing is returned to the user
// except extracted text and metadata.
// ============================================================

const VISION_API_URL = 'https://vision.googleapis.com/v1/images:annotate';

/** Supported image MIME types */
const IMAGE_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/png', 'image/webp']);

/**
 * Extracts text from a PDF buffer using pdf-parse.
 *
 * @param {Buffer} buffer
 * @returns {Promise<{ text: string|null, pageCount: number|null, error: string|null }>}
 */
async function extractFromPdf(buffer) {
  try {
    const pdfParse = require('pdf-parse');
    const data = await pdfParse(buffer);

    const text = (data.text || '').trim();

    if (text.length < 20) {
      return {
        text: null,
        pageCount: data.numpages || null,
        error:
          'This PDF appears to contain scanned images rather than selectable text. ' +
          'Please export as an image (JPG/PNG) and upload again, or paste the text manually.',
      };
    }

    return { text, pageCount: data.numpages || null, error: null };
  } catch (err) {
    console.error('[FileExtractor] PDF parsing failed:', err.message);
    return { text: null, pageCount: null, error: 'Failed to read this PDF. It may be encrypted or corrupted.' };
  }
}

/**
 * Extracts text from an image buffer using Google Cloud Vision API v1.
 * DOCUMENT_TEXT_DETECTION is used for better accuracy on structured documents.
 *
 * @param {Buffer} buffer
 * @param {string} mimetype
 * @returns {Promise<{ text: string|null, error: string|null }>}
 */
async function extractFromImage(buffer, mimetype) {
  const apiKey = process.env.GOOGLE_CLOUD_VISION_API_KEY;

  if (!apiKey || apiKey === 'your_google_cloud_vision_api_key_here') {
    return {
      text: null,
      error:
        'Image OCR requires the Google Cloud Vision API to be configured. ' +
        'Please add GOOGLE_CLOUD_VISION_API_KEY to your .env file, or paste the text from the letter manually.',
    };
  }

  try {
    const base64Content = buffer.toString('base64');

    const signal =
      typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(20000) : undefined;

    const response = await fetch(`${VISION_API_URL}?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        requests: [
          {
            image: { content: base64Content },
            features: [{ type: 'DOCUMENT_TEXT_DETECTION', maxResults: 1 }],
          },
        ],
      }),
      ...(signal && { signal }),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      console.error('[FileExtractor] Vision API HTTP error:', response.status, errText.substring(0, 200));
      return { text: null, error: 'Google Cloud Vision API returned an error. Please try again.' };
    }

    const data = await response.json();

    // Check for API-level error
    if (data.responses?.[0]?.error) {
      const apiErr = data.responses[0].error;
      console.error('[FileExtractor] Vision API error:', apiErr);
      return { text: null, error: 'Google Cloud Vision API error: ' + (apiErr.message || 'unknown') };
    }

    const text = (data.responses?.[0]?.fullTextAnnotation?.text || '').trim();

    if (text.length < 20) {
      return {
        text: null,
        error: 'No readable text was found in this image. Please ensure the image is clear and well-lit.',
      };
    }

    return { text, pageCount: null, error: null };
  } catch (err) {
    console.error('[FileExtractor] Vision API request failed:', err.message);
    return { text: null, pageCount: null, error: 'Image OCR service is currently unavailable. Please try again or paste the text manually.' };
  }
}

/**
 * Routes the extraction to the correct method based on MIME type.
 *
 * @param {Buffer} buffer
 * @param {string} mimetype
 * @returns {Promise<{ text: string|null, pageCount: number|null, error: string|null }>}
 */
async function extractText(buffer, mimetype) {
  if (mimetype === 'application/pdf') {
    return extractFromPdf(buffer);
  }
  if (IMAGE_TYPES.has(mimetype)) {
    const result = await extractFromImage(buffer, mimetype);
    return { ...result, pageCount: null };
  }
  return { text: null, pageCount: null, error: 'Unsupported file type.' };
}

module.exports = { extractText };
