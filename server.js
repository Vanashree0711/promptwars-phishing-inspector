'use strict';

// ============================================================
// server.js
// Express application entry point.
//
// Middleware stack (in order):
//   1. helmet      — security headers (CSP, HSTS, X-Frame, etc.)
//   2. JSON body   — parse request bodies (50 KB limit)
//   3. Rate limit  — 30 requests/minute per IP on /api/
//   4. Static      — serve /public directory
//   5. Routes      — /api/analyze, /api/health
//   6. SPA catch   — serve index.html for all other GET paths
//   7. Error handler — centralised safe error responses
// ============================================================

require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

const { errorHandler } = require('./utils/errorHandler');
const analyzeRoute     = require('./routes/analyze');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Security headers via helmet ───────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:  ["'self'"],
        scriptSrc:   ["'self'"],
        styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
        imgSrc:      ["'self'", 'data:'],
        connectSrc:  ["'self'"],
        frameSrc:    ["'none'"],
        objectSrc:   ["'none'"],
        baseUri:     ["'self'"],
        formAction:  ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false, // Allows Google Fonts to load
  }),
);

// ── Body parsing (limited to 50 KB) ──────────────────────────
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// ── Rate limiting on all API routes ──────────────────────────
// 30 requests per minute per IP address
const apiLimiter = rateLimit({
  windowMs:       60 * 1000,
  max:            30,
  standardHeaders: true,
  legacyHeaders:  false,
  message:        { error: true, message: 'Too many requests. Please wait a moment and try again.' },
  skip:           (req) => req.path === '/api/health', // Health checks bypass rate limit
});
app.use('/api/', apiLimiter);

// ── Static files (public/) ────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── API routes ────────────────────────────────────────────────
app.use('/api/analyze', analyzeRoute);

// Health check — returns service status (used by Docker HEALTHCHECK)
app.get('/api/health', (req, res) => {
  res.json({
    status:                    'ok',
    timestamp:                 new Date().toISOString(),
    safeBrowsingConfigured:    !!process.env.GOOGLE_SAFE_BROWSING_API_KEY &&
                               process.env.GOOGLE_SAFE_BROWSING_API_KEY !== 'your_google_safe_browsing_api_key_here',
  });
});

// ── SPA fallback — serve index.html for all non-API GET routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Centralised error handler (must be registered last) ──────
app.use(errorHandler);

// ── Start server ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[Server] Phishing Inspector running on http://localhost:${PORT}`);
  console.log(`[Server] Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`[Server] Safe Browsing API: ${
    process.env.GOOGLE_SAFE_BROWSING_API_KEY &&
    process.env.GOOGLE_SAFE_BROWSING_API_KEY !== 'your_google_safe_browsing_api_key_here'
      ? 'Configured ✓'
      : 'Not configured — Safe Browsing checks will be skipped (graceful degradation)'
  }`);
});

// Export for testing purposes
module.exports = app;
