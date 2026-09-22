'use strict';

// ============================================================
// errorHandler.js
// Centralised Express error handling middleware and helper
// to create structured API errors.
//
// Security: Stack traces and internal paths are never exposed
// to clients — they are logged server-side only.
// ============================================================

/**
 * Express error-handling middleware (must have 4 parameters).
 * Registered as the last middleware in server.js.
 *
 * @param {Error} err
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  // Log full details server-side (never sent to client)
  console.error('[ErrorHandler]', {
    message: err.message,
    status: err.status,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
    // Only include stack in development
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });

  const status = err.status || err.statusCode || 500;

  // For 4xx errors, the message is safe to forward (it comes from our own validators).
  // For 5xx errors, return a generic message to prevent information leakage.
  const message =
    status < 500
      ? err.message
      : 'An internal error occurred. Please try again later.';

  res.status(status).json({ error: true, message });
}

/**
 * Creates a structured API error that the error handler will process.
 *
 * @param {string} message - Safe, user-facing error message
 * @param {number} [status=400] - HTTP status code
 * @returns {Error}
 */
function createError(message, status = 400) {
  const err = new Error(message);
  err.status = status;
  return err;
}

module.exports = { errorHandler, createError };
