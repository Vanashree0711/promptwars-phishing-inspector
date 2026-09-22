'use strict';

// ============================================================
// safeBrowsing.js
// Google Safe Browsing API v4 client.
//
// This module checks a URL against Google's continuously
// updated database of phishing, malware, and unwanted
// software sites.
//
// SECURITY:
//   - API key read from environment variable only
//   - Never logged or exposed to clients
//   - 5-second request timeout
//   - Graceful degradation if key absent or API fails
// ============================================================

const SAFE_BROWSING_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

/** Human-readable labels for Safe Browsing threat type codes */
const THREAT_LABELS = {
  MALWARE: 'Malware',
  SOCIAL_ENGINEERING: 'Phishing / Social Engineering',
  UNWANTED_SOFTWARE: 'Unwanted Software',
  POTENTIALLY_HARMFUL_APPLICATION: 'Potentially Harmful Application',
};

/**
 * Checks a URL against the Google Safe Browsing API v4.
 *
 * @param {string} url - The full URL string to check
 * @returns {Promise<{
 *   isMalicious: boolean,
 *   threatType: string|null,
 *   threatLabel: string|null,
 *   error: string|null
 * }>}
 */
async function checkSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey || apiKey === 'your_google_safe_browsing_api_key_here') {
    // Not configured — skip check, do not penalise score
    console.warn('[SafeBrowsing] API key not configured. Skipping Safe Browsing check.');
    return { isMalicious: false, threatType: null, threatLabel: null, error: 'Safe Browsing check not configured' };
  }

  const requestBody = {
    client: {
      clientId: 'phishing-inspector',
      clientVersion: '1.0.0',
    },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  };

  try {
    // AbortSignal.timeout is available in Node ≥ 17.3
    const signal = typeof AbortSignal.timeout === 'function'
      ? AbortSignal.timeout(5000)
      : undefined;

    const response = await fetch(
      `${SAFE_BROWSING_ENDPOINT}?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        ...(signal && { signal }),
      },
    );

    if (!response.ok) {
      // Log status code server-side; do not expose to client
      console.error('[SafeBrowsing] API returned HTTP', response.status);
      return { isMalicious: false, threatType: null, threatLabel: null, error: 'Safe Browsing API returned an error' };
    }

    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      const { threatType } = data.matches[0];
      return {
        isMalicious: true,
        threatType,
        threatLabel: THREAT_LABELS[threatType] || threatType,
        error: null,
      };
    }

    return { isMalicious: false, threatType: null, threatLabel: null, error: null };
  } catch (err) {
    console.error('[SafeBrowsing] Request failed:', err.message);
    return { isMalicious: false, threatType: null, threatLabel: null, error: 'Safe Browsing check unavailable' };
  }
}

module.exports = { checkSafeBrowsing };
