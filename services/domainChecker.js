'use strict';

// ============================================================
// domainChecker.js
// Checks domain registration age via WHOIS lookup.
//
// The result is used by scoreCalculator.js to apply domain-age
// risk signals.  All failures are handled gracefully:
//   - WHOIS unavailable  → null ageInDays, no score penalty
//   - Timeout            → null ageInDays, no score penalty
//   - No creation date   → null ageInDays, no score penalty
//
// Why no score penalty for missing data?  We must not punish
// users for querying legitimate domains whose WHOIS is
// private or simply unavailable.
// ============================================================

/** Maximum time (ms) to wait for a WHOIS response */
const WHOIS_TIMEOUT_MS = 7000;

/**
 * Attempts to parse a creation date from a WHOIS server result object.
 * Different registrars use different field names.
 *
 * @param {Object} serverData - One entry from whoiser's result object
 * @returns {Date|null}
 */
function parseCreationDate(serverData) {
  if (!serverData || typeof serverData !== 'object') return null;

  const dateFields = [
    'Created Date',
    'Creation Date',
    'created',
    'created date',
    'Domain Registration Date',
    'Registration Time',
    'Registered On',
    'registered',
  ];

  for (const field of dateFields) {
    const raw = serverData[field];
    if (!raw) continue;

    const value = Array.isArray(raw) ? raw[0] : raw;
    const parsed = new Date(value);
    if (!isNaN(parsed.getTime())) return parsed;
  }
  return null;
}

/**
 * Attempts to extract registrar name from a WHOIS server result.
 *
 * @param {Object} serverData
 * @returns {string|null}
 */
function parseRegistrar(serverData) {
  if (!serverData || typeof serverData !== 'object') return null;

  const fields = ['Registrar', 'registrar', 'Sponsoring Registrar', 'Registrar Name'];
  for (const field of fields) {
    const raw = serverData[field];
    if (raw) return Array.isArray(raw) ? raw[0] : raw;
  }
  return null;
}

/**
 * Checks the registration age of a domain using WHOIS.
 *
 * @param {string} domain - Hostname extracted from the validated URL
 * @returns {Promise<{
 *   ageInDays: number|null,
 *   createdDate: string|null,
 *   registrar: string|null,
 *   error: string|null
 * }>}
 */
async function checkDomainAge(domain) {
  try {
    // whoiser supports both CJS require and ESM import
    // Dynamic import ensures compatibility across module systems
    const whoiserModule = await import('whoiser');
    const whoiser = whoiserModule.default ?? whoiserModule;

    const lookupResult = await Promise.race([
      whoiser(domain, { timeout: WHOIS_TIMEOUT_MS - 1000, follow: 1 }),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error('WHOIS lookup timed out')),
          WHOIS_TIMEOUT_MS,
        ),
      ),
    ]);

    if (!lookupResult || typeof lookupResult !== 'object') {
      return { ageInDays: null, createdDate: null, registrar: null, error: 'No WHOIS data returned' };
    }

    // whoiser returns { 'whois.verisign-grs.com': { ... }, ... }
    // Iterate through all server results to find creation date
    let creationDate = null;
    let registrar    = null;

    for (const serverData of Object.values(lookupResult)) {
      // Skip raw/unparsed entries that whoiser may include
      if (serverData && serverData.__raw) continue;

      if (!creationDate) creationDate = parseCreationDate(serverData);
      if (!registrar)    registrar    = parseRegistrar(serverData);
      if (creationDate && registrar)   break;
    }

    if (!creationDate) {
      return { ageInDays: null, createdDate: null, registrar, error: 'Creation date not found in WHOIS data' };
    }

    const ageInDays = Math.floor(
      (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24),
    );

    return {
      ageInDays,
      createdDate: creationDate.toISOString().split('T')[0], // YYYY-MM-DD
      registrar: registrar || null,
      error: null,
    };
  } catch (err) {
    // Log server-side only — never expose to client
    console.error('[DomainChecker] WHOIS failed:', err.message);
    return { ageInDays: null, createdDate: null, registrar: null, error: 'WHOIS lookup unavailable' };
  }
}

module.exports = { checkDomainAge };
