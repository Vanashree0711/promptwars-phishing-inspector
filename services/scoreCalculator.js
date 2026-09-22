'use strict';

// ============================================================
// scoreCalculator.js
// Calculates the final Scam Threat Index (STI) and assembles
// the complete result object returned to the client.
//
// STI Formula:
//   score = min(100, Σ weight_i)   for each detected signal i
//
// The score is fully deterministic and traceable:
// every point added corresponds to a visible signal with
// evidence that the user can inspect.
// ============================================================

const { RISK_LEVELS, SAFETY_RECOMMENDATIONS, URL_SIGNALS } = require('../utils/constants');

/**
 * Finds a URL signal definition by id.
 * @param {string} id
 * @returns {Object}
 */
function getUrlSignal(id) {
  return URL_SIGNALS.find((s) => s.id === id);
}

/**
 * Builds a deduplicated list of safety recommendations based on
 * which signal categories were detected.
 *
 * @param {Array<Object>} allSignals
 * @param {{ isMalicious: boolean }|null} safeBrowsingResult
 * @returns {string[]}
 */
function buildRecommendations(allSignals, safeBrowsingResult) {
  const recs = new Set();
  const ids  = new Set(allSignals.map((s) => s.id));

  if (safeBrowsingResult && safeBrowsingResult.isMalicious) {
    recs.add(SAFETY_RECOMMENDATIONS.safe_browsing_hit);
  }

  const paymentIds = [
    'explicit_payment_demand',
    'fee_before_employment',
    'equipment_fee',
    'security_deposit',
    'cryptocurrency_payment',
    'wire_transfer_service',
  ];
  if (paymentIds.some((id) => ids.has(id))) {
    recs.add(SAFETY_RECOMMENDATIONS.no_payment);
    recs.add(SAFETY_RECOMMENDATIONS.legal_action);
  }

  if (ids.has('sensitive_info_request')) {
    recs.add(SAFETY_RECOMMENDATIONS.verify_identity);
  }

  if (allSignals.length > 0) {
    recs.add(SAFETY_RECOMMENDATIONS.verify_company);
    recs.add(SAFETY_RECOMMENDATIONS.report_india);
    recs.add(SAFETY_RECOMMENDATIONS.report_url);
  }

  return Array.from(recs);
}

/**
 * Calculates the Scam Threat Index and returns the full result object.
 *
 * @param {Object} params
 * @param {Array<Object>}   params.textSignals       - Signals from textAnalyzer
 * @param {Array<Object>}   params.urlSignals        - Signals from urlAnalyzer
 * @param {Object|null}     params.domainInfo        - Result from domainChecker (inc. domain name)
 * @param {Object|null}     params.safeBrowsingResult - Result from safeBrowsing
 * @param {'text'|'url'}    params.mode
 * @returns {Object} Complete result payload for the API response
 */
function calculateScore({ textSignals = [], urlSignals = [], domainInfo = null, safeBrowsingResult = null, mode }) {
  // Start with signals already detected
  const allSignals = [...textSignals, ...urlSignals];

  // ── Domain-age signals ────────────────────────────────────────
  if (domainInfo && domainInfo.ageInDays !== null) {
    if (domainInfo.ageInDays < 30) {
      const sig = getUrlSignal('domain_age_new');
      allSignals.push({
        ...sig,
        evidence: `Domain registered ${domainInfo.ageInDays} day${domainInfo.ageInDays !== 1 ? 's' : ''} ago (${domainInfo.createdDate})`,
      });
    } else if (domainInfo.ageInDays < 90) {
      const sig = getUrlSignal('domain_age_recent');
      allSignals.push({
        ...sig,
        evidence: `Domain registered ${domainInfo.ageInDays} days ago (${domainInfo.createdDate})`,
      });
    }
    // ≥ 90 days → no penalty
  }

  // ── Safe Browsing signal ──────────────────────────────────────
  if (safeBrowsingResult && safeBrowsingResult.isMalicious) {
    const sig = getUrlSignal('safe_browsing_hit');
    allSignals.push({
      ...sig,
      evidence: `Threat type identified: ${safeBrowsingResult.threatLabel || safeBrowsingResult.threatType}`,
    });
  }

  // ── Compute final score ───────────────────────────────────────
  const rawScore = allSignals.reduce((sum, s) => sum + s.weight, 0);
  const score    = Math.min(100, rawScore);

  // ── Determine risk level ──────────────────────────────────────
  const riskLevel = RISK_LEVELS.find((r) => score <= r.max) ?? RISK_LEVELS[RISK_LEVELS.length - 1];

  // ── Build recommendations ─────────────────────────────────────
  const recommendations = buildRecommendations(allSignals, safeBrowsingResult);

  // ── Format signals for client (strip regex patterns) ─────────
  const formattedSignals = allSignals.map(({ id, label, weight, evidence, explanation }) => ({
    id,
    label,
    weight,
    evidence,
    explanation,
  }));

  // ── Format domain info for client ────────────────────────────
  let domainInfoForClient = null;
  if (domainInfo) {
    domainInfoForClient = {
      domain:         domainInfo.domain || null,
      ageInDays:      domainInfo.ageInDays,
      createdDate:    domainInfo.createdDate,
      registrar:      domainInfo.registrar,
      ageUnavailable: domainInfo.ageInDays === null,
      unavailableReason: domainInfo.ageInDays === null ? (domainInfo.error || 'Unknown') : null,
    };
  }

  return {
    score,
    riskLevel:       riskLevel.level,
    riskEmoji:       riskLevel.emoji,
    riskDescription: riskLevel.description,
    signals:         formattedSignals,
    signalCount:     formattedSignals.length,
    domainInfo:      domainInfoForClient,
    safeBrowsingChecked:     safeBrowsingResult !== null && !safeBrowsingResult.error,
    safeBrowsingUnavailable: safeBrowsingResult !== null && !!safeBrowsingResult.error,
    recommendations,
    disclaimer: 'Risk assessment based on detected signals. This tool does not guarantee that content is or is not a scam. Always independently verify through official channels.',
    methodology: `Scam Threat Index = sum of weights of all ${formattedSignals.length} detected signal(s), capped at 100%. Each signal is independently verifiable from the evidence shown.`,
  };
}

module.exports = { calculateScore };
