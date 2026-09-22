'use strict';

// ============================================================
// constants.js
// Central registry of all signal definitions, weights, and
// configuration values used by the Scam Threat Index engine.
// ============================================================

/**
 * Text signals — detected by pattern-matching against pasted text.
 * Each signal has:
 *   id          – unique identifier
 *   label       – human-readable name shown in results
 *   weight      – points this signal contributes to the STI (0–100 pool)
 *   patterns    – array of RegExp to match against the text
 *   explanation – plain-language reason shown to the user
 */
const TEXT_SIGNALS = [
  {
    id: 'explicit_payment_demand',
    label: 'Explicit Payment Demand',
    weight: 25,
    patterns: [
      /\bsend\s+(?:us\s+)?(?:money|cash|funds|payment|₹|rs\.?|inr|usd|\$|£|€)/i,
      /\bpay\s+(?:₹|rs\.?|inr|usd|\$|£|€|\d)/i,
      /\btransfer\s+(?:the\s+)?(?:amount|money|funds)/i,
      /\bpayment\s+(?:is\s+)?(?:required|needed|mandatory|compulsory)/i,
      /\bdeposit\s+(?:the\s+)?(?:amount|fee|money)\s+(?:to|into|at)\b/i,
    ],
    explanation:
      'Legitimate employers and landlords do not ask you to send money before confirming employment or a rental agreement.',
  },
  {
    id: 'fee_before_employment',
    label: 'Fee Required Before Employment or Tenancy',
    weight: 20,
    patterns: [
      /\b(?:joining|registration|processing|admin(?:istration)?|onboarding|placement|training)\s+fee/i,
      /\bfee\s+(?:to\s+)?(?:confirm|secure|activate|process|get|receive)\s+(?:your\s+)?(?:offer|appointment|placement|seat|job|position|letter)/i,
      /\b(?:pay|submit|deposit|send)\s+(?:a\s+)?(?:fee|amount|charge)\s+(?:before|prior\s+to)\s+(?:joining|starting|your\s+(?:first\s+day|start))/i,
    ],
    explanation:
      'Charging any fee before employment or tenancy is confirmed is a classic scam tactic. Genuine organisations never require this.',
  },
  {
    id: 'equipment_fee',
    label: 'Equipment or Uniform Purchase Demand',
    weight: 15,
    patterns: [
      /\b(?:purchase|buy|procure|order)\s+(?:your\s+own\s+)?(?:laptop|computer|equipment|tools|uniform|kit|starter\s+pack)/i,
      /\b(?:laptop|equipment|tools|uniform|device)\s+(?:deposit|fee|cost|charge|amount)/i,
      /\bwork(?:ing)?\s*(?:from\s+home\s+)?(?:kit|equipment|setup|starter)\s+(?:fee|cost|charge|deposit)/i,
    ],
    explanation:
      'Legitimate employers provide or reimburse equipment costs. Being asked to buy equipment or pay a deposit before starting is a major red flag.',
  },
  {
    id: 'security_deposit',
    label: 'Security Deposit or Advance Payment Trap',
    weight: 18,
    patterns: [
      /\bsecurity\s+deposit\s+(?:of\s+)?(?:₹|rs\.?|\$|£|€)?\s*[\d,]+/i,
      /\badvance\s+(?:rent|deposit|payment)\s+(?:of\s+)?(?:₹|rs\.?|\$|£|€)?\s*[\d,]+/i,
      /\b(?:pay|send|submit|transfer)\s+(?:a\s+)?(?:security|advance|initial|token)\s+(?:deposit|amount|sum)/i,
      /\btoken\s+(?:money|amount|advance)/i,
    ],
    explanation:
      'Rental scams frequently request advance deposits without providing a verifiable physical address or identity proof.',
  },
  {
    id: 'cryptocurrency_payment',
    label: 'Cryptocurrency Payment Request',
    weight: 22,
    patterns: [
      /\b(?:bitcoin|btc|ethereum|eth|usdt|tether|usdc|binance|crypto(?:currency)?|blockchain\s+wallet|nft)\b/i,
      /\bsend\s+(?:crypto|btc|eth|usdt|coins?)/i,
      /\bwallet\s+address/i,
    ],
    explanation:
      'Cryptocurrency payments are irreversible and untraceable. No legitimate employer or landlord requires payment in cryptocurrency.',
  },
  {
    id: 'wire_transfer_service',
    label: 'Informal Money Transfer Service',
    weight: 18,
    patterns: [
      /\b(?:western\s+union|moneygram|ria\s+money|world\s+remit)\b/i,
      /\btransfer\s+(?:via|through|using)\s+(?:wire|swift|iban|hawala)/i,
    ],
    explanation:
      'Requesting payment through informal or irreversible money-transfer services is a strong fraud indicator.',
  },
  {
    id: 'urgency_pressure',
    label: 'Urgency or Pressure Tactics',
    weight: 10,
    patterns: [
      /\bwithin\s+(?:24|48|72)\s+hours?\b/i,
      /\bimmediately|urgent(?:ly)?|asap\b|as\s+soon\s+as\s+possible/i,
      /\blimited\s+(?:time|seats?|positions?|spots?|vacancies)\s+(?:available|left|remaining|only)/i,
      /\boffer\s+(?:expires?|valid\s+only|closes?)\s+(?:today|tonight|this\s+week|soon)/i,
      /\bdo\s+not\s+(?:delay|miss\s+this|ignore|wait)/i,
      /\bfirst\s+(?:come|paid)\s+first\s+served/i,
      /\blast\s+(?:chance|opportunity|day|date)\b/i,
    ],
    explanation:
      'Creating artificial urgency is a manipulation tactic used to prevent you from taking time to verify the opportunity.',
  },
  {
    id: 'sensitive_info_request',
    label: 'Sensitive Personal or Financial Information Request',
    weight: 10,
    patterns: [
      /\b(?:bank\s+account(?:\s+number)?|account\s+number|ifsc\s+code|routing\s+number|sort\s+code)\b/i,
      /\b(?:social\s+security\s+(?:number|card)|ssn|aadhaar(?:\s+(?:number|card))?|pan\s+(?:card|number)|passport\s+(?:number|copy|scan|photo))\b/i,
      /\b(?:otp|one[\s-]time\s+(?:password|pin)|verification\s+code)\s+(?:share|send|provide|give|forward)\b/i,
      /\bcvv|credit\s+card\s+(?:number|details|info)|debit\s+card\s+(?:number|details|pin)\b/i,
    ],
    explanation:
      'Requesting bank credentials, national ID numbers, or OTPs before confirming employment or tenancy is a phishing red flag.',
  },
  {
    id: 'too_good_to_be_true',
    label: 'Unrealistic Earnings or Salary Claim',
    weight: 8,
    patterns: [
      /earn\s+(?:₹|rs\.?|\$|£|€)?\s*[\d,]+\s*(?:per\s+(?:day|week|hour)|daily|weekly|hourly)/i,
      /\b(?:₹|rs\.?|\$)[\d,.]+\s*(?:lakh|lac|k)?\s*(?:per\s+month|\/month|p\.?m\.?)\s+(?:from\s+home|work(?:ing)?\s+from\s+home|part[-\s]time|online)/i,
      /\bno\s+(?:experience|qualifications?|skills?|education)\s+(?:required|needed|necessary)\b/i,
      /\beasy\s+(?:money|income|earnings|job|work)\s+(?:from\s+home|online|guaranteed)/i,
    ],
    explanation:
      'Offers promising very high pay for minimal work or no qualifications are hallmarks of job scams.',
  },
  {
    id: 'reimbursement_promise',
    label: 'Vague Reimbursement or Refund Promise',
    weight: 8,
    patterns: [
      /\b(?:will\s+be\s+(?:reimbursed|refunded|returned|credited|repaid)|we\s+will\s+reimburse|amount\s+will\s+be\s+returned)\s+(?:after|once|when|upon)\b/i,
      /\b(?:fully\s+)?(?:refundable|reimbursable)\s+(?:deposit|amount|fee|charge)\s+(?:after|upon|once|when)\b/i,
    ],
    explanation:
      'Promises to refund fees "after joining" are rarely honoured in scam scenarios and are designed to lower your guard.',
  },
  {
    id: 'suspicious_url_in_text',
    label: 'Suspicious Link Embedded in Text',
    weight: 10,
    patterns: [
      /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/\S*)?/i,
      /(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|tiny\.cc|is\.gd|buff\.ly|rebrand\.ly|rb\.gy|cutt\.ly|shorturl\.at|bit\.do|clck\.ru)\/\S+/i,
    ],
    explanation:
      'IP-address-based URLs or link shorteners in offer letters hide the true destination and are frequently used in phishing.',
  },
  {
    id: 'spam_formatting',
    label: 'Spam-Style Formatting',
    weight: 5,
    patterns: [], // Handled via custom logic in textAnalyzer.js
    explanation:
      'Excessive use of capital letters or exclamation marks is characteristic of low-quality scam and spam messages.',
  },
];

/**
 * URL signals — detected by analysing the structure of a URL.
 * Domain-age signals are added dynamically by scoreCalculator.js
 * after the WHOIS lookup result is known.
 */
const URL_SIGNALS = [
  {
    id: 'insecure_protocol',
    label: 'Insecure HTTP Protocol',
    weight: 8,
    explanation:
      'The URL uses HTTP instead of HTTPS. Legitimate job portals and rental platforms always encrypt traffic with HTTPS.',
  },
  {
    id: 'ip_based_url',
    label: 'IP Address Used Instead of Domain Name',
    weight: 20,
    explanation:
      'The URL uses a raw IP address instead of a domain name. Legitimate websites use registered domain names, not numeric IPs.',
  },
  {
    id: 'url_shortener',
    label: 'URL Shortener Detected',
    weight: 15,
    explanation:
      'The URL passes through a link-shortening service, hiding the real destination. Legitimate recruitment or rental sites use their own domain.',
  },
  {
    id: 'suspicious_tld',
    label: 'High-Risk Top-Level Domain',
    weight: 10,
    explanation:
      'The domain uses a TLD that is commonly associated with free-domain abuse and phishing campaigns.',
  },
  {
    id: 'lookalike_domain',
    label: 'Possible Brand Impersonation',
    weight: 15,
    explanation:
      'The domain name closely resembles a well-known brand but contains subtle differences — a classic impersonation tactic.',
  },
  {
    id: 'excessive_subdomains',
    label: 'Excessive Number of Subdomains',
    weight: 8,
    explanation:
      'The URL contains an unusually high number of subdomains, which attackers use to make malicious URLs look like legitimate ones.',
  },
  {
    id: 'numeric_subdomain',
    label: 'Numeric or Obfuscated Subdomain',
    weight: 8,
    explanation:
      'The URL contains numbers in its subdomain, which is unusual for legitimate business websites and may indicate obfuscation.',
  },
  {
    id: 'long_url',
    label: 'Excessively Long URL',
    weight: 5,
    explanation:
      'The URL is unusually long. Attackers use long URLs to obscure the true domain or include malicious tracking parameters.',
  },
  // Domain-age signals are referenced by scoreCalculator.js
  {
    id: 'domain_age_new',
    label: 'Very Recently Registered Domain (< 30 days)',
    weight: 20,
    explanation:
      'The domain was registered very recently. Scammers frequently create new domains for short-lived phishing campaigns.',
  },
  {
    id: 'domain_age_recent',
    label: 'Recently Registered Domain (30–90 days)',
    weight: 10,
    explanation:
      'The domain was registered within the last 3 months. This is a moderate risk indicator when combined with other signals.',
  },
  {
    id: 'safe_browsing_hit',
    label: 'Known Malicious URL (Google Safe Browsing)',
    weight: 40,
    explanation:
      'Google Safe Browsing has flagged this URL as a known phishing, malware, or unwanted software site. Do not visit it.',
  },
];

/**
 * Risk level bands for the Scam Threat Index.
 * Checked in order; first match wins (score <= max).
 */
const RISK_LEVELS = [
  {
    max: 20,
    level: 'Low',
    emoji: '🟢',
    description: 'Few or no risk signals detected. Exercise normal caution when proceeding.',
  },
  {
    max: 40,
    level: 'Moderate',
    emoji: '🟡',
    description: 'Some risk signals detected. Independently verify this opportunity before proceeding.',
  },
  {
    max: 65,
    level: 'High',
    emoji: '🟠',
    description: 'Multiple risk signals detected. Exercise significant caution and verify all claims independently.',
  },
  {
    max: 100,
    level: 'Critical',
    emoji: '🔴',
    description: 'Strong scam indicators detected. Do not send money or share personal documents without thorough independent verification.',
  },
];

/** Safety recommendation strings referenced by scoreCalculator.js */
const SAFETY_RECOMMENDATIONS = {
  no_payment: 'Do not send any money, deposits, or fees before physically meeting the employer or landlord and signing a verified contract.',
  legal_action: 'If you have already transferred money, contact your bank immediately to attempt a recall, then file a police complaint.',
  verify_identity: 'Do not share bank account details, national ID numbers (Aadhaar, PAN), OTPs, or copies of identity documents until you have independently verified the legitimacy of the opportunity.',
  verify_company: 'Verify the company or individual through official government business registries, LinkedIn, or by calling a number you look up independently (not one provided in the message).',
  report_india: 'Report suspected scams to the National Cybercrime Reporting Portal: cybercrime.gov.in or call the helpline 1930.',
  report_url: 'Report suspected phishing URLs to Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish/',
  safe_browsing_hit: 'This URL has been flagged as a known threat by Google Safe Browsing. Do not visit this link.',
};

/** Known URL-shortening service domains */
const KNOWN_URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'tiny.cc',
  'is.gd', 'buff.ly', 'rebrand.ly', 'rb.gy', 'cutt.ly', 'shorturl.at',
  'bit.do', 'clck.ru', 'snip.ly', 'mcaf.ee', 'yourls.org', 'adf.ly',
]);

/** TLDs commonly abused for phishing and free-domain scams */
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'club', 'online',
  'site', 'click', 'link', 'work', 'loan', 'win', 'racing', 'party',
  'review', 'science', 'trade', 'webcam', 'pw', 'cc',
]);

/**
 * Well-known brand names used for lookalike domain detection.
 * Levenshtein distance of 1–2 from any of these triggers a flag.
 */
const KNOWN_BRANDS = [
  'google', 'facebook', 'amazon', 'microsoft', 'apple', 'linkedin',
  'instagram', 'twitter', 'paypal', 'netflix', 'youtube', 'whatsapp',
  'gmail', 'outlook', 'yahoo', 'indeed', 'naukri', 'flipkart',
  'infosys', 'wipro', 'tcs', 'accenture', 'hdfc', 'sbi', 'icici',
  'axis', 'kotak', 'zomato', 'swiggy', 'uber', 'ola',
];

/** Input size limits (enforced server-side) */
const INPUT_LIMITS = {
  maxTextLength: 10000,
  maxUrlLength: 2048,
};

module.exports = {
  TEXT_SIGNALS,
  URL_SIGNALS,
  RISK_LEVELS,
  SAFETY_RECOMMENDATIONS,
  KNOWN_URL_SHORTENERS,
  SUSPICIOUS_TLDS,
  KNOWN_BRANDS,
  INPUT_LIMITS,
};
