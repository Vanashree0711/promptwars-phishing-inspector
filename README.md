# 🛡️ Fake Offer Letter & Phishing Inspector

A single-page security scanner that analyses suspicious job offer letters, appointment letters, rental/deposit messages, and URLs for scam and phishing indicators — producing an explainable **Scam Threat Index (STI)** score from 0–100%.

Built for the **PromptWars Hackathon** · Uses **Google Safe Browsing API** · Deployable on **Google Cloud Run**

---

## 1. Problem Statement

Job seekers and renters lose money to fake appointment letters, pay-for-equipment phishing, and deposit traps that bypass standard email spam filters. These targeted scams mimic legitimate HR and landlord communications well enough to evade conventional spam detection.

---

## 2. Problem Explanation

Standard email filters catch mass spam but miss *personalised*, *conversational* phishing messages that:

- Impersonate legitimate employers or property managers
- Request registration fees, equipment deposits, or advance rent before confirming a job/rental
- Use urgency tactics to prevent the victim from verifying the offer
- Use newly registered domains or obfuscated URLs that look credible at first glance

Victims lose money that is often irreversible (wire transfers, cryptocurrency, informal payment services).

---

## 3. Solution

The Phishing Inspector provides:

- **Text analysis** — paste any suspicious message; the engine detects payment demands, fee traps, urgency language, sensitive-information requests, and more
- **URL analysis** — enter any URL; the engine checks domain age, structural risk signals, and queries Google Safe Browsing
- **Scam Threat Index** — a 0–100% score derived from a transparent, documented weighted formula
- **Full explainability** — every detected signal shows the quoted evidence from your input and a plain-language explanation of why it is suspicious
- **Safety recommendations** — actionable next steps tailored to the detected signals

---

## 4. Key Features

| Feature | Description |
|---|---|
| Text analysis | 12 signal categories with regex pattern matching and evidence extraction |
| URL analysis | 8 structural signal checks (IP URLs, shorteners, suspicious TLDs, lookalike domains, excessive subdomains, etc.) |
| Domain age | Server-side WHOIS lookup with graceful degradation if unavailable |
| Google Safe Browsing | Checks URL against Google's threat database (phishing, malware, social engineering) |
| Scam Threat Index | Weighted additive formula — fully deterministic, every point is explainable |
| Risk levels | Low / Moderate / High / Critical with colour-coded SVG gauge |
| Safety recommendations | Context-aware action steps based on detected signal categories |
| Accessibility | WCAG 2.1 AA — semantic HTML, ARIA, keyboard navigation, visible focus states |
| Mobile responsive | Works on all screen sizes from 360px up |
| Security | Helmet.js, rate limiting, body-size limits, no SSRF, no secrets in frontend |

---

## 5. User Workflow

```
1. Open the application
2. Choose "Analyse Text" or "Analyse URL"
3. Paste your suspicious message OR enter the URL
4. Click "Scan Now"
5. View the Scam Threat Index (0–100%)
6. Read detected risk indicators with quoted evidence
7. View domain information (URL mode)
8. Follow the safety recommendations
```

---

## 6. Architecture

```
┌─────────────────────────────────────┐
│  Browser (Single Page)              │
│  index.html + style.css + app.js    │
└─────────────┬───────────────────────┘
              │ POST /api/analyze (JSON)
              ▼
┌─────────────────────────────────────┐
│  Node.js + Express                  │
│  server.js (helmet, rate limit)     │
│  routes/analyze.js                  │
│                                     │
│  services/                          │
│    textAnalyzer.js   ─ text signals │
│    urlAnalyzer.js    ─ URL signals  │
│    domainChecker.js  ─ WHOIS        │
│    safeBrowsing.js   ─ Google API   │
│    scoreCalculator.js ─ STI formula │
│                                     │
│  utils/                             │
│    inputValidator.js                │
│    errorHandler.js                  │
│    constants.js                     │
└──────────────┬──────────────────────┘
               │
     ┌─────────┴──────────┐
     ▼                    ▼
Google Safe Browsing   WHOIS lookup
     API               (whoiser npm)
```

**Key design decisions:**
- Analysis is **100% server-side** — frontend only sends input and renders results
- Server **never fetches user-supplied URLs** — only parses structure (eliminates SSRF)
- All external API failures are handled gracefully without crashing or penalising the score

---

## 7. Technology Stack

| Layer | Technology | Reason |
|---|---|---|
| Frontend | HTML5, CSS3, Vanilla JS (ES6+) | No framework needed; easy to audit; fast |
| Backend | Node.js 18+ + Express 4 | Lightweight; suitable for API + static serving |
| Security headers | Helmet.js | CSP, HSTS, X-Frame-Options, etc. |
| Rate limiting | express-rate-limit | Protects against API abuse |
| Domain age | whoiser (npm) | Structured WHOIS data; no third-party API key required |
| Safe Browsing | Google Safe Browsing API v4 | Authoritative threat intelligence |
| Deployment | Google Cloud Run | Serverless containers; auto-HTTPS; zero infrastructure |
| Secrets | dotenv | Standard environment variable management |

---

## 8. Google Products/Services Used

### Google Safe Browsing API v4
- **What it does**: Checks URLs against Google's continuously updated database of phishing, malware, and social engineering sites
- **Why it improves the project**: Provides authoritative, real-world threat intelligence that rule-based heuristics cannot replicate; a URL matching Google's database immediately flags a Critical-level signal
- **How it is used**: When a user submits a URL, the server makes a POST request to `safebrowsing.googleapis.com/v4/threatMatches:find` with the URL; results are incorporated into the STI calculation
- **Credentials**: API key stored in `.env`; never exposed to client, never logged

### Google Cloud Run (Deployment)
- **What it does**: Fully managed serverless container platform; runs the Express app as a Docker container with auto-HTTPS, auto-scaling, and zero infrastructure management
- **Why it improves the project**: Production-grade deployment with minimal operational overhead; appropriate for a stateless Node.js API
- **How it is used**: The included Dockerfile packages the application; deployment is a single `gcloud run deploy` command

### Google Fonts (Inter typeface)
- **What it does**: Provides the Inter typeface
- **Why it improves the project**: Professional, high-readability typography appropriate for a security tool; WCAG-friendly
- **How it is used**: Loaded via `<link>` in the HTML `<head>`

---

## 9. Scam Threat Index Methodology

**Formula**: `STI = min(100, Σ weight_i)` for each detected signal *i*

The score is fully deterministic: same input → same score, every time. Every point is traceable to a specific detected signal.

### Text Signal Weights

| Signal | Max Points | Rationale |
|---|---|---|
| Explicit payment demand | 25 | Strongest single scam indicator |
| Cryptocurrency payment request | 22 | Irreversible and untraceable — always fraud indicator |
| Fee before employment/rental | 20 | Defines the scam category |
| Wire transfer / money service | 18 | Informal irreversible payment |
| Security deposit trap | 18 | Rental scam hallmark |
| Equipment purchase demand | 15 | Classic job-scam variant |
| Urgency / pressure tactics | 10 | Psychological manipulation |
| Sensitive information request | 10 | Identity theft risk |
| Suspicious URL in text | 10 | IP URL or shortener |
| Vague reimbursement promise | 8 | Lowers guard while extracting money |
| Unrealistic salary claim | 8 | Too-good-to-be-true signal |
| Spam-style formatting | 5 | Low-quality communication indicator |

### URL Signal Weights

| Signal | Max Points | Rationale |
|---|---|---|
| Google Safe Browsing hit | 40 | Known malicious URL |
| Domain < 30 days old | 20 | Fresh domain for phishing campaign |
| IP-based URL | 20 | No legitimate business uses raw IP |
| Lookalike domain | 15 | Brand impersonation |
| URL shortener | 15 | Hides real destination |
| Domain 30–90 days old | 10 | Recent registration — moderate risk |
| Suspicious TLD (.xyz, .tk, etc.) | 10 | Free/abused TLDs |
| Insecure HTTP | 8 | No encryption |
| Excessive subdomains | 8 | Obfuscation |
| Numeric subdomain | 8 | Unusual for legitimate sites |
| Long URL (> 150 chars) | 5 | Obfuscation |

### Risk Levels

| Score | Level | Meaning |
|---|---|---|
| 0–20% | 🟢 Low | Few or no signals; exercise normal caution |
| 21–40% | 🟡 Moderate | Some signals; verify before proceeding |
| 41–65% | 🟠 High | Multiple signals; significant caution required |
| 66–100% | 🔴 Critical | Strong indicators; do not proceed without verification |

---

## 10. Security Measures

| Threat | Mitigation |
|---|---|
| XSS | All user-derived content inserted via `textContent` (never `innerHTML`); CSP header via Helmet |
| SSRF | Server never fetches user-supplied URLs; only parses structure |
| Injection | Input passed through validator; regex matches on sanitised strings only |
| Secret exposure | API key in `.env`; `.env` in `.gitignore`; no secrets in frontend bundle |
| API abuse | `express-rate-limit`: 30 requests/minute per IP on all `/api/` routes |
| Error leakage | Generic messages to client; full details logged server-side only |
| Oversized input | Body parser limited to 50 KB; text truncated at 10,000 characters server-side |
| Security headers | Helmet.js: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Non-root container | Docker runs as a non-root user (`nodeuser`) |

---

## 11. Accessibility

- **Semantic HTML**: `<main>`, `<header>`, `<footer>`, `<section>`, `<article>`, `<aside>`, `<form>`, `<label>`
- **ARIA roles**: `role="tablist"`, `role="tab"`, `role="tabpanel"`, `role="alert"`, `role="note"`, `aria-live="polite"`, `aria-live="assertive"`, `aria-selected`, `aria-controls`, `aria-hidden`
- **Keyboard navigation**: All interactive elements reachable via Tab; arrow keys navigate tabs (ARIA tabs pattern)
- **Focus management**: Results section receives focus after scan completes; Scan Again returns focus to input
- **Skip link**: "Skip to main content" for keyboard/screen reader users
- **Colour contrast**: All text meets WCAG AA 4.5:1 minimum
- **Not colour-only**: Risk levels shown with emoji + text label + colour
- **Touch targets**: Minimum 40px height on all interactive elements
- **Accessible errors**: Error messages use `role="alert"` and `aria-live="assertive"`

---

## 12. Setup Instructions

### Prerequisites

- Node.js 18 or higher (`node --version`)
- Git
- (Optional) Google Cloud account for Safe Browsing API key

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/phishing-inspector.git
cd phishing-inspector

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env and add your GOOGLE_SAFE_BROWSING_API_KEY (optional but recommended)
```

---

## 13. Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | Google Safe Browsing API v4 key. Without it, Safe Browsing checks are skipped (graceful degradation). |
| `PORT` | Optional | Server port (default: `3000`) |
| `NODE_ENV` | Optional | `development` or `production` (default: `development`) |

**To obtain a Safe Browsing API key:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Enable the **Safe Browsing API**
4. Create an API key under **Credentials**
5. Add it to your `.env` file

---

## 14. Local Development

```bash
# Start the development server
npm start
# or with auto-restart on file changes (Node 18+):
npm run dev

# Server runs at http://localhost:3000
# Health check: http://localhost:3000/api/health
```

---

## 15. Testing

Run through these test cases manually to verify all functionality:

| # | Input | Expected Result |
|---|---|---|
| 1 | Empty textarea + Scan | Validation error; no API call made |
| 2 | Normal job description (no red flags) | STI: Low; no signals detected |
| 3 | "Pay ₹2,000 registration fee to confirm your offer immediately" | Payment + urgency signals; STI: Critical |
| 4 | "Purchase your own laptop before joining, cost ₹15,000" | Equipment fee signal |
| 5 | "Send ₹5,000 refundable security deposit to confirm" | Security deposit signal |
| 6 | "Respond within 24 hours or lose this opportunity!!!" | Urgency + spam formatting signals |
| 7 | "Send payment in Bitcoin to wallet address 1A2B3C…" | Cryptocurrency signal |
| 8 | `https://google.com` | Low STI; Clean Safe Browsing; domain age shown |
| 9 | `https://bit.ly/fakejoboffer` | URL shortener signal |
| 10 | `http://192.168.1.1/jobs` | IP URL + HTTP signals |
| 11 | `https://g00gle-jobs.xyz` | Lookalike + suspicious TLD signals |
| 12 | `not a url at all` | Validation error: "Please enter a valid URL" |
| 13 | 12,000-character text | Truncation notice; analysis completes |
| 14 | `<script>alert(1)</script>` in text | Rendered as plain text; no execution |
| 15 | GOOGLE_SAFE_BROWSING_API_KEY absent | "Safe Browsing check not configured" message |
| 16 | Mobile viewport (375px) | Layout correct; all features usable |
| 17 | Keyboard-only navigation | Full app operable via Tab + Enter |

---

## 16. Deployment

### Google Cloud Run (Recommended)

```bash
# 1. Authenticate with Google Cloud
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# 2. Enable required APIs
gcloud services enable run.googleapis.com artifactregistry.googleapis.com

# 3. Build and push Docker image
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/phishing-inspector

# 4. Deploy to Cloud Run
gcloud run deploy phishing-inspector \
  --image gcr.io/YOUR_PROJECT_ID/phishing-inspector \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "GOOGLE_SAFE_BROWSING_API_KEY=YOUR_KEY_HERE,NODE_ENV=production"

# 5. Get the deployment URL
gcloud run services describe phishing-inspector --region us-central1 --format "value(status.url)"
```

### Alternative: Docker locally

```bash
docker build -t phishing-inspector .
docker run -p 3000:8080 \
  -e GOOGLE_SAFE_BROWSING_API_KEY=your_key \
  -e NODE_ENV=production \
  phishing-inspector
```

---

## 17. Limitations

| Limitation | Notes |
|---|---|
| Heuristic-only text analysis | The engine uses documented patterns; a sufficiently sophisticated scam that avoids all trigger phrases may receive a lower score than warranted |
| WHOIS data availability | Some domains use privacy protection or non-standard WHOIS formats; age information may be unavailable in those cases |
| Safe Browsing quota | Google Safe Browsing API has a free usage quota; very high traffic may exhaust it, triggering graceful degradation |
| URL shorteners | The tool identifies shortener domains but cannot safely follow and check the destination (anti-SSRF design decision) |
| Language | Pattern matching is primarily tuned for English and some Indian-language numeric formatting |
| Not a guarantee | A Low score does not certify that content is legitimate; always verify through official channels |

---

## 18. Responsible Use Disclaimer

This tool is designed to **assist** users in identifying common scam patterns. It is **not a guarantee** that any content is fraudulent or legitimate.

- Results are a risk assessment based on detected signals, not a legal or criminal determination
- A high score does not prove fraud; a low score does not prove legitimacy
- Always verify opportunities through official government business registries, official company websites, and trusted contacts
- Report suspected fraud to:
  - **India**: National Cybercrime Reporting Portal — [cybercrime.gov.in](https://cybercrime.gov.in) / Helpline 1930
  - **Google Safe Browsing report**: [safebrowsing.google.com/safebrowsing/report_phish/](https://safebrowsing.google.com/safebrowsing/report_phish/)

This tool does not store, log, or transmit any text or URLs you submit for analysis.
