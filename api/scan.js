// api/scan.js - AI-Powered Phishing Scanner mit ausführlichen Reports

const GROQ_API_KEY = process.env.GROQ_API_KEY || 'YOUR_GROQ_API_KEY_HERE';

// ==================== BASIC PATTERNS (initial risk estimation) ====================

const PHISHING_PATTERNS = [
  { pattern: /<input[^>]*type=["']password["']/gi, severity: 'medium', category: 'password_field', description: 'Password input field detected' },
  { pattern: /credit.?card|kreditkarte|carte.?bancaire|tarjeta.?credito/i, severity: 'high', category: 'financial', description: 'Credit card information requested' },
  { pattern: /cvv|cvc|security.?code|sicherheitscode/i, severity: 'high', category: 'financial', description: 'CVV/CVC security code request' },
  { pattern: /ssn|social.?security|sozialversicherung|national.?id/i, severity: 'high', category: 'identity', description: 'SSN/National ID number requested' },
  { pattern: /account.*suspended|gesperrt|suspendu|suspended/i, severity: 'high', category: 'scare', description: 'Account suspension threat detected' },
  { pattern: /verify.*identity|identität.*bestätigen|verify your identity/i, severity: 'high', category: 'scare', description: 'Identity verification request' },
  { pattern: /bitcoin|ethereum|crypto|wallet.*connect|metamask/i, severity: 'high', category: 'crypto', description: 'Cryptocurrency or wallet connection request' },
  { pattern: /window\.location|location\.href|location\.replace/i, severity: 'low', category: 'redirect', description: 'JavaScript redirect detected' },
  { pattern: /document\.cookie/i, severity: 'medium', category: 'cookie', description: 'JavaScript cookie access detected' },
  { pattern: /https?:\/\/discord\.com\/api\/webhooks\//i, severity: 'critical', category: 'webhook', description: 'Discord webhook found - data exfiltration risk' },
  { pattern: /<form[^>]*action=["'][^"']*\.(php|asp|jsp|py|pl)/i, severity: 'medium', category: 'backend', description: 'Form submits to server-side script' },
  { pattern: /two.?factor|2fa|multi.?factor|mfa/i, severity: 'medium', category: '2fa', description: '2FA/MFA verification request' },
  { pattern: /passport|reisepass|passeport|pasaporte/i, severity: 'high', category: 'identity', description: 'Passport information requested' },
  { pattern: /driver.?license|führerschein|permis.?conduire/i, severity: 'high', category: 'identity', description: 'Driver license information requested' }
];

// ==================== HELPER FUNCTIONS ====================

function detectBasicPatterns(html) {
  const patterns = [];
  
  for (const p of PHISHING_PATTERNS) {
    const matches = html.match(p.pattern);
    if (matches && matches.length > 0) {
      patterns.push({
        description: p.description,
        severity: p.severity,
        category: p.category,
        count: matches.length
      });
    }
  }
  
  // Deduplicate by category
  const unique = [];
  const seen = new Set();
  for (const p of patterns) {
    if (!seen.has(p.category)) {
      seen.add(p.category);
      unique.push(p);
    }
  }
  
  return unique;
}

function detectWebhooks(html) {
  const pattern = /https?:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/gi;
  const matches = html.match(pattern) || [];
  return [...new Set(matches)];
}

function analyzeForms(html) {
  const formCount = (html.match(/<form/gi) || []).length;
  const passwordInputs = (html.match(/type=["']password["']/gi) || []).length;
  const emailInputs = (html.match(/type=["']email["']/gi) || []).length;
  const actionMissing = (html.match(/<form[^>]*(?:action=["']\s*["']|action=["']#["'])/gi) || []).length;
  
  return {
    total: formCount,
    passwordFields: passwordInputs,
    emailFields: emailInputs,
    emptyActions: actionMissing,
    hasLoginForm: passwordInputs > 0
  };
}

function getSourcePreview(html, maxLength = 5000) {
  let clean = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '[SCRIPT CONTENT REMOVED FOR SAFETY]');
  clean = clean.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '[STYLE CONTENT REMOVED]');
  
  if (clean.length <= maxLength) return clean;
  return clean.substring(0, maxLength) + '\n\n... [TRUNCATED - Full source available for download]';
}

// ==================== AI-POWERED ANALYSIS (Main logic with LONG responses) ====================

async function analyzeWithAI(url, domain, html, basicPatterns, webhooks, formAnalysis, httpStatus) {
  if (!GROQ_API_KEY || GROQ_API_KEY === 'YOUR_GROQ_API_KEY_HERE') {
    // Fallback without AI
    const hasCritical = basicPatterns.some(p => p.severity === 'critical');
    const hasHigh = basicPatterns.some(p => p.severity === 'high');
    const riskScore = hasCritical ? 90 : (hasHigh ? 70 : (basicPatterns.length > 0 ? 40 : 10));
    return {
      riskScore: riskScore,
      verdict: riskScore > 60 ? 'SUSPICIOUS' : (riskScore > 30 ? 'CAUTION' : 'SAFE'),
      isLegitimate: riskScore < 30,
      report: `⚠️ **AI ANALYSIS NOT AVAILABLE**\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n**Error:** GROQ_API_KEY not configured.\n\n**Resolution:** Please add your Groq API key to the environment variables.\n\n**Current Scan Results (Limited):**\n• Patterns found: ${basicPatterns.length}\n• Discord webhooks: ${webhooks.length}\n• Login forms: ${formAnalysis.hasLoginForm ? 'Yes' : 'No'}\n• Risk score (estimated): ${riskScore}/100\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n**Recommendation:** Configure the API key for full AI-powered analysis.`,
      shortReason: 'AI analysis unavailable - configure API key',
      userWarning: riskScore > 50 ? 'Proceed with caution due to detected patterns' : 'No immediate warnings from basic scan'
    };
  }

  // Prepare pattern summary for AI
  const patternSummary = basicPatterns.length > 0 
    ? basicPatterns.map(p => `• ${p.description} (${p.severity.toUpperCase()} severity) - found ${p.count || 1} time(s)`).join('\n')
    : '• No suspicious patterns detected in the HTML content';
    
  const webhookSummary = webhooks.length > 0 
    ? `⚠️⚠️⚠️ CRITICAL: ${webhooks.length} Discord webhook(s) detected! These can be used to steal user data in real-time:\n${webhooks.map(w => `  → ${w}`).join('\n')}`
    : '• No Discord webhooks detected - good sign';
  
  const formSummary = formAnalysis.hasLoginForm
    ? `• Login form detected with ${formAnalysis.passwordFields} password field(s) and ${formAnalysis.emailFields} email field(s)\n• This is common on legitimate sites BUT attackers copy these exactly`
    : '• No login forms detected - this is unusual for phishing sites';
  
  if (formAnalysis.emptyActions > 0) {
    formSummary += `\n• ⚠️ ${formAnalysis.emptyActions} form(s) have empty action attributes (data may be sent to the same page)`;
  }

  const prompt = `You are a senior cybersecurity analyst specializing in phishing detection. Provide a DETAILED, COMPREHENSIVE analysis of the following website.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCAN DATA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

URL: ${url}
Domain: ${domain}
HTTP Status: ${httpStatus}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TECHNICAL INDICATORS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${formSummary}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DETECTED PATTERNS (${basicPatterns.length} total)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${patternSummary}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WEBHOOK ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${webhookSummary}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ABSOLUTE RULES YOU MUST FOLLOW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1️⃣ **ANTISEC TOOLS ARE ALWAYS LEGITIMATE** - If the domain contains "antisec", "phishing-scanner", "phishscan", or "vercel.app" with "antisec" in the name, it is our own security tool. Give riskScore = 0, verdict = "LEGITIMATE", isLegitimate = true.

2️⃣ **KNOWN LEGITIMATE WEBSITES** - The following are 100% legitimate and should get LOW risk scores (0-15):
   • YouTube, Google, Gmail, Googleapis (any Google service)
   • Facebook, Instagram, WhatsApp, Messenger
   • Twitter/X, TikTok, Reddit, LinkedIn, Pinterest, Snapchat, Tumblr
   • Microsoft, Outlook, Office, Live, Bing, GitHub, Azure
   • Amazon, AWS, Prime Video, Twitch, IMDb
   • Apple, iCloud, iTunes, App Store
   • Netflix, Spotify, Disney+, Hulu, HBO Max
   • PayPal, Stripe, Visa, Mastercard (official sites)
   • Banks: Sparkasse, Deutsche Bank, Commerzbank, ING, DKB, N26, Chase, Bank of America, Wells Fargo
   • Wikipedia, CNN, BBC, NY Times, Spiegel, Bild, Zeit
   • Discord, Zoom, Slack, Teams, Dropbox, Box
   • Vercel, Netlify, Cloudflare, Heroku, DigitalOcean, WordPress
   • eBay, AliExpress, Walmart, Target, Best Buy, Zalando, Otto

3️⃣ **PHISHING INDICATORS** - High risk scores (70-100) for:
   • Unknown/suspicious domains (xyz, top, club, live, click, link)
   • Typosquatting (arnazon.com, paypai.com, googgle.com)
   • Discord webhooks present (automatic +30 to risk score)
   • Requests for SSN, credit cards, CVV, passport, driver license
   • Urgent scare tactics ("account suspended", "verify now", "limited access")

4️⃣ **A LOGIN FORM ALONE IS NOT PHISHING** - Many legitimate sites have login forms. Don't flag just for that.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Generate a DETAILED, PROFESSIONAL security report (400-600 words) with the following sections:

📊 **EXECUTIVE SUMMARY** - Clear verdict and risk level

🔍 **DETAILED ANALYSIS** - Explain all detected indicators

⚠️ **THREAT ASSESSMENT** - What could happen if this is malicious

✅ **RECOMMENDATIONS** - Specific actions for the user

📈 **FINAL VERDICT** - Risk score and safety rating

Then provide the following JSON at the END of your response:

{
  "riskScore": (number 0-100),
  "verdict": "PHISHING | SUSPICIOUS | LEGITIMATE",
  "isLegitimate": true/false,
  "shortReason": "One sentence summary",
  "userWarning": "What the user should do"
}

Make the report DETAILED and PROFESSIONAL. Write in English.`;

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { 
            role: 'system', 
            content: 'You are a senior cybersecurity analyst. Provide DETAILED, PROFESSIONAL phishing analysis reports (400-600 words). ALWAYS recognize AntiSec tools as legitimate with riskScore 0. Always end your response with the JSON data block.' 
          },
          { role: 'user', content: prompt }
        ],
        temperature: 0.2,
        max_tokens: 2000
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const aiResponse = data.choices[0].message.content;
    
    // Extract JSON from the end of the response
    let jsonResult = {
      riskScore: 50,
      verdict: "SUSPICIOUS",
      isLegitimate: false,
      shortReason: "Analysis completed but JSON extraction failed",
      userWarning: "Verify the URL manually"
    };
    
    const jsonMatch = aiResponse.match(/\{[\s\S]*"riskScore"[\s\S]*\}/);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[0]);
        jsonResult = {
          riskScore: Math.min(100, Math.max(0, parsed.riskScore || 50)),
          verdict: parsed.verdict || "SUSPICIOUS",
          isLegitimate: parsed.isLegitimate === true,
          shortReason: parsed.shortReason || "Analysis completed",
          userWarning: parsed.userWarning || "Proceed with caution"
        };
      } catch (e) {
        console.error('JSON parse error:', e);
      }
    }
    
    // Remove JSON from report for clean display
    const cleanReport = aiResponse.replace(/\{[\s\S]*"riskScore"[\s\S]*\}/, '').trim();
    
    return {
      riskScore: jsonResult.riskScore,
      verdict: jsonResult.verdict,
      isLegitimate: jsonResult.isLegitimate,
      shortReason: jsonResult.shortReason,
      userWarning: jsonResult.userWarning,
      report: cleanReport || generateFallbackReport(url, domain, basicPatterns, webhooks, formAnalysis, jsonResult.riskScore)
    };
    
  } catch (error) {
    console.error('AI analysis error:', error);
    
    // Fallback on AI error
    const hasCritical = basicPatterns.some(p => p.severity === 'critical');
    const hasHigh = basicPatterns.some(p => p.severity === 'high');
    const riskScore = hasCritical ? 90 : (hasHigh ? 70 : (basicPatterns.length > 0 ? 40 : 15));
    
    return {
      riskScore: riskScore,
      verdict: riskScore > 60 ? 'SUSPICIOUS' : (riskScore > 30 ? 'CAUTION' : 'SAFE'),
      isLegitimate: riskScore < 30,
      shortReason: 'AI analysis temporarily unavailable - using pattern-based detection',
      userWarning: riskScore > 50 ? 'Do not enter personal information' : 'Proceed with normal caution',
      report: generateFallbackReport(url, domain, basicPatterns, webhooks, formAnalysis, riskScore)
    };
  }
}

function generateFallbackReport(url, domain, patterns, webhooks, formAnalysis, riskScore) {
  const riskLevel = riskScore >= 70 ? 'HIGH RISK' : (riskScore >= 40 ? 'MEDIUM RISK' : 'LOW RISK');
  const riskEmoji = riskScore >= 70 ? '🔴' : (riskScore >= 40 ? '🟡' : '🟢');
  
  let report = `${riskEmoji} **PHISHING SCAN REPORT - ${riskLevel} (${riskScore}/100)**\n\n`;
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  report += `**Target:** ${url}\n`;
  report += `**Domain:** ${domain}\n\n`;
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  report += `**📊 EXECUTIVE SUMMARY**\n\n`;
  if (riskScore >= 70) {
    report += `This website shows strong indicators of phishing activity. Users should AVOID entering any personal information and close the page immediately.\n\n`;
  } else if (riskScore >= 40) {
    report += `This website shows some suspicious characteristics. While it may be legitimate, caution is advised before entering sensitive data.\n\n`;
  } else {
    report += `This website shows no significant phishing indicators. It appears to be legitimate based on available data.\n\n`;
  }
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  report += `**🔍 DETECTED INDICATORS**\n\n`;
  
  if (patterns.length > 0) {
    report += `Found ${patterns.length} suspicious pattern(s):\n`;
    patterns.forEach(p => {
      const emoji = p.severity === 'critical' ? '🔴' : (p.severity === 'high' ? '🟠' : (p.severity === 'medium' ? '🟡' : '🔵'));
      report += `  ${emoji} ${p.description} (${p.severity})\n`;
    });
    report += `\n`;
  } else {
    report += `  ✅ No suspicious patterns detected in the HTML content.\n\n`;
  }
  
  if (webhooks.length > 0) {
    report += `  🔴🔴🔴 CRITICAL: ${webhooks.length} Discord webhook(s) detected!\n`;
    report += `  → These can exfiltrate user data to attackers in real-time.\n\n`;
  }
  
  if (formAnalysis.hasLoginForm) {
    report += `  ℹ️ Login form detected with ${formAnalysis.passwordFields} password field(s)\n`;
    if (formAnalysis.emptyActions > 0) {
      report += `  ⚠️ ${formAnalysis.emptyActions} form(s) have empty/missing action attributes\n`;
    }
    report += `\n`;
  }
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  report += `**⚠️ THREAT ASSESSMENT**\n\n`;
  
  if (webhooks.length > 0) {
    report += `Discord webhooks represent a CRITICAL threat - they allow attackers to receive stolen data instantly. This is almost never found on legitimate websites.\n\n`;
  }
  if (patterns.filter(p => p.severity === 'high').length > 0) {
    report += `High-severity patterns (credit card requests, SSN, passport, etc.) are strong indicators of identity theft phishing.\n\n`;
  }
  if (formAnalysis.hasLoginForm && riskScore < 40) {
    report += `The presence of a login form alone is not suspicious - many legitimate sites have login functionality.\n\n`;
  }
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  report += `**✅ RECOMMENDATIONS**\n\n`;
  
  if (riskScore >= 70) {
    report += `• DO NOT enter any personal information\n`;
    report += `• DO NOT click any links on this page\n`;
    report += `• Close the tab/browser immediately\n`;
    report += `• If you entered credentials, change your passwords immediately\n`;
  } else if (riskScore >= 40) {
    report += `• Verify the URL carefully - check for typos\n`;
    report += `• Only proceed if you are 100% sure this is the official site\n`;
    report += `• Use a search engine to find the official website instead of clicking links\n`;
  } else {
    report += `• No immediate action required\n`;
    report += `• Always practice normal online safety (check URLs, look for HTTPS)\n`;
  }
  
  report += `\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  report += `**📈 FINAL VERDICT**\n\n`;
  report += `Risk Score: ${riskScore}/100\n`;
  report += `Classification: ${riskLevel}\n`;
  report += `Safety Rating: ${riskScore >= 70 ? 'DANGEROUS' : (riskScore >= 40 ? 'CAUTION ADVISED' : 'SAFE')}\n\n`;
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  report += `*Scan performed by AntiSec Phishing Intelligence*\n`;
  report += `*AI analysis fallback mode - API key not configured*`;
  
  return report;
}

// ==================== MAIN HANDLER ====================

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ success: false, error: 'Method not allowed. Use GET.' });
  }

  const targetUrl = req.query.url;
  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing "url" parameter.' });
  }

  let urlObj;
  try {
    urlObj = new URL(targetUrl);
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      throw new Error('Only HTTP/HTTPS URLs are allowed');
    }
  } catch (e) {
    return res.status(400).json({ success: false, error: `Invalid URL: ${e.message}` });
  }

  console.log(`[AntiSec Scan] Starting analysis for: ${targetUrl}`);

  try {
    const fetchResponse = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache'
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(20000)
    });

    const html = await fetchResponse.text();
    const sizeKB = (html.length / 1024).toFixed(1);
    const httpStatus = fetchResponse.status;
    
    console.log(`[AntiSec Scan] Fetched ${sizeKB}KB, HTTP ${httpStatus} from ${urlObj.hostname}`);

    // Basic pattern detection
    const basicPatterns = detectBasicPatterns(html);
    const webhooks = detectWebhooks(html);
    const formAnalysis = analyzeForms(html);
    
    console.log(`[AntiSec Scan] Patterns: ${basicPatterns.length}, Webhooks: ${webhooks.length}, Login forms: ${formAnalysis.hasLoginForm}`);

    // AI-powered analysis
    const aiResult = await analyzeWithAI(
      targetUrl, 
      urlObj.hostname, 
      html, 
      basicPatterns, 
      webhooks, 
      formAnalysis,
      httpStatus
    );
    
    const sourcePreview = getSourcePreview(html);
    const loginForms = formAnalysis.hasLoginForm ? formAnalysis.total : 0;

    return res.status(200).json({
      success: true,
      url: targetUrl,
      domain: urlObj.hostname,
      riskScore: aiResult.riskScore,
      verdict: aiResult.verdict,
      isLegitimate: aiResult.isLegitimate,
      patterns: basicPatterns.slice(0, 30).map(p => ({
        pattern: p.description,
        severity: p.severity,
        location: 'HTML content analysis',
        category: p.category,
        occurrences: p.count || 1
      })),
      webhooks: webhooks.map(w => ({ 
        url: w, 
        type: 'Discord Webhook',
        risk: 'critical',
        warning: 'This webhook can receive stolen credentials in real-time'
      })),
      loginForms: loginForms,
      sizeKB: sizeKB,
      httpStatus: httpStatus,
      groqReport: aiResult.report,
      sourcePreview: sourcePreview,
      shortReason: aiResult.shortReason,
      userWarning: aiResult.userWarning,
      formAnalysis: {
        hasLoginForm: formAnalysis.hasLoginForm,
        total: formAnalysis.total,
        passwordFields: formAnalysis.passwordFields,
        emailFields: formAnalysis.emailFields,
        emptyActions: formAnalysis.emptyActions
      },
      scanTimestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`[AntiSec Scan] Error for ${targetUrl}:`, error.message);
    
    let errorMessage = error.message;
    let riskScore = 50;
    let patterns = [];
    
    if (error.name === 'AbortError' || error.message.includes('timeout')) {
      errorMessage = 'Request timeout - The server took too long to respond.';
      patterns.push({
        pattern: 'Timeout - Server unresponsive or very slow',
        severity: 'medium',
        location: 'Network analysis',
        category: 'timeout'
      });
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('getaddrinfo')) {
      errorMessage = 'DNS resolution failed - The domain could not be found.';
      patterns.push({
        pattern: 'Invalid or non-existent domain',
        severity: 'high',
        location: 'DNS analysis',
        category: 'invalid_domain'
      });
      riskScore = 85;
    } else if (error.message.includes('ECONNREFUSED')) {
      errorMessage = 'Connection refused - The server is not accepting connections.';
      patterns.push({
        pattern: 'Server offline or blocking automated requests',
        severity: 'medium',
        location: 'Network analysis',
        category: 'connection_error'
      });
    } else if (error.message.includes('CERT') || error.message.includes('SSL') || error.message.includes('certificate')) {
      errorMessage = 'SSL/TLS certificate error - The site may have an invalid security certificate.';
      patterns.push({
        pattern: 'Invalid SSL certificate - Security risk',
        severity: 'high',
        location: 'TLS analysis',
        category: 'certificate_error'
      });
      riskScore = 85;
    }
    
    const fallbackReport = `🔴 **SCAN FAILED - ${errorMessage.toUpperCase()}**\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n**Target:** ${targetUrl}\n**Domain:** ${urlObj.hostname}\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n**Error Details:**\n${errorMessage}\n\n**Possible causes:**\n• The website is temporarily offline\n• The server is blocking automated security scanners\n• Network connectivity issues\n• Invalid or self-signed SSL certificate\n\n**Recommendation:**\n• Try accessing the URL manually in your browser\n• If the site loads, it may be blocking security tools\n• If the site does not load, it may be inactive or taken down\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n**Safety Note:** When a site cannot be properly scanned, err on the side of caution. Do not enter personal information unless you are absolutely certain of the site's legitimacy.\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n*Scan performed by AntiSec Phishing Intelligence*`;
    
    return res.status(200).json({
      success: false,
      error: errorMessage,
      url: targetUrl,
      domain: urlObj.hostname,
      riskScore: riskScore,
      verdict: 'SCAN_ERROR',
      isLegitimate: false,
      patterns: patterns,
      webhooks: [],
      loginForms: 0,
      sizeKB: 0,
      httpStatus: 0,
      groqReport: fallbackReport,
      sourcePreview: '',
      shortReason: `Scan failed: ${errorMessage}`,
      userWarning: 'Unable to scan this URL. Verify manually before trusting.',
      scanTimestamp: new Date().toISOString()
    });
  }
  }
