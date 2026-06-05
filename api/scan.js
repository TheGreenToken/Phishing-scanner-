// api/scan.js - AI-Powered Phishing Scanner mit Key-Rotation & Discord Logging
// LANGE KI-REPORTS (800-1200 Wörter)

// ==================== KONFIGURATION ====================

// Alle verfügbaren API Keys aus den Environment Variables sammeln
function getAvailableApiKeys() {
  const keys = [];
  let index = 1;
  
  while (true) {
    const keyName = index === 1 ? 'GROQ_API_KEY' : `GROQ_API_KEY${index}`;
    const keyValue = process.env[keyName];
    if (keyValue && keyValue !== 'YOUR_GROQ_API_KEY_HERE') {
      keys.push({ name: keyName, value: keyValue });
    } else if (index > 1 && !keyValue) {
      break;
    }
    index++;
  }
  
  return keys;
}

const LOG_WEBHOOK_URL = process.env.LOG_DISCORD_WEBHOOK || null;

// ==================== API KEY ROTATION MANAGER ====================

class ApiKeyManager {
  constructor(keys) {
    this.keys = keys;
    this.currentIndex = 0;
    this.keyUsageCount = new Map();
    this.keyFailureCount = new Map();
    this.lastKeySwitchTime = Date.now();
  }
  
  getCurrentKey() {
    if (this.keys.length === 0) return null;
    return this.keys[this.currentIndex];
  }
  
  getNextKey() {
    if (this.keys.length <= 1) return this.getCurrentKey();
    this.currentIndex = (this.currentIndex + 1) % this.keys.length;
    this.lastKeySwitchTime = Date.now();
    console.log(`[KeyManager] Rotated to key: ${this.keys[this.currentIndex].name}`);
    return this.keys[this.currentIndex];
  }
  
  recordSuccess(keyName) {
    const count = this.keyUsageCount.get(keyName) || 0;
    this.keyUsageCount.set(keyName, count + 1);
    this.keyFailureCount.set(keyName, 0);
  }
  
  recordFailure(keyName) {
    const failures = (this.keyFailureCount.get(keyName) || 0) + 1;
    this.keyFailureCount.set(keyName, failures);
    if (failures >= 3) {
      console.log(`[KeyManager] Key ${keyName} failed ${failures} times - rotating`);
      this.getNextKey();
    }
  }
  
  getStats() {
    const stats = {};
    for (const key of this.keys) {
      stats[key.name] = {
        successes: this.keyUsageCount.get(key.name) || 0,
        failures: this.keyFailureCount.get(key.name) || 0
      };
    }
    return stats;
  }
}

let keyManager = null;

function getKeyManager() {
  const keys = getAvailableApiKeys();
  if (!keyManager || keyManager.keys.length !== keys.length) {
    keyManager = new ApiKeyManager(keys);
  }
  return keyManager;
}

// ==================== DISCORD LOGGING ====================

async function sendToDiscordLog(url, domain, riskScore, verdict, clientIp, userAgent, patternsCount, webhooksCount, success, errorMessage = null) {
  if (!LOG_WEBHOOK_URL) return;
  
  function getProvider(ip) {
    if (!ip || ip === 'unknown') return 'Unknown';
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) return 'Private/Local';
    if (ip.includes('cloudflare')) return 'Cloudflare';
    if (ip.includes('aws') || ip.includes('amazon')) return 'AWS';
    if (ip.includes('azure')) return 'Microsoft Azure';
    if (ip.includes('google') || ip.includes('gcp')) return 'Google Cloud';
    if (ip.includes('vercel')) return 'Vercel';
    return 'Public ISP';
  }
  
  const timestamp = new Date().toISOString();
  const riskEmoji = riskScore >= 70 ? '🔴' : (riskScore >= 40 ? '🟡' : '🟢');
  const statusEmoji = success ? '✅' : '❌';
  
  const embed = {
    title: `${statusEmoji} AntiSec Phishing Scan ${success ? 'Completed' : 'Failed'}`,
    color: success ? (riskScore >= 70 ? 0xe8000f : (riskScore >= 40 ? 0xffcc00 : 0x00cc44)) : 0xe8000f,
    timestamp: timestamp,
    footer: { text: 'AntiSec Phishing Intelligence Scanner' },
    fields: [
      { name: '🎯 Target URL', value: `\`\`\`${url.length > 200 ? url.substring(0, 197) + '...' : url}\`\`\``, inline: false },
      { name: '🌐 Domain', value: `\`${domain}\``, inline: true },
      { name: `${riskEmoji} Risk Score`, value: `**${riskScore}/100**`, inline: true },
      { name: '⚖️ Verdict', value: `\`${verdict || (success ? 'UNKNOWN' : 'SCAN_ERROR')}\``, inline: true },
      { name: '📊 Statistics', value: `Patterns: ${patternsCount}\nWebhooks: ${webhooksCount}`, inline: true },
      { name: '🖥️ Client Info', value: `IP: \`${clientIp || 'unknown'}\`\nProvider: \`${getProvider(clientIp)}\``, inline: true },
      { name: '🔧 User Agent', value: `\`\`\`${(userAgent || 'unknown').substring(0, 100)}\`\`\``, inline: false }
    ]
  };
  
  if (!success && errorMessage) {
    embed.fields.push({ name: '⚠️ Error', value: `\`\`\`${errorMessage.substring(0, 200)}\`\`\``, inline: false });
  }
  
  if (keyManager) {
    const stats = keyManager.getStats();
    const statsText = Object.entries(stats).map(([name, data]) => `${name}: ${data.successes} OK, ${data.failures} fails`).join('\n');
    if (statsText) {
      embed.fields.push({ name: '🔑 API Key Status', value: `\`\`\`${statsText}\`\`\``, inline: false });
    }
  }
  
  try {
    await fetch(LOG_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed], username: 'AntiSec Scanner Log' })
    });
  } catch (error) {
    console.error('[Logging] Webhook error:', error.message);
  }
}

// ==================== CLIENT INFO ====================

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const realIp = req.headers['x-real-ip'];
  const cfConnectingIp = req.headers['cf-connecting-ip'];
  const vercelIp = req.headers['x-vercel-forwarded-for'];
  
  if (cfConnectingIp) return cfConnectingIp;
  if (realIp) return realIp;
  if (forwarded) return forwarded.split(',')[0].trim();
  if (vercelIp) return vercelIp.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function getUserAgent(req) {
  return req.headers['user-agent'] || 'unknown';
}

// ==================== BASIC PATTERNS ====================

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
  { pattern: /driver.?license|führerschein|permis.?conduire/i, severity: 'high', category: 'identity', description: 'Driver license information requested' },
  { pattern: /urgent|dringend|immediate|sofort/i, severity: 'medium', category: 'urgency', description: 'Urgency language detected' },
  { pattern: /click.?here|klick.?hier|cliquez.?ici|haga.?clic/i, severity: 'low', category: 'suspicious_link', description: 'Generic click here link' }
];

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
  let clean = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '[SCRIPT CONTENT REMOVED]');
  clean = clean.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '[STYLE CONTENT REMOVED]');
  if (clean.length <= maxLength) return clean;
  return clean.substring(0, maxLength) + '\n\n... [TRUNCATED]';
}

// ==================== GROQ API CALL WITH RETRY ====================

async function callGroqWithRetry(messages, maxRetries = 3) {
  const manager = getKeyManager();
  let lastError = null;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const currentKey = manager.getCurrentKey();
    if (!currentKey) {
      throw new Error('No valid GROQ_API_KEY configured');
    }
    
    try {
      console.log(`[Groq] Attempt ${attempt + 1}/${maxRetries} using ${currentKey.name}`);
      
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentKey.value}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(messages),
        signal: AbortSignal.timeout(45000)
      });
      
      if (response.status === 429) {
        console.log(`[Groq] Rate limit on ${currentKey.name}, rotating`);
        manager.recordFailure(currentKey.name);
        manager.getNextKey();
        lastError = new Error(`Rate limit on ${currentKey.name}`);
        continue;
      }
      
      if (!response.ok) {
        const errorText = await response.text();
        manager.recordFailure(currentKey.name);
        manager.getNextKey();
        lastError = new Error(`HTTP ${response.status}: ${errorText}`);
        continue;
      }
      
      const data = await response.json();
      manager.recordSuccess(currentKey.name);
      return data;
      
    } catch (error) {
      manager.recordFailure(currentKey.name);
      manager.getNextKey();
      lastError = error;
    }
  }
  
  throw lastError || new Error('All API keys exhausted');
}

// ==================== EXTREM LANGER AI PROMPT (800-1200 Wörter) ====================

async function analyzeWithAI(url, domain, html, basicPatterns, webhooks, formAnalysis, httpStatus) {
  const keys = getAvailableApiKeys();
  const hasValidKeys = keys.length > 0 && keys[0].value !== 'YOUR_GROQ_API_KEY_HERE';
  
  if (!hasValidKeys) {
    const hasCritical = basicPatterns.some(p => p.severity === 'critical');
    const hasHigh = basicPatterns.some(p => p.severity === 'high');
    const riskScore = hasCritical ? 90 : (hasHigh ? 70 : (basicPatterns.length > 0 ? 40 : 10));
    return {
      riskScore: riskScore,
      verdict: riskScore > 60 ? 'SUSPICIOUS' : (riskScore > 30 ? 'CAUTION' : 'SAFE'),
      isLegitimate: riskScore < 30,
      report: `⚠️ **AI ANALYSIS NOT AVAILABLE**\n\nNo valid GROQ_API_KEY configured. Please add API keys to environment variables.\n\nCurrent scan results are based on pattern matching only.`,
      shortReason: 'AI analysis unavailable - configure API keys',
      userWarning: riskScore > 50 ? 'Proceed with caution' : 'No immediate warnings'
    };
  }
  
  const patternSummary = basicPatterns.length > 0 
    ? basicPatterns.map(p => `• ${p.description} (${p.severity.toUpperCase()} severity) - found ${p.count || 1} time(s)`).join('\n')
    : '• No suspicious patterns detected in the HTML content';
    
  const webhookSummary = webhooks.length > 0 
    ? `⚠️⚠️⚠️ CRITICAL SECURITY WARNING: ${webhooks.length} Discord webhook(s) detected!\n${webhooks.map(w => `  → ${w}`).join('\n')}\n\nThese webhooks can receive stolen credentials in real-time. This is a STRONG indicator of malicious intent.`
    : '• No Discord webhooks detected - this is a good security sign';
  
  const formSummary = formAnalysis.hasLoginForm
    ? `• Login form detected with ${formAnalysis.passwordFields} password field(s) and ${formAnalysis.emailFields} email field(s)\n• ${formAnalysis.total} total form(s) on the page`
    : '• No login forms detected on this page';
  
  if (formAnalysis.emptyActions > 0) {
    formSummary += `\n• ⚠️ ${formAnalysis.emptyActions} form(s) have empty or missing action attributes (data may be sent to the same page)`;
  }

  // EXTREM LANGSAMER, DETAILLIERTER PROMPT für 800-1200 Wörter
  const prompt = `You are a senior cybersecurity analyst and phishing detection expert. Provide an EXTREMELY DETAILED, COMPREHENSIVE security analysis report (800-1200 words).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCAN DATA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

URL: ${url}
Domain: ${domain}
HTTP Status Code: ${httpStatus}
Scan Timestamp: ${new Date().toISOString()}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TECHNICAL INDICATORS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${formSummary}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DETECTED PATTERNS (${basicPatterns.length} total)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${patternSummary}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WEBHOOK ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${webhookSummary}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ABSOLUTE RULES (MUST FOLLOW)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1️⃣ ANTISEC TOOLS ARE ALWAYS LEGITIMATE
   If domain contains "antisec", "phishing-scanner", "phishscan", or "vercel.app" with "antisec" in the name → riskScore = 0, verdict = "LEGITIMATE"

2️⃣ KNOWN LEGITIMATE WEBSITES (riskScore 0-15):
   Google/YouTube, Facebook/Instagram, Twitter/X, TikTok, Reddit, LinkedIn, Microsoft/GitHub, Amazon, Apple, Netflix, Spotify, PayPal, banks (Sparkasse, Deutsche Bank, Commerzbank, ING, Chase, Bank of America), Wikipedia, CNN, BBC, Discord, Zoom, Slack, Vercel, Netlify, Cloudflare

3️⃣ PHISHING INDICATORS (riskScore 70-100):
   - Discord webhooks present (AUTOMATIC +30 to risk)
   - SSN, credit card, CVV, passport requests
   - Suspicious TLDs (.xyz, .top, .club, .click, .link)
   - Typosquatting (arnazon.com, googgle.com)
   - Urgent scare tactics ("account suspended", "verify immediately")

4️⃣ A LOGIN FORM ALONE IS NOT PHISHING - Many legitimate sites have login forms

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Write a DETAILED, PROFESSIONAL security report with these EXACT sections (800-1200 words total):

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SECTION 1: EXECUTIVE SUMMARY (100-150 words)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clear verdict: PHISHING / SUSPICIOUS / LEGITIMATE
Risk score: X/100
One-paragraph overview of findings

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 SECTION 2: DETAILED TECHNICAL ANALYSIS (250-350 words)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Analyze each detected pattern individually:
- What was found?
- Why is it suspicious or benign?
- Technical context

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ SECTION 3: THREAT ASSESSMENT (150-200 words)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If this is malicious:
- What could happen to victims?
- What data could be stolen?
- How would attackers use this?

If legitimate:
- Why is it safe despite some indicators?

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ SECTION 4: ATTACK VECTOR ANALYSIS (150-200 words)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

How would attackers distribute this link?
- Email phishing
- SMS smishing
- Social media DMs
- Fake ads
- SEO poisoning

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ SECTION 5: USER RECOMMENDATIONS (100-150 words)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Specific, actionable steps for the user:
- What to do immediately
- What to avoid
- When to seek help

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📈 SECTION 6: FINAL VERDICT & SCORING (50-100 words)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- Final risk score
- Confidence level
- Safety rating (Safe / Caution / Dangerous)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

After your detailed report, provide this JSON:

{
  "riskScore": (number 0-100),
  "verdict": "PHISHING | SUSPICIOUS | LEGITIMATE",
  "isLegitimate": true/false,
  "shortReason": "One sentence summary (max 100 chars)",
  "userWarning": "What the user should do (max 150 chars)"
}

Make the report PROFESSIONAL, DETAILED, and WELL-STRUCTURED. Write in English. Use markdown formatting (headers, bullet points, bold).`;

  try {
    const groqResponse = await callGroqWithRetry({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { 
          role: 'system', 
          content: 'You are a senior cybersecurity analyst. Write EXTREMELY DETAILED reports (800-1200 words) with professional structure. Always recognize legitimate sites. Respond with the report first, then the JSON at the end.' 
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0.2,
      max_tokens: 3500
    });
    
    const aiResponse = groqResponse.choices[0].message.content;
    
    // Extrahiere JSON vom Ende der Antwort
    let jsonResult = {
      riskScore: 50,
      verdict: "SUSPICIOUS",
      isLegitimate: false,
      shortReason: "Analysis completed",
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
    
    // Entferne JSON aus dem Report für saubere Anzeige
    const cleanReport = aiResponse.replace(/\{[\s\S]*"riskScore"[\s\S]*\}/, '').trim();
    
    return {
      riskScore: jsonResult.riskScore,
      verdict: jsonResult.verdict,
      isLegitimate: jsonResult.isLegitimate,
      shortReason: jsonResult.shortReason,
      userWarning: jsonResult.userWarning,
      report: cleanReport || generateLongFallbackReport(url, domain, basicPatterns, webhooks, formAnalysis, jsonResult.riskScore)
    };
    
  } catch (error) {
    console.error('AI analysis error:', error);
    const riskScore = webhooks.length > 0 ? 85 : (basicPatterns.length > 0 ? 50 : 20);
    return {
      riskScore: riskScore,
      verdict: riskScore > 60 ? 'SUSPICIOUS' : 'SAFE',
      isLegitimate: riskScore < 30,
      shortReason: `AI error: ${error.message}`,
      userWarning: riskScore > 50 ? 'Do not enter personal information' : 'Proceed with caution',
      report: generateLongFallbackReport(url, domain, basicPatterns, webhooks, formAnalysis, riskScore)
    };
  }
}

// ==================== LANGER FALLBACK REPORT (ohne KI) ====================

function generateLongFallbackReport(url, domain, patterns, webhooks, formAnalysis, riskScore) {
  const riskLevel = riskScore >= 70 ? 'HIGH RISK' : (riskScore >= 40 ? 'MEDIUM RISK' : 'LOW RISK');
  const riskEmoji = riskScore >= 70 ? '🔴' : (riskScore >= 40 ? '🟡' : '🟢');
  
  let report = `${riskEmoji} **PHISHING SCAN REPORT - ${riskLevel} (${riskScore}/100)**\n\n`;
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  // SECTION 1: Executive Summary
  report += `## 📊 EXECUTIVE SUMMARY\n\n`;
  if (riskScore >= 70) {
    report += `This website exhibits STRONG indicators of malicious phishing activity. Our analysis has detected multiple high-severity patterns consistent with credential harvesting and identity theft schemes. Users should AVOID this site entirely and not enter any personal information.\n\n`;
  } else if (riskScore >= 40) {
    report += `This website shows MODERATE suspicious characteristics. While it may be legitimate, several indicators suggest caution is warranted. We recommend verifying the URL carefully before proceeding.\n\n`;
  } else {
    report += `This website shows MINIMAL suspicious indicators. Based on our pattern analysis, it appears likely to be legitimate. No immediate action is required, but standard online safety practices should always be followed.\n\n`;
  }
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  // SECTION 2: Technical Analysis
  report += `## 🔍 DETAILED TECHNICAL ANALYSIS\n\n`;
  report += `**Target:** ${url}\n`;
  report += `**Domain:** ${domain}\n`;
  report += `**Analysis Method:** Pattern-based detection (AI fallback mode)\n\n`;
  
  if (patterns.length > 0) {
    report += `### Detected Suspicious Patterns (${patterns.length} total):\n\n`;
    patterns.forEach((p, idx) => {
      const emoji = p.severity === 'critical' ? '🔴' : (p.severity === 'high' ? '🟠' : (p.severity === 'medium' ? '🟡' : '🔵'));
      report += `${idx + 1}. ${emoji} **${p.description}** (${p.severity.toUpperCase()} severity)\n`;
      report += `   - Category: ${p.category}\n`;
      report += `   - Occurrences: ${p.count || 1}\n\n`;
    });
  } else {
    report += `### No Suspicious Patterns Detected\n\n`;
    report += `The automated pattern scan did not find any known phishing indicators in the HTML content. This is a positive sign.\n\n`;
  }
  
  if (webhooks.length > 0) {
    report += `### ⚠️ CRITICAL: Discord Webhooks Detected\n\n`;
    report += `The page contains ${webhooks.length} Discord webhook URL(s):\n`;
    webhooks.forEach(w => {
      report += `- \`${w}\`\n`;
    });
    report += `\n**Why this matters:** Discord webhooks are often used by attackers to exfiltrate stolen credentials in real-time. This is a STRONG indicator of malicious intent and significantly increases the risk score.\n\n`;
  }
  
  if (formAnalysis.hasLoginForm) {
    report += `### Login Form Analysis\n\n`;
    report += `- Total forms on page: ${formAnalysis.total}\n`;
    report += `- Password fields: ${formAnalysis.passwordFields}\n`;
    report += `- Email fields: ${formAnalysis.emailFields}\n`;
    report += `- Forms with empty actions: ${formAnalysis.emptyActions}\n\n`;
    report += `Login forms are common on legitimate websites. The presence of a login form alone is NOT sufficient to classify a site as phishing.\n\n`;
  }
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  // SECTION 3: Threat Assessment
  report += `## ⚠️ THREAT ASSESSMENT\n\n`;
  
  if (webhooks.length > 0) {
    report += `### Critical Threat Level\n\n`;
    report += `The presence of Discord webhooks creates an immediate data exfiltration risk. If this is a phishing page, any credentials entered by victims would be instantly sent to the attacker's Discord server. This allows real-time harvesting of:\n\n`;
    report += `- Usernames and passwords\n`;
    report += `- Credit card numbers and CVV codes\n`;
    report += `- Personal identification information (SSN, passport, driver's license)\n`;
    report += `- Session cookies (allowing account takeover)\n\n`;
  }
  
  if (patterns.filter(p => p.severity === 'high' || p.severity === 'critical').length > 0) {
    report += `### Data Theft Potential\n\n`;
    report += `High-severity patterns indicate this site may be designed to steal:\n\n`;
    report += `- **Financial credentials** (credit cards, banking logins)\n`;
    report += `- **Identity documents** (SSN, passport, driver's license)\n`;
    report += `- **Account access** (passwords, 2FA codes)\n\n`;
  }
  
  if (riskScore < 40) {
    report += `### Low Threat Level\n\n`;
    report += `No significant threat indicators were detected. This appears to be a legitimate website with normal functionality. However, always exercise standard caution when entering personal information online.\n\n`;
  }
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  // SECTION 4: Attack Vector Analysis
  report += `## 🛡️ ATTACK VECTOR ANALYSIS\n\n`;
  
  if (riskScore >= 40) {
    report += `If this is a malicious phishing site, attackers would likely distribute it through:\n\n`;
    report += `**1. Email Phishing**\n`;
    report += `   - Impersonating legitimate companies (PayPal, Amazon, banks)\n`;
    report += `   - Urgent messages about "suspended accounts" or "unusual activity"\n`;
    report += `   - Fake invoices or shipping notifications\n\n`;
    report += `**2. SMS Smishing**\n`;
    report += `   - Text messages claiming package delivery issues\n`;
    report += `   - Bank fraud alerts with fake phone numbers\n\n`;
    report += `**3. Social Media DMs**\n`;
    report += `   - Direct messages on Discord, Twitter, or Instagram\n`;
    report += `   - Fake "verification" or "prize" scams\n\n`;
    report += `**4. SEO Poisoning**\n`;
    report += `   - Fake customer support numbers\n`;
    report += `   - Impersonated login pages for popular services\n\n`;
  } else {
    report += `No significant attack vectors identified. This domain does not exhibit characteristics typical of phishing distribution campaigns.\n\n`;
  }
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  // SECTION 5: User Recommendations
  report += `## ✅ USER RECOMMENDATIONS\n\n`;
  
  if (riskScore >= 70) {
    report += `**⚠️ IMMEDIATE ACTIONS REQUIRED:**\n\n`;
    report += `1. **DO NOT** enter any personal information on this site\n`;
    report += `2. **DO NOT** click any links or download any files\n`;
    report += `3. **Close the tab/browser** immediately\n`;
    report += `4. If you already entered credentials, change your passwords NOW\n`;
    report += `5. Enable 2FA on all affected accounts\n`;
    report += `6. Monitor your bank statements for unauthorized transactions\n`;
    report += `7. Report the site to Google Safe Browsing: https://safebrowsing.google.com\n\n`;
  } else if (riskScore >= 40) {
    report += `**⚠️ CAUTION ADVISED:**\n\n`;
    report += `1. **Verify the URL carefully** - Look for typos or unusual domain names\n`;
    report += `2. **Check for HTTPS** - Ensure the connection is secure\n`;
    report += `3. **Search for official site** - Use Google to find the real website\n`;
    report += `4. **Don't click email links** - Type the URL manually if possible\n`;
    report += `5. **Use a password manager** - It won't autofill on fake sites\n\n`;
  } else {
    report += `**✅ SAFE - Standard Precautions:**\n\n`;
    report += `1. Always check the URL before entering passwords\n`;
    report += `2. Look for HTTPS (padlock icon in address bar)\n`;
    report += `3. Use unique passwords for each site\n`;
    report += `4. Enable two-factor authentication when available\n`;
    report += `5. Be cautious of unexpected emails asking you to log in\n\n`;
  }
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  // SECTION 6: Final Verdict
  report += `## 📈 FINAL VERDICT & SCORING\n\n`;
  report += `| Category | Value |\n`;
  report += `|----------|-------|\n`;
  report += `| **Risk Score** | ${riskScore}/100 |\n`;
  report += `| **Risk Level** | ${riskLevel} |\n`;
  report += `| **Confidence** | Medium (AI fallback mode) |\n`;
  report += `| **Safety Rating** | ${riskScore >= 70 ? '🔴 DANGEROUS' : (riskScore >= 40 ? '🟡 CAUTION' : '🟢 SAFE')} |\n\n`;
  
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  report += `*Scan performed by AntiSec Phishing Intelligence Scanner*\n`;
  report += `*AI analysis fallback mode - API key not configured for extended AI reports*`;
  
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
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  const targetUrl = req.query.url;
  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing "url" parameter' });
  }

  const clientIp = getClientIp(req);
  const userAgent = getUserAgent(req);
  const scanStartTime = Date.now();

  let urlObj;
  try {
    urlObj = new URL(targetUrl);
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      throw new Error('Only HTTP/HTTPS allowed');
    }
  } catch (e) {
    await sendToDiscordLog(targetUrl, 'invalid', 0, 'INVALID_URL', clientIp, userAgent, 0, 0, false, e.message);
    return res.status(400).json({ success: false, error: `Invalid URL: ${e.message}` });
  }

  console.log(`[AntiSec] Scan: ${targetUrl} from ${clientIp}`);

  try {
    const fetchResponse = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9'
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(20000)
    });

    const html = await fetchResponse.text();
    const sizeKB = (html.length / 1024).toFixed(1);
    const httpStatus = fetchResponse.status;
    
    const basicPatterns = detectBasicPatterns(html);
    const webhooks = detectWebhooks(html);
    const formAnalysis = analyzeForms(html);
    
    const aiResult = await analyzeWithAI(
      targetUrl, urlObj.hostname, html, basicPatterns, webhooks, formAnalysis, httpStatus
    );
    
    const sourcePreview = getSourcePreview(html);
    const loginForms = formAnalysis.hasLoginForm ? formAnalysis.total : 0;
    
    await sendToDiscordLog(
      targetUrl, urlObj.hostname, aiResult.riskScore, aiResult.verdict,
      clientIp, userAgent, basicPatterns.length, webhooks.length, true, null
    );
    
    const scanDuration = Date.now() - scanStartTime;
    console.log(`[AntiSec] Complete: ${targetUrl} - Risk ${aiResult.riskScore} - ${scanDuration}ms`);

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
        location: 'HTML content',
        category: p.category,
        occurrences: p.count || 1
      })),
      webhooks: webhooks.map(w => ({ url: w, type: 'Discord Webhook', risk: 'critical' })),
      loginForms: loginForms,
      sizeKB: sizeKB,
      httpStatus: httpStatus,
      groqReport: aiResult.report,
      sourcePreview: sourcePreview,
      shortReason: aiResult.shortReason,
      userWarning: aiResult.userWarning,
      scanDurationMs: scanDuration,
      apiKeysAvailable: getAvailableApiKeys().length,
      scanTimestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`[AntiSec] Error:`, error.message);
    
    await sendToDiscordLog(
      targetUrl, urlObj.hostname, 0, 'SCAN_ERROR', clientIp, userAgent, 0, 0, false, error.message
    );
    
    return res.status(200).json({
      success: false,
      error: error.message,
      url: targetUrl,
      domain: urlObj.hostname,
      riskScore: 50,
      verdict: 'SCAN_ERROR',
      isLegitimate: false,
      patterns: [],
      webhooks: [],
      loginForms: 0,
      sizeKB: 0,
      groqReport: `❌ **Scan Failed**\n\nError: ${error.message}`,
      sourcePreview: '',
      shortReason: `Scan failed: ${error.message}`,
      userWarning: 'Unable to scan this URL',
      scanTimestamp: new Date().toISOString()
    });
  }
                                }
