// api/scan.js - AI-Powered Phishing Scanner mit Key-Rotation & Discord Logging

// ==================== KONFIGURATION ====================

// Alle verfügbaren API Keys aus den Environment Variables sammeln
function getAvailableApiKeys() {
  const keys = [];
  let index = 1;
  
  // Sammle GROQ_API_KEY, GROQ_API_KEY2, GROQ_API_KEY3, ...
  while (true) {
    const keyName = index === 1 ? 'GROQ_API_KEY' : `GROQ_API_KEY${index}`;
    const keyValue = process.env[keyName];
    if (keyValue && keyValue !== 'YOUR_GROQ_API_KEY_HERE') {
      keys.push({ name: keyName, value: keyValue });
    } else if (index > 1 && !keyValue) {
      break; // Kein weiterer Key gefunden
    }
    index++;
  }
  
  return keys;
}

// Webhook-URL für Logging (aus env)
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
    console.log(`[KeyManager] Rotated to key index ${this.currentIndex}: ${this.keys[this.currentIndex].name}`);
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
    console.log(`[KeyManager] Key ${keyName} failed (${failures} failures)`);
    
    // Bei 3 Fehlern: Key als defekt markieren und rotieren
    if (failures >= 3) {
      console.log(`[KeyManager] Key ${keyName} has ${failures} failures - rotating`);
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

// Globaler KeyManager (wird bei jedem Request neu initialisiert)
let keyManager = null;

function getKeyManager() {
  const keys = getAvailableApiKeys();
  if (!keyManager || keyManager.keys.length !== keys.length) {
    keyManager = new ApiKeyManager(keys);
  }
  return keyManager;
}

// ==================== DISCORD LOGGING (mit Embed) ====================

async function sendToDiscordLog(url, domain, riskScore, verdict, clientIp, userAgent, patternsCount, webhooksCount, success, errorMessage = null) {
  if (!LOG_WEBHOOK_URL) {
    console.log('[Logging] No LOG_DISCORD_WEBHOOK configured - skipping');
    return;
  }
  
  // Provider aus IP ermitteln (vereinfacht)
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
    footer: {
      text: 'AntiSec Phishing Intelligence Scanner',
      icon_url: 'https://cdn.discordapp.com/icons/...'
    },
    fields: [
      {
        name: '🎯 Target URL',
        value: `\`\`\`${url.length > 200 ? url.substring(0, 197) + '...' : url}\`\`\``,
        inline: false
      },
      {
        name: '🌐 Domain',
        value: `\`${domain}\``,
        inline: true
      },
      {
        name: `${riskEmoji} Risk Score`,
        value: `**${riskScore}/100**`,
        inline: true
      },
      {
        name: '⚖️ Verdict',
        value: `\`${verdict || (success ? 'UNKNOWN' : 'SCAN_ERROR')}\``,
        inline: true
      },
      {
        name: '📊 Statistics',
        value: `Patterns: ${patternsCount}\nWebhooks: ${webhooksCount}`,
        inline: true
      },
      {
        name: '🖥️ Client Info',
        value: `IP: \`${clientIp || 'unknown'}\`\nProvider: \`${getProvider(clientIp)}\``,
        inline: true
      },
      {
        name: '🔧 User Agent',
        value: `\`\`\`${(userAgent || 'unknown').substring(0, 100)}\`\`\``,
        inline: false
      }
    ]
  };
  
  if (!success && errorMessage) {
    embed.fields.push({
      name: '⚠️ Error',
      value: `\`\`\`${errorMessage.substring(0, 200)}\`\`\``,
      inline: false
    });
  }
  
  // Key-Rotation Stats (falls verfügbar)
  if (keyManager) {
    const stats = keyManager.getStats();
    const statsText = Object.entries(stats).map(([name, data]) => 
      `${name}: ${data.successes} OK, ${data.failures} fails`
    ).join('\n');
    if (statsText) {
      embed.fields.push({
        name: '🔑 API Key Status',
        value: `\`\`\`${statsText}\`\`\``,
        inline: false
      });
    }
  }
  
  try {
    const response = await fetch(LOG_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [embed],
        username: 'AntiSec Scanner Log',
        avatar_url: 'https://cdn.discordapp.com/icons/...'
      })
    });
    
    if (!response.ok) {
      console.error(`[Logging] Failed to send webhook: ${response.status}`);
    } else {
      console.log('[Logging] Successfully sent scan log to Discord');
    }
  } catch (error) {
    console.error('[Logging] Webhook error:', error.message);
  }
}

// ==================== CLIENT IP ERMITTELN ====================

function getClientIp(req) {
  // Verschiedene Header für IP-Ermittlung (hinter Proxies)
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
  { pattern: /driver.?license|führerschein|permis.?conduire/i, severity: 'high', category: 'identity', description: 'Driver license information requested' }
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

// ==================== AI ANALYSIS WITH KEY ROTATION ====================

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
        signal: AbortSignal.timeout(30000)
      });
      
      if (response.status === 429) {
        // Rate Limit - Key rotieren
        console.log(`[Groq] Rate limit on ${currentKey.name}, rotating key`);
        manager.recordFailure(currentKey.name);
        manager.getNextKey();
        lastError = new Error(`Rate limit on ${currentKey.name}`);
        continue;
      }
      
      if (!response.ok) {
        const errorText = await response.text();
        console.log(`[Groq] Error on ${currentKey.name}: ${response.status} - ${errorText}`);
        manager.recordFailure(currentKey.name);
        manager.getNextKey();
        lastError = new Error(`HTTP ${response.status}: ${errorText}`);
        continue;
      }
      
      const data = await response.json();
      manager.recordSuccess(currentKey.name);
      return data;
      
    } catch (error) {
      console.log(`[Groq] Exception on ${currentKey.name}: ${error.message}`);
      manager.recordFailure(currentKey.name);
      manager.getNextKey();
      lastError = error;
    }
  }
  
  throw lastError || new Error('All API keys exhausted or failed');
}

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
    ? basicPatterns.map(p => `• ${p.description} (${p.severity.toUpperCase()})`).join('\n')
    : '• No suspicious patterns detected';
    
  const webhookSummary = webhooks.length > 0 
    ? `⚠️⚠️⚠️ CRITICAL: ${webhooks.length} Discord webhook(s) detected!`
    : '• No Discord webhooks detected';
  
  const prompt = `You are a phishing detection expert. Analyze this website:

URL: ${url}
Domain: ${domain}
HTTP Status: ${httpStatus}

Login form: ${formAnalysis.hasLoginForm ? 'Yes' : 'No'}
Password fields: ${formAnalysis.passwordFields}
Discord webhooks: ${webhooks.length > 0 ? 'YES (CRITICAL)' : 'No'}

Patterns found:
${patternSummary}

${webhookSummary}

RULES:
1. AntiSec tools (domains with "antisec", "phishing-scanner", "phishscan") are LEGITIMATE - riskScore 0
2. YouTube, Google, Facebook, Amazon, Microsoft, Apple, Netflix, Spotify, Twitter, GitHub, PayPal are LEGITIMATE
3. Discord webhooks = automatic +30 risk score
4. Login form alone does NOT make a phishing site

Respond with JSON only:
{
  "riskScore": 0-100,
  "verdict": "PHISHING|SUSPICIOUS|LEGITIMATE",
  "isLegitimate": true/false,
  "shortReason": "brief reason",
  "userWarning": "what to do"
}`;

  try {
    const groqResponse = await callGroqWithRetry({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: 'You are a phishing detection expert. Respond ONLY with valid JSON.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.2,
      max_tokens: 500
    });
    
    const aiResponse = groqResponse.choices[0].message.content;
    const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
    
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      return {
        riskScore: Math.min(100, Math.max(0, parsed.riskScore || 50)),
        verdict: parsed.verdict || 'SUSPICIOUS',
        isLegitimate: parsed.isLegitimate === true,
        shortReason: parsed.shortReason || 'Analysis completed',
        userWarning: parsed.userWarning || 'Proceed with caution',
        report: generateDetailedReport(url, domain, parsed.riskScore || 50, parsed.verdict, basicPatterns, webhooks, formAnalysis)
      };
    }
    
    throw new Error('Invalid JSON response');
    
  } catch (error) {
    console.error('AI analysis error:', error);
    const riskScore = webhooks.length > 0 ? 85 : (basicPatterns.length > 0 ? 50 : 20);
    return {
      riskScore: riskScore,
      verdict: riskScore > 60 ? 'SUSPICIOUS' : 'SAFE',
      isLegitimate: riskScore < 30,
      shortReason: `AI error: ${error.message}`,
      userWarning: riskScore > 50 ? 'Do not enter personal information' : 'Proceed with caution',
      report: generateDetailedReport(url, domain, riskScore, 'MANUAL_FALLBACK', basicPatterns, webhooks, formAnalysis)
    };
  }
}

function generateDetailedReport(url, domain, riskScore, verdict, patterns, webhooks, formAnalysis) {
  const riskEmoji = riskScore >= 70 ? '🔴' : (riskScore >= 40 ? '🟡' : '🟢');
  const verdictText = verdict === 'PHISHING' ? '⚠️ PHISHING SUSPECTED' : (verdict === 'SUSPICIOUS' ? '⚠️ SUSPICIOUS' : '✅ LEGITIMATE');
  
  let report = `${riskEmoji} **${verdictText}** (Risk: ${riskScore}/100)\n\n`;
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  report += `**Target:** ${url}\n`;
  report += `**Domain:** ${domain}\n\n`;
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  if (patterns.length > 0) {
    report += `**Detected Patterns:**\n`;
    patterns.forEach(p => {
      const emoji = p.severity === 'critical' ? '🔴' : (p.severity === 'high' ? '🟠' : (p.severity === 'medium' ? '🟡' : '🔵'));
      report += `  ${emoji} ${p.description}\n`;
    });
    report += `\n`;
  } else {
    report += `✅ No suspicious patterns detected\n\n`;
  }
  
  if (webhooks.length > 0) {
    report += `🔴🔴🔴 **CRITICAL:** ${webhooks.length} Discord webhook(s) found!\n`;
    report += `   → Data can be exfiltrated to attackers in real-time\n\n`;
  }
  
  if (formAnalysis.hasLoginForm) {
    report += `ℹ️ Login form detected (${formAnalysis.passwordFields} password field(s))\n\n`;
  }
  
  if (riskScore >= 70) {
    report += `**Recommendation:** DO NOT use this site! Close the page immediately.\n`;
  } else if (riskScore >= 40) {
    report += `**Recommendation:** Proceed with caution. Verify the URL carefully.\n`;
  } else {
    report += `**Recommendation:** No immediate action required. Normal caution is sufficient.\n`;
  }
  
  report += `\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  report += `*Scan performed by AntiSec Phishing Intelligence*`;
  
  return report;
}

// ==================== MAIN HANDLER ====================

export default async function handler(req, res) {
  // CORS Headers
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

  // Client Info für Logging
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
    // Auch Fehler loggen
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
    
    // Erfolgs-Log an Discord senden
    await sendToDiscordLog(
      targetUrl, 
      urlObj.hostname, 
      aiResult.riskScore, 
      aiResult.verdict,
      clientIp, 
      userAgent, 
      basicPatterns.length, 
      webhooks.length, 
      true, 
      null
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
    
    // Fehler-Log an Discord senden
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
