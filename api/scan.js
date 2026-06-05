// api/scan.js - AI-Powered Phishing Scanner mit API-Key-Rotation & Discord Logging

// ==================== KONFIGURATION ====================

// Alle GROQ API Keys aus Environment Variablen sammeln (unendlich skalierbar)
function getGroqApiKeys() {
  const keys = [];
  let i = 1;
  
  // Primärer Key
  if (process.env.GROQ_API_KEY) {
    keys.push({ key: process.env.GROQ_API_KEY, index: 1 });
  }
  
  // Weitere Keys: GROQ_API_KEY2, GROQ_API_KEY3, GROQ_API_KEY4, ...
  while (true) {
    const keyName = `GROQ_API_KEY${i === 1 ? '' : i}`;
    const keyValue = process.env[keyName];
    if (!keyValue && i > 1) break;
    if (keyValue && i > 1) {
      keys.push({ key: keyValue, index: i });
    }
    i++;
  }
  
  return keys;
}

// Discord Webhook URL für Logging
const DISCORD_WEBHOOK_URL = process.env.DISCORD_LOG_WEBHOOK || null;

// ==================== HELFER FÜR API-KEY-ROTATION ====================

let currentKeyIndex = 0;
const keyUsageCount = new Map(); // Track usage per key
const keyFailCount = new Map();   // Track failures per key

async function callGroqWithKeyRotation(messages, maxTokens = 2000, temperature = 0.2) {
  const apiKeys = getGroqApiKeys();
  
  if (apiKeys.length === 0) {
    throw new Error('No GROQ_API_KEY found in environment variables');
  }
  
  // Sortiere Keys nach Erfolgsrate (am Anfang noch nicht, später schon)
  const sortedKeys = [...apiKeys].sort((a, b) => {
    const failA = keyFailCount.get(a.key) || 0;
    const failB = keyFailCount.get(b.key) || 0;
    return failA - failB;
  });
  
  // Rotiere durch die Keys (Round Robin mit Fehlervermeidung)
  let attempts = 0;
  const maxAttempts = sortedKeys.length;
  
  for (let offset = 0; offset < maxAttempts; offset++) {
    const keyIndex = (currentKeyIndex + offset) % sortedKeys.length;
    const apiKey = sortedKeys[keyIndex];
    
    if (!apiKey) continue;
    
    // Überspringe Keys mit vielen Fehlern (temporär)
    if ((keyFailCount.get(apiKey.key) || 0) > 3) {
      console.log(`[KeyRotation] Skipping key ${apiKey.index} due to ${keyFailCount.get(apiKey.key)} failures`);
      continue;
    }
    
    try {
      console.log(`[KeyRotation] Trying key ${apiKey.index} (attempt ${attempts + 1}/${maxAttempts})`);
      
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey.key}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile',
          messages: messages,
          temperature: temperature,
          max_tokens: maxTokens
        })
      });
      
      if (response.ok) {
        // Erfolg: Key verwenden und Zähler aktualisieren
        currentKeyIndex = (keyIndex + 1) % sortedKeys.length;
        keyUsageCount.set(apiKey.key, (keyUsageCount.get(apiKey.key) || 0) + 1);
        keyFailCount.set(apiKey.key, 0); // Fehlerzähler zurücksetzen
        
        const data = await response.json();
        console.log(`[KeyRotation] Success with key ${apiKey.index} (Total usage: ${keyUsageCount.get(apiKey.key)})`);
        return data;
      }
      
      // Rate Limit Error?
      const errorText = await response.text();
      console.log(`[KeyRotation] Key ${apiKey.index} failed: HTTP ${response.status} - ${errorText.substring(0, 100)}`);
      
      if (response.status === 429) {
        // Rate Limit - Key als "überlastet" markieren
        keyFailCount.set(apiKey.key, (keyFailCount.get(apiKey.key) || 0) + 1);
        console.log(`[KeyRotation] Rate limit on key ${apiKey.index}, failures: ${keyFailCount.get(apiKey.key)}`);
        continue; // Nächsten Key versuchen
      }
      
      if (response.status === 401) {
        // Invalid Key - permanent ausschließen
        keyFailCount.set(apiKey.key, 999); // Sehr hohe Zahl = permanent deaktiviert
        console.log(`[KeyRotation] Invalid key ${apiKey.index}, permanently disabled`);
        continue;
      }
      
      // Andere Fehler - kurze Pause und nächsten Key
      keyFailCount.set(apiKey.key, (keyFailCount.get(apiKey.key) || 0) + 1);
      continue;
      
    } catch (error) {
      console.log(`[KeyRotation] Key ${apiKey.index} error: ${error.message}`);
      keyFailCount.set(apiKey.key, (keyFailCount.get(apiKey.key) || 0) + 1);
      continue;
    }
  }
  
  throw new Error('All GROQ API keys exhausted or rate limited');
}

// ==================== DISCORD LOGGING ====================

async function sendToDiscordLog(scanData, clientInfo) {
  if (!DISCORD_WEBHOOK_URL) {
    console.log('[DiscordLog] No webhook URL configured - skipping');
    return;
  }
  
  const { url, domain, riskScore, verdict, isLegitimate, patterns, webhooks, formAnalysis, scanTimestamp } = scanData;
  const { ip, userAgent, provider, country, city } = clientInfo;
  
  // Risiko-Farbe für Embed
  let color = 0x00ff00; // Grün für sicher
  if (riskScore >= 70) color = 0xff0000; // Rot für Phishing
  else if (riskScore >= 40) color = 0xffaa00; // Orange für verdächtig
  
  const riskEmoji = riskScore >= 70 ? '🔴' : (riskScore >= 40 ? '🟡' : '🟢');
  
  // Embed erstellen
  const embed = {
    title: `${riskEmoji} Phishing Scan Log`,
    description: `A scan was performed by **AntiSec Phishing Scanner**`,
    color: color,
    timestamp: scanTimestamp,
    fields: [
      {
        name: '🎯 Target URL',
        value: url.length > 100 ? url.substring(0, 100) + '...' : url,
        inline: false
      },
      {
        name: '🌐 Domain',
        value: domain,
        inline: true
      },
      {
        name: '📊 Risk Score',
        value: `${riskScore}/100`,
        inline: true
      },
      {
        name: '⚖️ Verdict',
        value: verdict,
        inline: true
      },
      {
        name: '✅ Legitimate',
        value: isLegitimate ? 'Yes' : 'No',
        inline: true
      },
      {
        name: '🔍 Patterns Found',
        value: patterns.length > 0 ? patterns.map(p => `• ${p.description.substring(0, 60)}`).join('\n') : 'None',
        inline: false
      },
      {
        name: '🔗 Discord Webhooks',
        value: webhooks.length > 0 ? webhooks.map(w => `• ${w.url.substring(0, 80)}`).join('\n') : 'None detected',
        inline: false
      },
      {
        name: '📝 Form Analysis',
        value: `Login form: ${formAnalysis.hasLoginForm ? 'Yes' : 'No'}\nPassword fields: ${formAnalysis.passwordFields}\nTotal forms: ${formAnalysis.total}`,
        inline: true
      }
    ],
    footer: {
      text: 'AntiSec Phishing Intelligence Scanner'
    }
  };
  
  // Client-Info-Felder
  const clientFields = [
    {
      name: '🖥️ Client IP',
      value: ip || 'Unknown',
      inline: true
    },
    {
      name: '📍 Location',
      value: `${city || 'Unknown'}, ${country || 'Unknown'}`,
      inline: true
    },
    {
      name: '🏢 ISP/Provider',
      value: provider || 'Unknown',
      inline: true
    },
    {
      name: '🌍 User Agent',
      value: userAgent ? userAgent.substring(0, 100) + (userAgent.length > 100 ? '...' : '') : 'Unknown',
      inline: false
    }
  ];
  
  embed.fields.push(...clientFields);
  
  // Zusätzliche Warnung bei kritischen Ergebnissen
  if (riskScore >= 70) {
    embed.fields.push({
      name: '⚠️ CRITICAL WARNING',
      value: 'High risk score detected! This may be a phishing site.',
      inline: false
    });
  }
  
  if (webhooks.length > 0) {
    embed.fields.push({
      name: '🔴 DISCORD WEBHOOK DETECTED',
      value: 'This site contains Discord webhooks that can exfiltrate user data!',
      inline: false
    });
  }
  
  try {
    const response = await fetch(DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        embeds: [embed],
        username: 'AntiSec Scanner',
        avatar_url: 'https://cdn.discordapp.com/icons/...' // Optional
      })
    });
    
    if (response.ok) {
      console.log('[DiscordLog] Log sent successfully');
    } else {
      console.log(`[DiscordLog] Failed to send log: ${response.status}`);
    }
  } catch (error) {
    console.error('[DiscordLog] Error sending log:', error.message);
  }
}

// Client-Info extrahieren (IP, Provider, Location)
async function getClientInfo(req) {
  // IP-Adresse ermitteln (Vercel-spezifisch)
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
             req.socket.remoteAddress || 
             req.connection.remoteAddress || 
             'Unknown';
  
  const userAgent = req.headers['user-agent'] || 'Unknown';
  
  // Provider/Location via ip-api.com (kostenlos, keine API-Key nötig)
  let provider = 'Unknown';
  let country = 'Unknown';
  let city = 'Unknown';
  
  try {
    // Nur für öffentliche IPs, nicht für localhost
    if (ip && !ip.startsWith('127.') && !ip.startsWith('::1') && ip !== 'Unknown') {
      const geoResponse = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,isp`, {
        signal: AbortSignal.timeout(3000)
      });
      const geoData = await geoResponse.json();
      if (geoData.status === 'success') {
        country = geoData.country || 'Unknown';
        city = geoData.city || 'Unknown';
        provider = geoData.isp || 'Unknown';
      }
    }
  } catch (error) {
    console.log('[ClientInfo] Geo lookup failed:', error.message);
  }
  
  return { ip, userAgent, provider, country, city };
}

// ==================== PHISHING PATTERNS ====================

const PHISHING_PATTERNS = [
  { pattern: /<input[^>]*type=["']password["']/gi, severity: 'medium', category: 'password_field', description: 'Password input field detected' },
  { pattern: /credit.?card|kreditkarte|carte.?bancaire|tarjeta.?credito/i, severity: 'high', category: 'financial', description: 'Credit card information requested' },
  { pattern: /cvv|cvc|security.?code|sicherheitscode/i, severity: 'high', category: 'financial', description: 'CVV/CVC security code request' },
  { pattern: /ssn|social.?security|sozialversicherung|national.?id/i, severity: 'high', category: 'identity', description: 'SSN/National ID number requested' },
  { pattern: /account.*suspended|gesperrt|suspendu|suspended/i, severity: 'high', category: 'scare', description: 'Account suspension threat detected' },
  { pattern: /verify.*identity|identität.*bestätigen|verify your identity/i, severity: 'high', category: 'scare', description: 'Identity verification request' },
  { pattern: /bitcoin|ethereum|crypto|wallet.*connect|metamask/i, severity: 'high', category: 'crypto', description: 'Cryptocurrency or wallet connection request' },
  { pattern: /https?:\/\/discord\.com\/api\/webhooks\//i, severity: 'critical', category: 'webhook', description: 'Discord webhook found - data exfiltration risk' },
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

// ==================== AI ANALYSIS ====================

async function analyzeWithAI(url, domain, html, basicPatterns, webhooks, formAnalysis, httpStatus) {
  const patternSummary = basicPatterns.length > 0 
    ? basicPatterns.map(p => `• ${p.description} (${p.severity.toUpperCase()} severity)`).join('\n')
    : '• No suspicious patterns detected';
    
  const webhookSummary = webhooks.length > 0 
    ? `⚠️ CRITICAL: ${webhooks.length} Discord webhook(s) detected!`
    : '• No Discord webhooks detected';
  
  const prompt = `You are a phishing detection expert. Analyze this website:

URL: ${url}
Domain: ${domain}
HTTP Status: ${httpStatus}

Login form: ${formAnalysis.hasLoginForm ? 'Yes' : 'No'}
Password fields: ${formAnalysis.passwordFields}
Discord webhooks: ${webhooks.length > 0 ? 'YES' : 'No'}

Patterns found:
${patternSummary}

${webhookSummary}

IMPORTANT RULES:
1. AntiSec tools (domains with "antisec", "phishing-scanner", "phishscan") are LEGITIMATE - give riskScore 0
2. YouTube, Google, Facebook, Amazon, Microsoft, Apple, Netflix, Spotify, Twitter, Instagram, LinkedIn, Wikipedia, GitHub, PayPal, banks are LEGITIMATE - give low risk (0-15)
3. Discord webhooks = automatic +30 to risk score
4. Login forms alone do NOT make a phishing site

Provide a detailed analysis (300-400 words) then the JSON.`;

  const messages = [
    { 
      role: 'system', 
      content: 'You are a senior cybersecurity analyst. Provide detailed phishing analysis. Always return JSON at the end.' 
    },
    { role: 'user', content: prompt }
  ];
  
  try {
    const data = await callGroqWithKeyRotation(messages, 1500, 0.2);
    const aiResponse = data.choices[0].message.content;
    
    // JSON extrahieren
    let jsonResult = {
      riskScore: 50,
      verdict: "SUSPICIOUS",
      isLegitimate: false,
      shortReason: "Analysis completed",
      userWarning: "Proceed with caution"
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
      } catch (e) {}
    }
    
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
    const hasCritical = basicPatterns.some(p => p.severity === 'critical');
    const hasHigh = basicPatterns.some(p => p.severity === 'high');
    const riskScore = hasCritical ? 90 : (hasHigh ? 70 : (basicPatterns.length > 0 ? 40 : 15));
    
    return {
      riskScore: riskScore,
      verdict: riskScore > 60 ? 'SUSPICIOUS' : (riskScore > 30 ? 'CAUTION' : 'SAFE'),
      isLegitimate: riskScore < 30,
      shortReason: 'AI temporarily unavailable - using pattern detection',
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
  report += `**Target:** ${url}\n**Domain:** ${domain}\n\n`;
  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  if (patterns.length > 0) {
    report += `**Detected Patterns:**\n${patterns.map(p => `• ${p.description}`).join('\n')}\n\n`;
  }
  
  if (webhooks.length > 0) {
    report += `🔴 **CRITICAL:** ${webhooks.length} Discord webhook(s) detected!\n\n`;
  }
  
  report += `**Recommendation:** ${riskScore >= 70 ? 'DO NOT use this site!' : (riskScore >= 40 ? 'Proceed with caution' : 'No immediate action needed')}\n`;
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

  let urlObj;
  try {
    urlObj = new URL(targetUrl);
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      throw new Error('Only HTTP/HTTPS allowed');
    }
  } catch (e) {
    return res.status(400).json({ success: false, error: `Invalid URL: ${e.message}` });
  }

  console.log(`[AntiSec] Starting scan for: ${targetUrl}`);
  
  // Client-Info für Logging
  const clientInfo = await getClientInfo(req);
  const scanTimestamp = new Date().toISOString();

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
    
    console.log(`[AntiSec] Patterns: ${basicPatterns.length}, Webhooks: ${webhooks.length}`);

    const aiResult = await analyzeWithAI(
      targetUrl, urlObj.hostname, html, basicPatterns, webhooks, formAnalysis, httpStatus
    );
    
    const sourcePreview = getSourcePreview(html);
    const loginForms = formAnalysis.hasLoginForm ? formAnalysis.total : 0;
    
    const scanData = {
      url: targetUrl,
      domain: urlObj.hostname,
      riskScore: aiResult.riskScore,
      verdict: aiResult.verdict,
      isLegitimate: aiResult.isLegitimate,
      patterns: basicPatterns,
      webhooks: webhooks,
      loginForms: loginForms,
      formAnalysis: formAnalysis,
      scanTimestamp: scanTimestamp
    };
    
    // Discord Log senden (asynchron, nicht blockierend)
    sendToDiscordLog(scanData, clientInfo).catch(err => console.error('Discord log error:', err));

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
        category: p.category
      })),
      webhooks: webhooks.map(w => ({ url: w, type: 'Discord Webhook' })),
      loginForms: loginForms,
      sizeKB: sizeKB,
      groqReport: aiResult.report,
      sourcePreview: sourcePreview,
      shortReason: aiResult.shortReason,
      userWarning: aiResult.userWarning,
      scanTimestamp: scanTimestamp
    });

  } catch (error) {
    console.error(`[AntiSec] Error:`, error.message);
    
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
      groqReport: `⚠️ **Scan Failed**\n\nError: ${error.message}`,
      sourcePreview: '',
      scanTimestamp: scanTimestamp
    });
  }
      }
