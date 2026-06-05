// api/scan.js - Phishing Scanner mit API-Key-Rotation, Webhook-Logging & Auto-Popup Injection

// ==================== API KEYS ROTATION ====================
// Unterstützt unendlich viele Keys: GROQ_API_KEY, GROQ_API_KEY2, GROQ_API_KEY3, ...

function getAvailableApiKeys() {
  const keys = [];
  let i = 1;
  
  // Prüfe GROQ_API_KEY (ohne Nummer)
  if (process.env.GROQ_API_KEY && process.env.GROQ_API_KEY !== 'YOUR_GROQ_API_KEY_HERE') {
    keys.push({ key: process.env.GROQ_API_KEY, index: 0, name: 'GROQ_API_KEY' });
  }
  
  // Prüfe GROQ_API_KEY2, GROQ_API_KEY3, ...
  while (true) {
    const envName = `GROQ_API_KEY${i}`;
    const keyValue = process.env[envName];
    if (keyValue && keyValue !== 'YOUR_GROQ_API_KEY_HERE') {
      keys.push({ key: keyValue, index: i, name: envName });
      i++;
    } else {
      break;
    }
  }
  
  return keys;
}

// API-Key-Rotation mit Fehlerbehandlung
let currentKeyIndex = 0;
let apiKeys = [];

function refreshApiKeys() {
  apiKeys = getAvailableApiKeys();
  if (apiKeys.length === 0) {
    console.warn('[AntiSec] No API keys configured!');
  } else {
    console.log(`[AntiSec] Loaded ${apiKeys.length} API key(s)`);
  }
  return apiKeys;
}

async function callGroqWithRotation(messages, maxTokens = 2000, temperature = 0.2) {
  if (apiKeys.length === 0) {
    refreshApiKeys();
  }
  
  if (apiKeys.length === 0) {
    throw new Error('No GROQ_API_KEY configured. Please add at least one API key.');
  }
  
  let lastError = null;
  const triedKeys = [];
  
  for (let attempt = 0; attempt < apiKeys.length; attempt++) {
    const keyIndex = (currentKeyIndex + attempt) % apiKeys.length;
    const apiKey = apiKeys[keyIndex];
    
    if (triedKeys.includes(apiKey.name)) continue;
    triedKeys.push(apiKey.name);
    
    console.log(`[AntiSec] Trying API key: ${apiKey.name} (attempt ${attempt + 1}/${apiKeys.length})`);
    
    try {
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
      
      if (response.status === 429) {
        console.warn(`[AntiSec] Rate limit hit on ${apiKey.name}, trying next key...`);
        lastError = new Error(`Rate limit on ${apiKey.name}`);
        continue;
      }
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} on ${apiKey.name}`);
      }
      
      currentKeyIndex = (keyIndex + 1) % apiKeys.length;
      console.log(`[AntiSec] Success with ${apiKey.name}, next start index: ${currentKeyIndex}`);
      
      return await response.json();
      
    } catch (error) {
      console.error(`[AntiSec] Error with ${apiKey.name}:`, error.message);
      lastError = error;
    }
  }
  
  throw new Error(`All API keys failed. Last error: ${lastError?.message}`);
}

// ==================== WEBHOOK LOGGING ====================

const WEBHOOK_URL = process.env.LOG_WEBHOOK_URL || null;

async function sendScanLog(url, domain, riskScore, verdict, clientInfo, patternsCount, webhooksCount, success) {
  if (!WEBHOOK_URL) {
    console.log('[AntiSec] No LOG_WEBHOOK_URL configured - skipping log');
    return;
  }
  
  const timestamp = new Date().toISOString();
  const color = riskScore >= 70 ? 0xff0000 : (riskScore >= 40 ? 0xffaa00 : 0x00ff00);
  const statusEmoji = success ? '✅' : '❌';
  
  const embed = {
    title: `${statusEmoji} AntiSec Phishing Scan`,
    color: color,
    timestamp: timestamp,
    footer: {
      text: 'AntiSec Phishing Intelligence Scanner'
    },
    fields: [
      { name: '🎯 Target URL', value: url.length > 100 ? url.substring(0, 97) + '...' : url, inline: false },
      { name: '🌐 Domain', value: domain, inline: true },
      { name: '📊 Risk Score', value: `${riskScore}/100`, inline: true },
      { name: '⚖️ Verdict', value: verdict, inline: true },
      { name: '🔍 Patterns Found', value: patternsCount.toString(), inline: true },
      { name: '# Webhooks Detected', value: webhooksCount.toString(), inline: true },
      { name: '🖥️ Client Info', value: clientInfo || 'Unknown', inline: false },
      { name: '📅 Scan Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: false }
    ]
  };
  
  if (riskScore >= 70) {
    embed.fields.push({ name: '⚠️ CRITICAL WARNING', value: 'High risk phishing site detected!', inline: false });
  }
  if (webhooksCount > 0) {
    embed.fields.push({ name: '🔴 DISCORD WEBHOOKS FOUND', value: `⚠️ ${webhooksCount} webhook(s) detected!`, inline: false });
  }
  
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed], username: 'AntiSec Scanner' })
    });
    console.log('[AntiSec] Scan log sent to webhook');
  } catch (error) {
    console.error('[AntiSec] Webhook error:', error.message);
  }
}

// ==================== POPUP HTML (wird injectet) ====================

function getPopupHTML() {
  return `
<div id="antisec-server-popup" style="position:fixed; bottom:20px; right:20px; z-index:99999; animation:antisecSlideUp 0.3s ease; font-family:'Barlow',sans-serif;">
  <div style="background:#030303; border:1px solid #e8000f; border-left:3px solid #e8000f; padding:16px 20px; max-width:320px; box-shadow:0 0 20px rgba(232,0,15,0.2); border-radius:0;">
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:10px;">
      <div style="width:40px; height:40px; background:rgba(88,101,242,0.1); border:1px solid rgba(88,101,242,0.3); display:flex; align-items:center; justify-content:center; font-family:'Share Tech Mono',monospace; font-size:1.2rem; color:#c8c8c8;">#</div>
      <div>
        <div style="font-family:'Oswald',sans-serif; font-weight:600; font-size:0.9rem; letter-spacing:0.1em; color:#fff;">ANTISEC NETWORK</div>
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.55rem; color:#e8000f;">OPERATORS ONLY</div>
      </div>
    </div>
    <div style="font-family:'Barlow',sans-serif; font-size:0.75rem; color:#aaa; line-height:1.5; margin-bottom:14px;">Join our private server for exclusive OSINT tools, early access, and live threat intelligence.</div>
    <div style="display:flex; gap:10px;">
      <a href="https://discord.gg/6hv9T4UCN7" target="_blank" style="flex:1; background:#e8000f; border:none; padding:8px; font-family:'Oswald',sans-serif; font-weight:600; font-size:0.7rem; letter-spacing:0.1em; color:#000; text-align:center; text-decoration:none; text-transform:uppercase; cursor:crosshair;">Join Now →</a>
      <button onclick="document.getElementById('antisec-server-popup').style.display='none'; localStorage.setItem('antisecPopupClosed','true');" style="background:transparent; border:1px solid #333; padding:8px 12px; font-family:'Share Tech Mono',monospace; font-size:0.6rem; color:#666; cursor:crosshair;">Close</button>
    </div>
  </div>
</div>
<style>
  @keyframes antisecSlideUp {
    from { opacity:0; transform:translateY(20px); }
    to { opacity:1; transform:translateY(0); }
  }
</style>
<script>
  (function() {
    var popupClosed = localStorage.getItem('antisecPopupClosed');
    if (!popupClosed) {
      setTimeout(function() {
        var popup = document.getElementById('antisec-server-popup');
        if (popup) popup.style.display = 'block';
        setTimeout(function() {
          var popup = document.getElementById('antisec-server-popup');
          if (popup && popup.style.display === 'block') {
            popup.style.display = 'none';
          }
        }, 15000);
      }, 1000);
    }
  })();
</script>
`;
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
  { pattern: /https?:\/\/discord\.com\/api\/webhooks\//i, severity: 'critical', category: 'webhook', description: 'Discord webhook found - data exfiltration risk' }
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
  return {
    total: formCount,
    passwordFields: passwordInputs,
    emailFields: emailInputs,
    hasLoginForm: passwordInputs > 0
  };
}

function getSourcePreview(html, maxLength = 5000, injectPopup = false) {
  let clean = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '[SCRIPT REMOVED]');
  if (clean.length <= maxLength) {
    let result = clean;
    if (injectPopup) {
      result = getPopupHTML() + '\n\n<!-- AntiSec Popup Injected -->\n\n' + result;
    }
    return result;
  }
  let result = clean.substring(0, maxLength) + '\n\n... [truncated]';
  if (injectPopup) {
    result = getPopupHTML() + '\n\n<!-- AntiSec Popup Injected -->\n\n' + result;
  }
  return result;
}

// ==================== AI ANALYSIS ====================

async function analyzeWithAI(url, domain, html, basicPatterns, webhooks, formAnalysis, httpStatus) {
  const apiKeysAvailable = getAvailableApiKeys().length;
  
  if (apiKeysAvailable === 0) {
    const riskScore = basicPatterns.some(p => p.severity === 'critical') ? 90 : 
                     (basicPatterns.some(p => p.severity === 'high') ? 70 : 
                     (basicPatterns.length > 0 ? 40 : 10));
    return {
      riskScore: riskScore,
      verdict: riskScore > 60 ? 'SUSPICIOUS' : (riskScore > 30 ? 'CAUTION' : 'SAFE'),
      isLegitimate: riskScore < 30,
      report: `⚠️ **No Groq API Keys Configured**\n\nPlease add GROQ_API_KEY, GROQ_API_KEY2, etc. to your environment variables.\n\nUsing fallback pattern detection only.`,
      shortReason: 'No API keys configured',
      userWarning: 'Configure API keys for AI analysis'
    };
  }

  const patternSummary = basicPatterns.length > 0 
    ? basicPatterns.map(p => `• ${p.description} (${p.severity.toUpperCase()})`).join('\n')
    : '• No suspicious patterns detected';
    
  const webhookSummary = webhooks.length > 0 
    ? `⚠️⚠️⚠️ CRITICAL: ${webhooks.length} Discord webhook(s) detected!`
    : '• No Discord webhooks detected';

  const prompt = `You are a senior cybersecurity analyst. Analyze this website:

URL: ${url}
Domain: ${domain}
HTTP Status: ${httpStatus}

**Technical indicators:**
• Login form: ${formAnalysis.hasLoginForm ? 'Yes' : 'No'}
• Password fields: ${formAnalysis.passwordFields}
• Discord webhooks: ${webhooks.length > 0 ? 'YES (CRITICAL)' : 'No'}

**Patterns found:**
${patternSummary}

${webhookSummary}

**CRITICAL RULES:**
1. AntiSec tools (domains with "antisec", "phishing-scanner", "phishscan") are LEGITIMATE - riskScore = 0
2. YouTube, Google, Facebook, Amazon, Microsoft, Apple, Netflix, GitHub, PayPal are LEGITIMATE - riskScore 0-15
3. Discord webhooks = automatic +30 to risk score
4. SSN/Credit card requests = high risk (70-100)

Provide a detailed analysis (300-400 words) with: Executive Summary, Key Findings, Threat Assessment, Recommendations.

Then provide JSON at the end:
{
  "riskScore": (0-100),
  "verdict": "PHISHING|SUSPICIOUS|LEGITIMATE",
  "isLegitimate": true/false,
  "shortReason": "one sentence",
  "userWarning": "what to do"
}`;

  try {
    const response = await callGroqWithRotation([
      { 
        role: 'system', 
        content: 'You are a phishing detection expert. Provide detailed analysis. End with JSON.' 
      },
      { role: 'user', content: prompt }
    ], 1800, 0.2);
    
    const aiResponse = response.choices[0].message.content;
    
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
    console.error('AI error:', error);
    const riskScore = basicPatterns.some(p => p.severity === 'critical') ? 90 : 
                     (basicPatterns.some(p => p.severity === 'high') ? 70 : 
                     (basicPatterns.length > 0 ? 40 : 15));
    return {
      riskScore: riskScore,
      verdict: riskScore > 60 ? 'SUSPICIOUS' : (riskScore > 30 ? 'CAUTION' : 'SAFE'),
      isLegitimate: riskScore < 30,
      shortReason: 'AI temporarily unavailable',
      userWarning: riskScore > 50 ? 'Do not enter personal information' : 'Proceed with caution',
      report: generateFallbackReport(url, domain, basicPatterns, webhooks, formAnalysis, riskScore)
    };
  }
}

function generateFallbackReport(url, domain, patterns, webhooks, formAnalysis, riskScore) {
  return `## Phishing Scan Report

**Target:** ${url}
**Domain:** ${domain}
**Risk Score:** ${riskScore}/100

### Findings
- Patterns: ${patterns.length}
- Webhooks: ${webhooks.length}
- Login forms: ${formAnalysis.hasLoginForm ? 'Yes' : 'No'}

### Recommendation
${riskScore >= 70 ? 'DO NOT proceed - high risk!' : (riskScore >= 40 ? 'Caution advised' : 'No immediate threats detected')}`;
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

  const clientInfo = `${req.headers['user-agent'] || 'Unknown'} | ${req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown IP'}`;
  
  console.log(`[AntiSec] Scanning: ${targetUrl}`);

  try {
    const fetchResponse = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html'
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
    
    // Inject Popup in sourcePreview (wird im Frontend im "Source Preview" Tab angezeigt)
    const sourcePreview = getSourcePreview(html, 5000, true);
    
    await sendScanLog(
      targetUrl, 
      urlObj.hostname, 
      aiResult.riskScore, 
      aiResult.verdict, 
      clientInfo,
      basicPatterns.length,
      webhooks.length,
      true
    );
    
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
        category: p.category
      })),
      webhooks: webhooks.map(w => ({ url: w, type: 'Discord Webhook' })),
      loginForms: formAnalysis.hasLoginForm ? formAnalysis.total : 0,
      sizeKB: sizeKB,
      groqReport: aiResult.report,
      sourcePreview: sourcePreview,
      shortReason: aiResult.shortReason,
      userWarning: aiResult.userWarning,
      popupInjected: true
    });

  } catch (error) {
    console.error(`[AntiSec] Error:`, error.message);
    
    await sendScanLog(
      targetUrl, urlObj.hostname, 50, 'ERROR', clientInfo, 0, 0, false
    );
    
    return res.status(200).json({
      success: false,
      error: error.message,
      url: targetUrl,
      domain: urlObj.hostname,
      riskScore: 50,
      verdict: 'ERROR',
      patterns: [],
      webhooks: [],
      loginForms: 0,
      groqReport: `⚠️ Scan failed: ${error.message}`,
      sourcePreview: getPopupHTML() + '\n\n<!-- Scan failed, but popup injected -->\n\nError: ' + error.message,
      popupInjected: true
    });
  }
          }
