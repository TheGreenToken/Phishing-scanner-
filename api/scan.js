// api/scan.js - Advanced Phishing Scanner mit optimierter Groq AI Integration

const GROQ_API_KEY = process.env.GROQ_API_KEY || 'YOUR_GROQ_API_KEY_HERE';

// ==================== ERWEITERTE PHISHING-PATTERNS ====================

const PHISHING_PATTERNS = [
  // Password/Login related (HIGH)
  { pattern: /<input[^>]*type=["']password["']/gi, severity: 'high', category: 'password_field', description: 'Password input field detected' },
  { pattern: /<form[^>]*action=["'][^"']*\.(php|asp|jsp|py|pl)[^"']*["']/gi, severity: 'high', category: 'backend_script', description: 'Form submits to backend script' },
  
  // Financial/Credit Card (HIGH)
  { pattern: /credit.?card|kreditkarte|carte.?bancaire|tarjeta.?credito|cartão.?crédito/i, severity: 'high', category: 'financial', description: 'Credit card information requested' },
  { pattern: /cvv|cvc|security.?code|sicherheitscode|code.?sécurité/i, severity: 'high', category: 'financial', description: 'CVV/CVC code request (highly suspicious)' },
  { pattern: /(?:bank|konto|account|compte|cuenta).*(?:nummer|number|número|n°)/i, severity: 'high', category: 'financial', description: 'Bank account number requested' },
  
  // Identity Theft (HIGH)
  { pattern: /ssn|social.?security|sozialversicherung|sécurité.?sociale|seguridad.?social/i, severity: 'high', category: 'identity_theft', description: 'SSN/National ID requested' },
  { pattern: /passport|reisepass|passeport|pasaporte|passaporte/i, severity: 'high', category: 'identity_theft', description: 'Passport information requested' },
  { pattern: /driver.?license|führerschein|permis.?conduire|licencia.?conducir/i, severity: 'high', category: 'identity_theft', description: 'Driver license requested' },
  
  // Scare tactics / Urgency (HIGH)
  { pattern: /(?:account|konto|compte|cuenta).*(?:suspended|gesperrt|suspendu|suspendido)/i, severity: 'high', category: 'scare_tactic', description: 'Account suspension threat detected' },
  { pattern: /(?:unusual|ungewöhnlich|inhabituelle|inusual).*(?:activity|aktivität|activité|actividad)/i, severity: 'high', category: 'scare_tactic', description: 'Unusual activity alert (scare tactic)' },
  { pattern: /(?:limited|eingeschränkt|limité|limitado).*(?:access|zugriff|accès|acceso)/i, severity: 'high', category: 'scare_tactic', description: 'Limited access threat' },
  { pattern: /(?:verify|verifizieren|vérifier|verificar).*(?:identity|identität|identité|identidad)/i, severity: 'high', category: 'scare_tactic', description: 'Identity verification request' },
  { pattern: /(?:security|sicherheit|sécurité|seguridad).*(?:alert|warnung|alerte|alerta)/i, severity: 'medium', category: 'scare_tactic', description: 'Security alert (potential scare tactic)' },
  
  // Brand Impersonation (HIGH)
  { pattern: /paypal|amazon|apple|microsoft|netflix|spotify|dhl|fedex|ups|bank of america|chase|wells fargo|deutsche bank|commerzbank|sparkasse|volksbank/i, severity: 'high', category: 'brand_impersonation', description: 'Well-known brand name detected (potential impersonation)' },
  
  // 2FA/Credential Theft (MEDIUM)
  { pattern: /two.?factor|2fa|multi.?factor|mfa/i, severity: 'medium', category: '2fa_bypass', description: '2FA/MFA request (potential credential harvesting)' },
  { pattern: /(?:login|anmelden|signin|connexion|iniciar.?sesion).*(?:problem|issue|error|fehler|problème|problema)/i, severity: 'medium', category: 'login', description: 'Login problem/error message' },
  
  // Crypto Scams (HIGH)
  { pattern: /bitcoin|ethereum|crypto|wallet|metamask|trust.?wallet|phantom|ledger|trezor/i, severity: 'high', category: 'crypto_scam', description: 'Cryptocurrency/wallet related (potential scam)' },
  { pattern: /(?:send|deposit|transfer|überweisen|envoyer|enviar).*(?:bitcoin|eth|ethereum|crypto)/i, severity: 'high', category: 'crypto_scam', description: 'Crypto transfer request' },
  
  // Account Recovery (MEDIUM)
  { pattern: /(?:reactivate|reaktivieren|réactiver|reactivar).*(?:account|konto|compte|cuenta)/i, severity: 'medium', category: 'account_recovery', description: 'Account reactivation request' },
  { pattern: /(?:confirm|bestätigen|confirmer|confirmar).*(?:email|e-mail|mail)/i, severity: 'medium', category: 'email_verification', description: 'Email confirmation request' },
  
  // Suspicious redirects/URLs (MEDIUM)
  { pattern: /window\.location\s*=|location\.href\s*=|location\.replace\(/i, severity: 'medium', category: 'redirect', description: 'JavaScript redirect detected' },
  { pattern: /<meta[^>]*http-equiv=["']refresh["'][^>]*content=["']\d+;\s*url=/i, severity: 'medium', category: 'redirect', description: 'Meta refresh redirect detected' },
  
  // Data exfiltration indicators (HIGH)
  { pattern: /XMLHttpRequest|fetch\s*\(\s*["'][^"']*\/api\/webhook|axios\.post/i, severity: 'high', category: 'data_exfiltration', description: 'Potential data exfiltration via fetch/XMLHttpRequest' },
  { pattern: /document\.cookie/i, severity: 'high', category: 'cookie_theft', description: 'JavaScript cookie access detected' },
  
  // Suspicious form fields (MEDIUM)
  { pattern: /<input[^>]*name=["'][^"']*(?:card|credit|kredit|bank|account|kontonummer)[^"']*["']/gi, severity: 'high', category: 'financial', description: 'Financial information form field' },
  { pattern: /<input[^>]*placeholder=["'][^"']*(?:ssn|social|passport|ausweis)[^"']*["']/gi, severity: 'high', category: 'identity_theft', description: 'Identity information placeholder' },
  
  // Fake CAPTCHA/Verification (HIGH)
  { pattern: /complete.?verification|verify.?human|captcha|recaptcha|hcaptcha/i, severity: 'medium', category: 'verification_bypass', description: 'CAPTCHA/Verification request' },
  
  // Additional indicators
  { pattern: /(?:click|klick|cliquez|haga.?clic).*(?:here|hier|ici|aquí)/i, severity: 'low', category: 'generic_suspicious', description: 'Generic click here link' },
  { pattern: /(?:urgent|dringend|urgente|urgente).*(?:action|maßnahme|action|acción)/i, severity: 'medium', category: 'urgency', description: 'Urgent action requested' },
  { pattern: /<!\[CDATA\[.*?\]\]>/gis, severity: 'low', category: 'obfuscation', description: 'CDATA obfuscation detected' },
  { pattern: /&#[xX]?[0-9a-fA-F]+;/g, severity: 'low', category: 'obfuscation', description: 'HTML entity obfuscation detected' }
];

// Discord Webhook Pattern (verbessert)
const WEBHOOK_PATTERN = /https?:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/gi;

// Bekannte bösartige Domain-Muster
const SUSPICIOUS_DOMAIN_PATTERNS = [
  { pattern: /verify|secure|account|login|signin|auth|authenticate|confirm|update|reactivate/i, weight: 5 },
  { pattern: /-auth-|-secure-|-login-|-verify-|-account-/i, weight: 8 },
  { pattern: /\.(?:xyz|top|club|live|online|site|website|click|link|support)$/i, weight: 4 },
  { pattern: /^\d+[a-z]/i, weight: 3 },
  { pattern: /(?:paypal|amazon|apple|microsoft|netflix).*(?:verify|secure|login)/i, weight: 10 }
];

// ==================== HILFSFUNKTIONEN ====================

function detectPhishingPatterns(html, url, domain) {
  const patterns = [];
  const lowerHtml = html.toLowerCase();
  const lowerUrl = url.toLowerCase();
  const lowerDomain = domain.toLowerCase();

  // Domain-basierte Erkennung
  for (const dp of SUSPICIOUS_DOMAIN_PATTERNS) {
    if (dp.pattern.test(lowerDomain) || dp.pattern.test(lowerUrl)) {
      patterns.push({
        pattern: `Suspicious domain pattern: "${dp.pattern.toString().slice(1, -1)}"`,
        severity: dp.weight >= 8 ? 'high' : (dp.weight >= 5 ? 'medium' : 'low'),
        location: 'URL/Domain',
        category: 'suspicious_domain',
        weight: dp.weight
      });
    }
  }

  // HTML-Pattern-Erkennung
  for (const p of PHISHING_PATTERNS) {
    const matches = html.match(p.pattern);
    if (matches && matches.length > 0) {
      patterns.push({
        pattern: p.description,
        severity: p.severity,
        location: 'HTML content',
        category: p.category,
        occurrences: matches.length
      });
    }
  }

  // Deduplizieren (gleiche patterns zusammenfassen)
  const uniquePatterns = [];
  const seen = new Set();
  for (const p of patterns) {
    const key = `${p.category}|${p.pattern}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniquePatterns.push(p);
    }
  }

  return uniquePatterns;
}

function detectWebhooks(html) {
  const matches = html.match(WEBHOOK_PATTERN) || [];
  const unique = [...new Set(matches)];
  return unique.map(url => ({ 
    url, 
    type: 'Discord Webhook',
    risk: 'critical'
  }));
}

function analyzeForms(html) {
  const formCount = (html.match(/<form/gi) || []).length;
  const passwordInputs = (html.match(/type=["']password["']/gi) || []).length;
  const emailInputs = (html.match(/type=["']email["']/gi) || []).length;
  const submitButtons = (html.match(/type=["']submit["']|button[^>]*submit/gi) || []).length;
  const actionMissing = (html.match(/<form[^>]*(?:action=["']\s*["']|action=["']#["'])/gi) || []).length;
  
  return {
    total: formCount,
    passwordFields: passwordInputs,
    emailFields: emailInputs,
    submitButtons: submitButtons,
    emptyActions: actionMissing,
    hasLoginForm: passwordInputs > 0 && (emailInputs > 0 || formCount > 0)
  };
}

function analyzeSuspiciousElements(html) {
  const results = {
    hiddenFields: 0,
    obfuscatedCode: false,
    externalScripts: 0,
    inlineEvents: 0
  };
  
  // Hidden input fields (oft für Datensammlung)
  results.hiddenFields = (html.match(/<input[^>]*type=["']hidden["']/gi) || []).length;
  
  // Obfuscated JavaScript (einfache Erkennung)
  results.obfuscatedCode = /eval\s*\(|atob\s*\(|String\.fromCharCode|\/\*.*\*\/.{50,}/i.test(html);
  
  // External scripts
  results.externalScripts = (html.match(/<script[^>]*src=["'][^"']+["']/gi) || []).length;
  
  // Inline event handlers (könnten für Keylogging sein)
  results.inlineEvents = (html.match(/on(?:click|load|submit|change|keypress|keydown|keyup)=/gi) || []).length;
  
  return results;
}

function calculateRiskScore(patterns, webhooks, formAnalysis, suspiciousElements) {
  let score = 0;
  
  // Patterns mit Gewichtung
  for (const p of patterns) {
    if (p.severity === 'high') score += 15;
    else if (p.severity === 'medium') score += 8;
    else score += 3;
    // Extra weight für mehrere Vorkommen
    if (p.occurrences && p.occurrences > 1) score += Math.min(p.occurrences * 2, 10);
  }
  
  // Webhooks -> extrem hohes Risiko (Datendiebstahl)
  score += webhooks.length * 35;
  
  // Formular-Analyse
  if (formAnalysis.hasLoginForm) score += 15;
  if (formAnalysis.passwordFields > 1) score += 5;
  if (formAnalysis.emptyActions > 0) score += 10;
  if (formAnalysis.total > 2) score += 5;
  
  // Verdächtige Elemente
  if (suspiciousElements.hiddenFields > 3) score += Math.min(suspiciousElements.hiddenFields * 2, 15);
  if (suspiciousElements.obfuscatedCode) score += 20;
  if (suspiciousElements.inlineEvents > 5) score += 10;
  
  return Math.min(100, score);
}

function getSourcePreview(html, maxLength = 8000) {
  // Entferne große Script-Blöcke für bessere Lesbarkeit
  let clean = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '[SCRIPT CONTENT REMOVED]');
  clean = clean.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '[STYLE CONTENT REMOVED]');
  
  if (clean.length <= maxLength) return clean;
  return clean.substring(0, maxLength) + '\n\n... [truncated - full source available for download]';
}

// ==================== VERBESSERTER GROQ PROMPT ====================

async function generateGroqReport(url, domain, patterns, webhooks, formAnalysis, suspiciousElements, riskScore) {
  if (!GROQ_API_KEY || GROQ_API_KEY === 'YOUR_GROQ_API_KEY_HERE') {
    return '⚠️ **Groq API key not configured**\n\nPlease add `GROQ_API_KEY` to your environment variables to enable AI-powered analysis.';
  }

  // Klassifiziere Patterns nach Schweregrad
  const highRiskPatterns = patterns.filter(p => p.severity === 'high');
  const mediumRiskPatterns = patterns.filter(p => p.severity === 'medium');
  const lowRiskPatterns = patterns.filter(p => p.severity === 'low');
  
  const patternSummary = {
    high: highRiskPatterns.slice(0, 8).map(p => `🔴 **${p.pattern}**`).join('\n'),
    medium: mediumRiskPatterns.slice(0, 6).map(p => `🟡 ${p.pattern}`).join('\n'),
    low: lowRiskPatterns.slice(0, 4).map(p => `🟢 ${p.pattern}`).join('\n')
  };
  
  const webhookSummary = webhooks.length > 0 
    ? `⚠️ **CRITICAL**: ${webhooks.length} Discord webhook(s) detected!\n   ${webhooks.map(w => `   - ${w.url}`).join('\n')}\n   > These can be used to steal submitted data in real-time.`
    : '✅ No Discord webhooks detected.';

  const formSummary = formAnalysis.hasLoginForm
    ? `⚠️ Login form detected (${formAnalysis.passwordFields} password field(s), ${formAnalysis.emailFields} email field(s))`
    : 'ℹ️ No login forms detected.';
  
  if (formAnalysis.emptyActions > 0) {
    formSummary += `\n   ⚠️ ${formAnalysis.emptyActions} form(s) have empty/missing action attributes (data may be sent to same page)`;
  }

  const suspiciousSummary = [];
  if (suspiciousElements.hiddenFields > 0) {
    suspiciousSummary.push(`- ${suspiciousElements.hiddenFields} hidden input field(s) detected`);
  }
  if (suspiciousElements.obfuscatedCode) {
    suspiciousSummary.push('- Obfuscated JavaScript detected (potential evasion technique)');
  }
  if (suspiciousElements.inlineEvents > 10) {
    suspiciousSummary.push(`- ${suspiciousElements.inlineEvents} inline event handlers (potential keylogging risk)`);
  }

  const riskLevel = riskScore >= 70 ? 'CRITICAL' : (riskScore >= 40 ? 'WARNING' : 'LOW');
  const riskEmoji = riskScore >= 70 ? '🔴' : (riskScore >= 40 ? '🟡' : '🟢');

  const prompt = `You are a senior cybersecurity analyst specializing in phishing detection. Analyze the following website scan results.

${riskEmoji} **RISK ASSESSMENT: ${riskLevel} (${riskScore}/100)**

**Target:** ${url}
**Domain:** ${domain}

**DETECTED PATTERNS:**
${patternSummary.high || 'No high-risk patterns detected.'}
${patternSummary.medium ? '\n' + patternSummary.medium : ''}
${patternSummary.low ? '\n' + patternSummary.low : ''}

**FORMS ANALYSIS:**
${formSummary}

**SUSPICIOUS ELEMENTS:**
${suspiciousSummary.length > 0 ? suspiciousSummary.join('\n') : 'No additional suspicious elements detected.'}

${webhookSummary}

Please provide a professional cybersecurity assessment (350-500 words) with:

1. **Executive Summary** - Clear verdict (Phishing / Suspicious / Legitimate)
2. **Technical Analysis** - Explain the key indicators found
3. **Attack Vector** - How would an attacker use this page?
4. **User Recommendations** - Specific actions for potential victims
5. **URL Safety Status** - Final recommendation (Block / Caution / Safe)

Be concise, specific, and actionable. Use markdown formatting for readability.`;

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
            content: 'You are an expert cybersecurity phishing analyst. Provide clear, actionable, and professional threat assessments. Always prioritize user safety. Use markdown formatting with headers, bullet points, and clear section breaks.' 
          },
          { role: 'user', content: prompt }
        ],
        temperature: 0.2,
        max_tokens: 1200
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Groq API error:', response.status, errorText);
      return `⚠️ **AI Analysis Temporarily Unavailable**\n\nError: HTTP ${response.status}\n\nPlease try again later or check your API configuration.`;
    }

    const data = await response.json();
    let report = data.choices[0].message.content;
    
    // Füge Risiko-Badge am Anfang hinzu, falls nicht vorhanden
    if (!report.includes('RISK ASSESSMENT') && !report.includes('Verdict')) {
      const riskBadge = riskScore >= 70 ? '🔴 **CRITICAL PHISHING RISK**' : (riskScore >= 40 ? '🟡 **SUSPICIOUS - CAUTION ADVISED**' : '🟢 **LOW RISK - PROCEED WITH CAUTION**');
      report = `${riskBadge}\n\n${report}`;
    }
    
    return report;
    
  } catch (error) {
    console.error('Groq API error:', error);
    return `⚠️ **AI Analysis Unavailable**\n\nError: ${error.message}\n\nPlease ensure your Groq API key is valid and try again.`;
  }
}

// ==================== MAIN HANDLER ====================

export default async function handler(req, res) {
  // CORS-Header
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
    return res.status(400).json({ success: false, error: 'Missing or invalid "url" parameter.' });
  }

  // Validierung der URL
  let urlObj;
  try {
    urlObj = new URL(targetUrl);
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      throw new Error('Only HTTP/HTTPS URLs are allowed');
    }
  } catch (e) {
    return res.status(400).json({ success: false, error: `Invalid URL: ${e.message}` });
  }

  console.log(`[Scan] Starting scan for: ${targetUrl}`);

  try {
    // Fetch mit Timeout und spezifischen Headern
    const fetchResponse = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache'
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(20000) // 20 Sekunden Timeout
    });

    if (!fetchResponse.ok) {
      console.log(`[Scan] HTTP ${fetchResponse.status} for ${targetUrl}`);
      return res.status(200).json({
        success: true,
        url: targetUrl,
        domain: urlObj.hostname,
        riskScore: 75,
        patterns: [{
          pattern: `HTTP ${fetchResponse.status} - Page returned error status`,
          severity: 'high',
          location: 'HTTP response',
          category: 'error_page'
        }],
        webhooks: [],
        loginForms: 0,
        sizeKB: 0,
        groqReport: `⚠️ **Page inaccessible**\n\nThe target URL returned HTTP ${fetchResponse.status}. This could indicate:\n- The page is temporarily down\n- The server is blocking automated requests\n- The URL is invalid or has been taken down\n\n**Recommendation:** Verify the URL manually before proceeding.`,
        sourcePreview: '',
        formAnalysis: { hasLoginForm: false, total: 0, passwordFields: 0 },
        suspiciousElements: { hiddenFields: 0, obfuscatedCode: false, inlineEvents: 0 }
      });
    }

    const contentType = fetchResponse.headers.get('content-type') || '';
    if (!contentType.includes('text/html')) {
      console.log(`[Scan] Non-HTML content: ${contentType} for ${targetUrl}`);
      return res.status(200).json({
        success: true,
        url: targetUrl,
        domain: urlObj.hostname,
        riskScore: 50,
        patterns: [{
          pattern: `Non-HTML content (${contentType.split(';')[0]}) - not a standard webpage`,
          severity: 'medium',
          location: 'HTTP headers',
          category: 'unusual_content'
        }],
        webhooks: [],
        loginForms: 0,
        sizeKB: 0,
        groqReport: `ℹ️ **Not a standard webpage**\n\nThe URL returned content type: ${contentType.split(';')[0]}\n\nThis is not an HTML page, so phishing analysis is limited. If you meant to scan a webpage, please check the URL.`,
        sourcePreview: '',
        formAnalysis: { hasLoginForm: false, total: 0, passwordFields: 0 },
        suspiciousElements: { hiddenFields: 0, obfuscatedCode: false, inlineEvents: 0 }
      });
    }

    const html = await fetchResponse.text();
    const sizeKB = (html.length / 1024).toFixed(1);
    
    console.log(`[Scan] Fetched ${sizeKB}KB from ${targetUrl}`);

    // Analysen durchführen
    const patterns = detectPhishingPatterns(html, targetUrl, urlObj.hostname);
    const webhooks = detectWebhooks(html);
    const formAnalysis = analyzeForms(html);
    const suspiciousElements = analyzeSuspiciousElements(html);
    const riskScore = calculateRiskScore(patterns, webhooks, formAnalysis, suspiciousElements);
    
    console.log(`[Scan] Risk score: ${riskScore} (${patterns.length} patterns, ${webhooks.length} webhooks)`);

    // AI Report generieren (asynchron, aber wir warten darauf)
    const groqReport = await generateGroqReport(
      targetUrl, 
      urlObj.hostname, 
      patterns, 
      webhooks, 
      formAnalysis, 
      suspiciousElements, 
      riskScore
    );
    
    const sourcePreview = getSourcePreview(html);
    
    // Login-Formular-Zähler für die Statistik
    const loginForms = formAnalysis.hasLoginForm ? formAnalysis.total : 0;

    return res.status(200).json({
      success: true,
      url: targetUrl,
      domain: urlObj.hostname,
      riskScore: riskScore,
      patterns: patterns.slice(0, 40),
      webhooks: webhooks,
      loginForms: loginForms,
      sizeKB: sizeKB,
      groqReport: groqReport,
      sourcePreview: sourcePreview,
      formAnalysis: {
        hasLoginForm: formAnalysis.hasLoginForm,
        total: formAnalysis.total,
        passwordFields: formAnalysis.passwordFields
      },
      suspiciousElements: {
        hiddenFields: suspiciousElements.hiddenFields,
        obfuscatedCode: suspiciousElements.obfuscatedCode,
        inlineEvents: suspiciousElements.inlineEvents
      }
    });

  } catch (error) {
    console.error(`[Scan] Error for ${targetUrl}:`, error.message);
    
    // Detailliertere Fehlerbehandlung
    let errorMessage = error.message;
    let riskScore = 70;
    let patterns = [];
    
    if (error.name === 'AbortError' || error.message.includes('timeout')) {
      errorMessage = 'Request timeout - The server took too long to respond.';
      patterns.push({
        pattern: 'Timeout - Server unresponsive or very slow',
        severity: 'medium',
        location: 'Network',
        category: 'timeout'
      });
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('getaddrinfo')) {
      errorMessage = 'DNS resolution failed - The domain could not be found.';
      patterns.push({
        pattern: 'Invalid or non-existent domain',
        severity: 'medium',
        location: 'DNS',
        category: 'invalid_domain'
      });
    } else if (error.message.includes('ECONNREFUSED')) {
      errorMessage = 'Connection refused - The server is not accepting connections.';
      patterns.push({
        pattern: 'Server offline or blocking requests',
        severity: 'medium',
        location: 'Network',
        category: 'connection_error'
      });
    } else if (error.message.includes('CERT') || error.message.includes('SSL') || error.message.includes('certificate')) {
      errorMessage = 'SSL/TLS certificate error - The site may have an invalid security certificate.';
      patterns.push({
        pattern: 'Invalid SSL certificate - Potential security risk',
        severity: 'high',
        location: 'TLS',
        category: 'certificate_error'
      });
      riskScore = 85;
    }
    
    return res.status(200).json({
      success: false,
      error: errorMessage,
      url: targetUrl,
      domain: urlObj.hostname,
      riskScore: riskScore,
      patterns: patterns,
      webhooks: [],
      loginForms: 0,
      sizeKB: 0,
      groqReport: `⚠️ **Scan Failed**\n\nCould not complete the scan: ${errorMessage}\n\n**Possible reasons:**\n- The website is temporarily down\n- The server is blocking automated requests\n- Network connectivity issues\n- Invalid SSL certificate\n\n**Recommendation:** Try the URL manually in your browser to verify its status.`,
      sourcePreview: ''
    });
  }
}