// api/scan.js - AI-Powered Phishing Scanner (No manual whitelist)

const GROQ_API_KEY = process.env.GROQ_API_KEY || 'YOUR_GROQ_API_KEY_HERE';

// ==================== BASIC PATTERNS (initial risk estimation) ====================

const PHISHING_PATTERNS = [
  { pattern: /<input[^>]*type=["']password["']/gi, severity: 'medium', category: 'password_field', description: 'Password input field' },
  { pattern: /credit.?card|kreditkarte/i, severity: 'high', category: 'financial', description: 'Credit card request' },
  { pattern: /cvv|cvc|security.?code/i, severity: 'high', category: 'financial', description: 'CVV code request' },
  { pattern: /ssn|social.?security|sozialversicherung/i, severity: 'high', category: 'identity', description: 'SSN/National ID request' },
  { pattern: /account.*suspended|gesperrt|suspendu/i, severity: 'high', category: 'scare', description: 'Account suspension threat' },
  { pattern: /verify.*identity|identität.*bestätigen/i, severity: 'high', category: 'scare', description: 'Identity verification request' },
  { pattern: /bitcoin|ethereum|crypto|wallet.*connect/i, severity: 'high', category: 'crypto', description: 'Cryptocurrency request' },
  { pattern: /window\.location|location\.href|location\.replace/i, severity: 'low', category: 'redirect', description: 'JavaScript redirect' },
  { pattern: /document\.cookie/i, severity: 'medium', category: 'cookie', description: 'Cookie access' },
  { pattern: /https?:\/\/discord\.com\/api\/webhooks\//i, severity: 'critical', category: 'webhook', description: 'Discord webhook found' }
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
  let clean = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '[SCRIPT REMOVED]');
  clean = clean.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '[STYLE REMOVED]');
  
  if (clean.length <= maxLength) return clean;
  return clean.substring(0, maxLength) + '\n\n... [truncated]';
}

// ==================== AI-POWERED ANALYSIS (Main logic) ====================

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
      report: `⚠️ **AI not configured**\n\nPlease add GROQ_API_KEY to your environment variables.\n\nPatterns found: ${basicPatterns.length}\nWebhooks: ${webhooks.length}\nLogin forms: ${formAnalysis.hasLoginForm ? 'Yes' : 'No'}`,
      shortReason: 'AI analysis unavailable',
      userWarning: riskScore > 50 ? 'Proceed with caution' : 'No immediate warnings'
    };
  }

  // Prepare pattern summary for AI
  const patternSummary = basicPatterns.map(p => `- ${p.description} (${p.severity})`).join('\n') || 'No suspicious patterns found.';
  const webhookSummary = webhooks.length > 0 ? webhooks.map(w => `- ${w}`).join('\n') : 'None';
  
  const prompt = `You are a phishing detection expert. Analyze this website:

URL: ${url}
Domain: ${domain}
HTTP Status: ${httpStatus}

**Technical indicators:**
- Login form: ${formAnalysis.hasLoginForm ? 'Yes' : 'No'}
- Password fields: ${formAnalysis.passwordFields}
- Email fields: ${formAnalysis.emailFields}
- Forms with empty actions: ${formAnalysis.emptyActions}
- Discord webhooks: ${webhooks.length > 0 ? 'YES (CRITICAL)' : 'No'}

**Patterns found:**
${patternSummary}

**CRITICAL RULES for your analysis:**
1. YouTube, Google, Facebook, Amazon, Microsoft, Apple, Netflix, Spotify, Twitter, Instagram, LinkedIn, Wikipedia, Reddit, Twitch, PayPal, eBay, GitHub are LEGITIMATE websites (not phishing)
2. Banks like Sparkasse, Deutsche Bank, Commerzbank, ING, DKB, N26, PayPal are LEGITIMATE
3. Known tech sites like Vercel, Netlify, Cloudflare, GitHub are LEGITIMATE
4. Phishing sites are usually unknown domains with login copies asking for passwords, credit cards, or SSN
5. A login form alone does NOT make a phishing site - many legitimate sites have logins
6. Discord webhooks are a CRITICAL sign of phishing/data theft

**Respond ONLY with valid JSON in this format (no other text):**
{
  "riskScore": (number 0-100, 0 = safe, 100 = critical phishing),
  "verdict": "PHISHING | SUSPICIOUS | LEGITIMATE",
  "isLegitimate": true/false,
  "shortReason": "Brief explanation (max 100 characters)",
  "userWarning": "What the user should do (max 150 characters)"
}`;

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
            content: 'You are a phishing detection expert. Respond ONLY with valid JSON, no other text. Recognize known legitimate websites and give riskScore 0 for YouTube, Google, etc.' 
          },
          { role: 'user', content: prompt }
        ],
        temperature: 0.1,
        max_tokens: 300
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const aiResponse = data.choices[0].message.content;
    
    // Extract JSON (in case AI adds extra text)
    let jsonStr = aiResponse;
    const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
    if (jsonMatch) jsonStr = jsonMatch[0];
    
    const aiResult = JSON.parse(jsonStr);
    
    // Validate response
    const riskScore = Math.min(100, Math.max(0, aiResult.riskScore || 50));
    const isLegitimate = aiResult.isLegitimate === true || aiResult.verdict === 'LEGITIMATE';
    const verdict = aiResult.verdict || (isLegitimate ? 'LEGITIMATE' : (riskScore > 60 ? 'PHISHING' : 'SUSPICIOUS'));
    
    // Generate readable report
    const report = generateReadableReport(url, domain, riskScore, verdict, aiResult.shortReason, aiResult.userWarning, basicPatterns, webhooks, formAnalysis);
    
    return {
      riskScore: riskScore,
      verdict: verdict,
      isLegitimate: isLegitimate,
      shortReason: aiResult.shortReason || (isLegitimate ? 'Known legitimate website' : 'Suspicious indicators found'),
      userWarning: aiResult.userWarning || (isLegitimate ? 'No action needed' : 'Do not enter any personal information'),
      report: report
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
      shortReason: 'AI analysis temporarily unavailable',
      userWarning: riskScore > 50 ? 'Proceed with caution' : 'No immediate warnings',
      report: generateReadableReport(url, domain, riskScore, riskScore > 60 ? 'SUSPICIOUS' : 'SAFE', null, null, basicPatterns, webhooks, formAnalysis)
    };
  }
}

function generateReadableReport(url, domain, riskScore, verdict, shortReason, userWarning, patterns, webhooks, formAnalysis) {
  const riskEmoji = riskScore >= 70 ? '🔴' : (riskScore >= 40 ? '🟡' : '🟢');
  const verdictText = verdict === 'PHISHING' ? '⚠️ PHISHING SUSPECTED' : (verdict === 'SUSPICIOUS' ? '⚠️ SUSPICIOUS' : '✅ LEGITIMATE');
  
  let report = `${riskEmoji} **${verdictText}** (Risk: ${riskScore}/100)\n\n`;
  report += `**URL:** ${url}\n`;
  report += `**Domain:** ${domain}\n\n`;
  
  if (shortReason) {
    report += `**Analysis:** ${shortReason}\n\n`;
  }
  
  if (patterns.length > 0) {
    report += `**Detected Patterns:**\n`;
    patterns.forEach(p => {
      const emoji = p.severity === 'critical' ? '🔴' : (p.severity === 'high' ? '🟠' : (p.severity === 'medium' ? '🟡' : '🔵'));
      report += `- ${emoji} ${p.description}\n`;
    });
    report += `\n`;
  }
  
  if (webhooks.length > 0) {
    report += `🔴 **CRITICAL WARNING:** ${webhooks.length} Discord webhook(s) found!\n   → Data could be sent to attackers\n\n`;
  }
  
  if (formAnalysis.hasLoginForm) {
    report += `ℹ️ Login form detected (${formAnalysis.passwordFields} password field(s))\n\n`;
  }
  
  if (userWarning) {
    report += `**Recommendation:** ${userWarning}\n`;
  } else if (riskScore >= 70) {
    report += `**Recommendation:** DO NOT use this site! Do not enter any data. Close the page.\n`;
  } else if (riskScore >= 40) {
    report += `**Recommendation:** Proceed with caution. Only use if you are absolutely sure about this site.\n`;
  } else {
    report += `**Recommendation:** No immediate warnings. Normal caution is sufficient.\n`;
  }
  
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

  console.log(`[Scan] Target: ${targetUrl}`);

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
    
    console.log(`[Scan] Fetched ${sizeKB}KB, HTTP ${httpStatus}`);

    // Basic pattern detection
    const basicPatterns = detectBasicPatterns(html);
    const webhooks = detectWebhooks(html);
    const formAnalysis = analyzeForms(html);
    
    console.log(`[Scan] Basic patterns: ${basicPatterns.length}, Webhooks: ${webhooks.length}`);

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
      formAnalysis: {
        hasLoginForm: formAnalysis.hasLoginForm,
        total: formAnalysis.total,
        passwordFields: formAnalysis.passwordFields
      }
    });

  } catch (error) {
    console.error(`[Scan] Error:`, error.message);
    
    return res.status(200).json({
      success: false,
      error: error.message,
      url: targetUrl,
      domain: urlObj.hostname,
      riskScore: 50,
      verdict: 'ERROR',
      isLegitimate: false,
      patterns: [],
      webhooks: [],
      loginForms: 0,
      sizeKB: 0,
      groqReport: `⚠️ **Scan Failed**\n\nCould not complete the scan: ${error.message}\n\nPossible reasons:\n- Website is temporarily down\n- Server is blocking automated requests\n- Network connectivity issues\n\n**Recommendation:** Try the URL manually in your browser.`,
      sourcePreview: ''
    });
  }
}
