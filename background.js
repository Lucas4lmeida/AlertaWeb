// ============================================================================
// AlertaWeb — Background Service Worker (AUDITED)
// Motor de análise principal com verificações multi-camada
// ============================================================================

'use strict';

const CONFIG = {
  CACHE_DURATION_MS: 30 * 60 * 1000,
  RISK_THRESHOLDS: { LOW: 25, MEDIUM: 50, HIGH: 75, CRITICAL: 90 },
  // FIX #2: Retry config para injeção de content script
  INJECT_RETRIES: 3,
  INJECT_RETRY_DELAY_MS: 400
};

// FIX #1: Cache agora usa chrome.storage.session (persiste enquanto o browser está aberto,
// ao contrário do Map que morria com o Service Worker a cada ~30s de inatividade no MV3)
async function getCachedAnalysis(url) {
  try {
    const data = await chrome.storage.session.get(url);
    const cached = data[url];
    if (cached && (Date.now() - cached.timestamp < CONFIG.CACHE_DURATION_MS)) {
      return cached.result;
    }
    return null;
  } catch {
    return null;
  }
}

async function setCachedAnalysis(url, result) {
  try {
    await chrome.storage.session.set({ [url]: { result, timestamp: Date.now() } });
  } catch { /* session storage indisponível ou cheio */ }
}

// ============================================================================
// INICIALIZAÇÃO
// ============================================================================

// FIX #4: Só inicializa settings na PRIMEIRA instalação
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.storage.local.set({
      settings: {
        autoAnalyze: false,
        showNotifications: true,
        apiKeys: { whois: '', safeBrowsing: '', gemini: '', virusTotal: '' }
      },
      history: []
    });
  }
});

// ============================================================================
// LISTENER DE MENSAGENS
// ============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeTab') {
    handleAnalysis(request.tabId, request.forceReanalyze)
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (request.action === 'getSettings') {
    chrome.storage.local.get('settings', (data) => {
      sendResponse({ success: true, settings: data.settings || {} });
    });
    return true;
  }

  if (request.action === 'saveSettings') {
    chrome.storage.local.set({ settings: request.settings }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (request.action === 'getHistory') {
    chrome.storage.local.get('history', (data) => {
      sendResponse({ success: true, history: data.history || [] });
    });
    return true;
  }

  if (request.action === 'clearHistory') {
    chrome.storage.local.set({ history: [] }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (request.action === 'getCachedResult') {
    getCachedAnalysis(request.url).then(result => {
      if (result) sendResponse({ success: true, result });
      else sendResponse({ success: false });
    });
    return true;
  }
});

// ============================================================================
// ANÁLISE PRINCIPAL
// ============================================================================

async function handleAnalysis(tabId, forceReanalyze = false) {
  const settings = await getSettings();
  const apiKeys = settings.apiKeys || {};
  const pageData = await extractPageDataFromTab(tabId);

  if (!pageData || !pageData.url) {
    throw new Error('Não foi possível extrair dados da página.');
  }

  // Cache: pular se forceReanalyze
  if (!forceReanalyze) {
    const cached = await getCachedAnalysis(pageData.url);
    if (cached) return cached;
  }

  // ====== WHITELIST: domínios inquestionavelmente legítimos ======
  const domainInfo = classifyDomain(pageData.domain);

  if (domainInfo.whitelisted) {
    const result = {
      url: pageData.url, domain: pageData.domain, title: pageData.title,
      score: 0, riskLevel: 'safe',
      riskLabel: 'SEGURO — Site Confiável',
      riskColor: '#16a34a',
      findings: [{ severity: 'positive', message: `Domínio "${pageData.domain}" é reconhecido como site legítimo e confiável.` }],
      aiSummary: null, aiRecommendation: null,
      breakdown: { url: 0, content: 0, domain: 0, security: 0, forms: 0, external: 0, virusTotal: 0, ai: 0 },
      timestamp: Date.now()
    };
    await setCachedAnalysis(pageData.url, result);
    saveToHistory(result);
    return result;
  }

  // Passar flags de contexto para as análises
  pageData._context = {
    isUGC: domainInfo.isUGC,             // conteúdo gerado por usuários
    isCommercial: domainInfo.isCommercial // parece site comercial
  };

  const [
    urlAnalysis, contentAnalysis, domainAnalysis, securityAnalysis,
    formAnalysis, externalChecks, virusTotalCheck, aiAnalysis
  ] = await Promise.allSettled([
    analyzeURL(pageData),
    analyzeContent(pageData),
    analyzeDomain(pageData, apiKeys),
    analyzeSecurity(pageData),
    analyzeForms(pageData),
    runExternalChecks(pageData, apiKeys),
    runVirusTotalCheck(pageData, apiKeys),
    runAIAnalysis(pageData, apiKeys)
  ]);

  const result = consolidateResults({
    url: pageData.url,
    domain: pageData.domain,
    title: pageData.title,
    urlAnalysis: getSettledValue(urlAnalysis),
    contentAnalysis: getSettledValue(contentAnalysis),
    domainAnalysis: getSettledValue(domainAnalysis),
    securityAnalysis: getSettledValue(securityAnalysis),
    formAnalysis: getSettledValue(formAnalysis),
    externalChecks: getSettledValue(externalChecks),
    virusTotalCheck: getSettledValue(virusTotalCheck),
    aiAnalysis: getSettledValue(aiAnalysis),
    timestamp: Date.now()
  });

  await setCachedAnalysis(pageData.url, result);
  saveToHistory(result);
  return result;
}

function getSettledValue(settled) {
  return settled.status === 'fulfilled' ? settled.value : { error: settled.reason?.message || 'Falha na análise' };
}

// ============================================================================
// CLASSIFICAÇÃO DE DOMÍNIO (Whitelist + UGC + Comercial)
// ============================================================================

function classifyDomain(domain) {
  const d = domain.toLowerCase();

  // Whitelist: domínios inquestionavelmente legítimos
  // Usa endsWith para cobrir subdomínios (web.whatsapp.com, mail.google.com, etc.)
  const WHITELIST = [
    // Google
    'google.com', 'google.com.br', 'gmail.com', 'youtube.com', 'googleapis.com',
    'googlesyndication.com', 'google.co', 'gstatic.com', 'googleusercontent.com',
    // Meta
    'facebook.com', 'instagram.com', 'whatsapp.com', 'whatsapp.net', 'messenger.com',
    'meta.com', 'threads.net', 'fb.com',
    // Microsoft
    'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'bing.com',
    'linkedin.com', 'github.com', 'azure.com', 'windows.com', 'xbox.com',
    // Apple
    'apple.com', 'icloud.com',
    // Amazon
    'amazon.com', 'amazon.com.br', 'aws.amazon.com', 'amazonaws.com',
    // Plataformas
    'twitter.com', 'x.com', 'reddit.com', 'wikipedia.org', 'wikimedia.org',
    'stackoverflow.com', 'stackexchange.com', 'discord.com', 'discord.gg',
    'twitch.tv', 'netflix.com', 'spotify.com', 'pinterest.com', 'tiktok.com',
    'zoom.us', 'dropbox.com', 'notion.so', 'figma.com', 'canva.com',
    'telegram.org', 'web.telegram.org', 'signal.org',
    // Bancos BR
    'bb.com.br', 'itau.com.br', 'bradesco.com.br', 'santander.com.br',
    'caixa.gov.br', 'nubank.com.br', 'inter.co', 'c6bank.com.br',
    'bancooriginal.com.br', 'safra.com.br', 'sicredi.com.br', 'sicoob.com.br',
    'mercadopago.com.br', 'pagseguro.uol.com.br', 'picpay.com',
    // Gov BR
    'gov.br', 'receita.fazenda.gov.br', 'detran.se.gov.br',
    // E-commerce BR
    'mercadolivre.com.br', 'magazineluiza.com.br', 'americanas.com.br',
    'casasbahia.com.br', 'shopee.com.br', 'aliexpress.com',
    'amazon.com.br', 'submarino.com.br', 'kabum.com.br',
    // Outros confiáveis
    'paypal.com', 'stripe.com', 'cloudflare.com', 'vercel.app',
    'netlify.app', 'heroku.com', 'ebay.com', 'walmart.com',
    'claude.ai', 'anthropic.com', 'openai.com', 'chatgpt.com'
  ];

  // Domínios com conteúdo gerado por usuários (não analisar texto)
  const UGC_DOMAINS = [
    'whatsapp.com', 'whatsapp.net', 'messenger.com', 'telegram.org',
    'web.telegram.org', 'discord.com', 'signal.org',
    'gmail.com', 'outlook.com', 'mail.google.com', 'mail.yahoo.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'reddit.com', 'tiktok.com', 'youtube.com', 'twitch.tv',
    'linkedin.com', 'pinterest.com', 'threads.net',
    'stackoverflow.com', 'stackexchange.com', 'github.com',
    'quora.com', 'medium.com'
  ];

  const isWhitelisted = WHITELIST.some(w => d === w || d.endsWith('.' + w));
  const isUGC = UGC_DOMAINS.some(u => d === u || d.endsWith('.' + u));

  return {
    whitelisted: isWhitelisted,
    isUGC,
    isCommercial: false // será detectado pela análise de conteúdo
  };
}

// ============================================================================
// EXTRAÇÃO DE DADOS DA PÁGINA
// ============================================================================

// FIX #2: Retry pattern substituindo setTimeout frágil
async function extractPageDataFromTab(tabId) {
  // Tentar enviar mensagem ao content script já injetado
  try {
    const response = await sendMessageToTab(tabId, { action: 'extractPageData' });
    if (response?.success) return response.data;
  } catch {
    // Content script não está injetado — injetar agora
  }

  // Injetar e tentar novamente com retries
  await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });

  for (let attempt = 0; attempt < CONFIG.INJECT_RETRIES; attempt++) {
    await sleep(CONFIG.INJECT_RETRY_DELAY_MS);
    try {
      const response = await sendMessageToTab(tabId, { action: 'extractPageData' });
      if (response?.success) return response.data;
    } catch {
      // Retry
    }
  }

  throw new Error('Falha ao extrair dados da página após múltiplas tentativas.');
}

function sendMessageToTab(tabId, message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(response);
    });
  });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// ANÁLISE DE URL
// ============================================================================

function analyzeURL(pageData) {
  const findings = [];
  let score = 0;
  const url = pageData.url;
  const domain = pageData.domain;

  // FIX #12: Score HTTP REMOVIDO daqui — está apenas em analyzeSecurity para evitar duplicação
  // (antes: +20 aqui E +20 em analyzeSecurity = 40 pontos pela mesma coisa)

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    findings.push({ severity: 'high', message: 'URL usa endereço IP numérico ao invés de domínio — comportamento incomum.' });
    score += 25;
  }

  const suspiciousTLDs = ['.xyz', '.top', '.work', '.click', '.link', '.buzz', '.gq', '.ml', '.cf', '.tk', '.ga', '.icu', '.cam', '.rest', '.monster'];
  const tld = '.' + domain.split('.').pop();
  if (suspiciousTLDs.includes(tld)) {
    findings.push({ severity: 'medium', message: `Domínio usa TLD "${tld}" — frequentemente associado a sites fraudulentos.` });
    score += 15;
  }

  if (domain.length > 40) {
    findings.push({ severity: 'medium', message: 'Domínio excessivamente longo — pode ser tentativa de disfarçar URL real.' });
    score += 10;
  }

  const subdomains = domain.split('.').length - 2;
  if (subdomains > 2) {
    findings.push({ severity: 'medium', message: `Domínio com ${subdomains} subdomínios — pode ser tentativa de imitar site legítimo.` });
    score += 10;
  }

  if (url.includes('@') || (url.includes('//') && url.indexOf('//', 8) > 0)) {
    findings.push({ severity: 'high', message: 'URL contém caracteres usados em ataques de phishing ("@" ou "//" duplo).' });
    score += 20;
  }

  if (url.length > 200) {
    findings.push({ severity: 'low', message: 'URL excessivamente longa — pode conter parâmetros de rastreamento ou ofuscação.' });
    score += 5;
  }

  if (pageData.suspiciousPatterns.domainTyposquatting.detected) {
    const brands = pageData.suspiciousPatterns.domainTyposquatting.brands;
    findings.push({
      severity: 'critical',
      message: `Domínio parece imitar marca(s) conhecida(s): ${brands.join(', ')}. Possível typosquatting/phishing.`
    });
    score += 35;
  }

  const hyphenCount = domain.split('-').length - 1;
  if (hyphenCount >= 3) {
    findings.push({ severity: 'medium', message: `Domínio com ${hyphenCount} hífens — padrão incomum para sites legítimos.` });
    score += 10;
  }

  if (/\d{4,}/.test(domain.split('.')[0])) {
    findings.push({ severity: 'low', message: 'Domínio contém sequência numérica longa — pode indicar site temporário.' });
    score += 8;
  }

  return { score: Math.min(score, 100), findings };
}

// ============================================================================
// ANÁLISE DE CONTEÚDO
// ============================================================================

function analyzeContent(pageData) {
  const findings = [];
  let score = 0;
  const isUGC = pageData._context?.isUGC || false;

  // Em sites UGC (WhatsApp, Gmail, Reddit, etc.) o texto visível é de OUTROS
  // usuários, não do site. Analisar esse texto gera falsos positivos.
  if (isUGC) {
    findings.push({ severity: 'info', message: 'Plataforma de conteúdo de usuários — análise textual limitada (texto é de terceiros).' });
    // Pular TODA análise baseada em texto, manter apenas análise estrutural
  } else {
    // Análise textual: só para sites onde o conteúdo É do site
    const urgency = pageData.text.hasUrgencyLanguage;
    if (urgency.detected) {
      const level = urgency.count >= 5 ? 'high' : urgency.count >= 2 ? 'medium' : 'low';
      findings.push({
        severity: level,
        message: `${urgency.count} termos de urgência/pressão detectados: "${urgency.terms.slice(0, 3).join('", "')}".`
      });
      score += Math.min(urgency.count * 5, 25);
    }

    const guarantees = pageData.text.hasGuaranteePatterns;
    if (guarantees.detected) {
      findings.push({
        severity: guarantees.count >= 3 ? 'high' : 'medium',
        message: `${guarantees.count} promessas/garantias exageradas encontradas: "${guarantees.terms.slice(0, 3).join('", "')}".`
      });
      score += Math.min(guarantees.count * 6, 20);
    }

    const prices = pageData.text.hasPricePatterns;
    if (prices.hugDiscount > 0) {
      findings.push({ severity: 'medium', message: `${prices.hugDiscount} menções a descontos enormes — tática comum de golpes.` });
      score += 10;
    }
    if (prices.cryptocurrency > 0) {
      findings.push({ severity: 'medium', message: 'Menções a criptomoedas detectadas — verifique a legitimidade.' });
      score += 8;
    }
    if (prices.gamblingMultiplier > 0) {
      findings.push({ severity: 'high', message: `${prices.gamblingMultiplier} padrão(ões) de multiplicador/ganho de BET detectado(s).` });
      score += 15;
    }

    // Detecção de BET: só em sites não-UGC
    const gamblingResult = detectGamblingScam(pageData);
    if (gamblingResult.detected) {
      findings.push({ severity: gamblingResult.severity, message: gamblingResult.message });
      score += gamblingResult.score;
      if (gamblingResult.details.length > 0) {
        findings.push({
          severity: 'info',
          message: `Sinais de BET/apostas: ${gamblingResult.details.join(', ')}.`
        });
      }
    }
  }

  // Análise estrutural: aplica a todos os sites (UGC ou não)
  if (pageData.text.length < 200 && !isUGC) {
    findings.push({ severity: 'low', message: 'Página com muito pouco conteúdo textual.' });
    score += 5;
  }

  if (pageData.suspiciousPatterns.hasCountdownTimers && !isUGC) {
    findings.push({ severity: 'medium', message: 'Timer de contagem regressiva detectado — pressão psicológica para decisão rápida.' });
    score += 12;
  }

  // Heurísticas de "ausência": só penalizar fortemente se o site parecer comercial
  // Detectar se parece comercial pelo texto
  const textLower = (pageData.text.sample || '').toLowerCase();
  const looksCommercial = /comprar|adicionar ao carrinho|add to cart|checkout|finalizar pedido|frete|shipping|R\$\s*\d|price|\$\s*\d/i.test(textLower);

  if (!pageData.suspiciousPatterns.hasLegalPages) {
    if (looksCommercial) {
      findings.push({ severity: 'medium', message: 'Site comercial sem links para política de privacidade ou termos de uso.' });
      score += 10;
    } else if (!isUGC) {
      findings.push({ severity: 'low', message: 'Sem links visíveis para política de privacidade ou termos de uso.' });
      score += 3;
    }
  }

  if (!pageData.suspiciousPatterns.hasPhysicalAddress && looksCommercial) {
    findings.push({ severity: 'medium', message: 'Site comercial sem endereço físico ou CNPJ.' });
    score += 8;
  }

  if (!pageData.suspiciousPatterns.hasContactInfo && looksCommercial) {
    findings.push({ severity: 'medium', message: 'Site comercial sem informação de contato.' });
    score += 8;
  }

  if (pageData.images.broken > 2) {
    findings.push({ severity: 'low', message: `${pageData.images.broken} imagens quebradas — possível site abandonado ou falso.` });
    score += 5;
  }

  return { score: Math.min(score, 100), findings };
}

// ============================================================================
// DETECÇÃO DE SITES DE APOSTAS/BET FALSOS
// ============================================================================

function detectGamblingScam(pageData) {
  const text = (pageData.text.sample || '').toLowerCase();
  const domain = pageData.domain.toLowerCase();
  const title = (pageData.title || '').toLowerCase();
  const url = (pageData.url || '').toLowerCase();
  const combined = `${text} ${title} ${domain} ${url}`;

  const details = [];
  let riskPoints = 0;

  // 1. Domínio contém padrões de BET falsa
  const betDomainPatterns = [
    /bet\d+/i, /vip\d*/i, /win\d*/i, /slot/i, /casino/i, /poker/i,
    /jackpot/i, /spin/i, /bonus/i, /aposta/i, /jogo/i, /roleta/i,
    /fortune/i, /lucky/i, /mega\d*/i, /gold\d*/i, /royal/i,
    /tiger/i, /dragon/i, /bull/i, /crash/i, /mines/i
  ];
  for (const p of betDomainPatterns) {
    if (p.test(domain)) {
      details.push(`domínio contém "${domain.match(p)?.[0]}"`);
      riskPoints += 8;
      break;
    }
  }

  // 2. Termos de gambling no conteúdo
  const gamblingTerms = [
    'apostar', 'apostas', 'aposta', 'bet', 'betting',
    'cassino', 'casino', 'roleta', 'roulette', 'slot',
    'caça-níquel', 'jackpot', 'poker', 'blackjack', 'baccarat',
    'crash', 'mines', 'aviator', 'fortune tiger', 'fortune ox',
    'fortune mouse', 'fortune rabbit', 'spaceman', 'sweet bonanza',
    'gates of olympus', 'big bass', 'sugar rush', 'plinko',
    'depósito mínimo', 'deposite', 'saque', 'sacar',
    'odds', 'handicap', 'over/under', 'placar',
    'rodadas grátis', 'free spins', 'giros grátis',
    'bônus de boas-vindas', 'bônus de cadastro', 'bonus de registro',
    'rollover', 'wagering'
  ];
  const foundTerms = gamblingTerms.filter(t => combined.includes(t));
  if (foundTerms.length >= 3) {
    details.push(`${foundTerms.length} termos de apostas/gambling`);
    riskPoints += Math.min(foundTerms.length * 3, 20);
  }

  // 3. Padrões clássicos de BET FALSA brasileira
  const scamBetPatterns = [
    { pattern: /convide?\s*(e\s*)?ganh[ea]/i, label: 'esquema "convide e ganhe"' },
    { pattern: /login\s*di[áa]rio|acesso\s*di[áa]rio/i, label: '"login diário" com recompensa' },
    { pattern: /ganhe?\s*(até\s*)?R\$\s*\d/i, label: 'promessa de ganho em R$' },
    { pattern: /de\s*gra[çc]a\s*receba|receba\s*gr[áa]tis/i, label: '"receba de graça"' },
    { pattern: /c[óo]digo\s*de?\s*(resgate|convite|b[ôo]nus)/i, label: 'código de resgate/convite' },
    { pattern: /saldo\s*(de\s*)?(b[ôo]nus|gr[áa]tis)/i, label: 'saldo bônus grátis' },
    { pattern: /deposi[t]?(e|ar|o)\s*(e\s*)?ganh[ea]/i, label: '"deposite e ganhe"' },
    { pattern: /primeiro\s*dep[oó]sito|1[ºo°]\s*dep[oó]sito/i, label: 'bônus primeiro depósito' },
    { pattern: /vip|membro\s*(especial|exclusivo|premium)/i, label: 'sistema VIP/exclusivo' },
    { pattern: /retirar?\s*saldo|sacar?\s*prêmio/i, label: '"retire seu saldo/prêmio"' },
    { pattern: /pix\s*(instant[âa]neo|r[áa]pido|na\s*hora)/i, label: 'PIX instantâneo (golpe)' },
    { pattern: /grupo\s*(oficial|vip|telegram|whatsapp)/i, label: 'grupo VIP/oficial' },
    { pattern: /robô\s*(de\s*)?(apostas?|sinais?|trading)/i, label: '"robô de apostas/sinais"' },
    { pattern: /lucrando|lucro\s*(f[áa]cil|garantido|di[áa]rio)/i, label: 'promessa lucro fácil' },
    { pattern: /x\d{1,3}\s*(multiplicador|vezes)/i, label: 'multiplicador exagerado' },
    { pattern: /R\$\s*\d+[\.,]?\d*\s*x\s*\d+/i, label: 'esquema "R$ x vezes"' }
  ];

  const matchedPatterns = [];
  for (const { pattern, label } of scamBetPatterns) {
    if (pattern.test(combined)) {
      matchedPatterns.push(label);
    }
  }

  if (matchedPatterns.length > 0) {
    details.push(...matchedPatterns.slice(0, 5));
    riskPoints += Math.min(matchedPatterns.length * 8, 40);
  }

  // 4. Site de BET sem licença (não tem regulamentação visível)
  const hasLicense = /licen[çc]a|regulament|autorizado\s*por|LOTERJ|SPA-MF|apostas?\s*legais?\s*|regulat/i.test(text);
  const isGamblingsite = foundTerms.length >= 2 || matchedPatterns.length >= 1;

  if (isGamblingsite && !hasLicense) {
    details.push('sem menção a licença/regulamentação');
    riskPoints += 15;
  }

  // 5. Valores absurdos (R$300 x20, R$100 grátis, etc)
  const absurdValues = combined.match(/R\$\s*\d{2,4}\s*x\s*\d{1,2}/gi);
  if (absurdValues && absurdValues.length > 0) {
    details.push(`valores absurdos: ${absurdValues.slice(0, 2).join(', ')}`);
    riskPoints += 15;
  }

  // Determinar severidade
  if (riskPoints === 0) {
    return { detected: false, severity: 'info', message: '', score: 0, details: [] };
  }

  let severity = 'medium';
  let message = '';

  if (riskPoints >= 40) {
    severity = 'critical';
    message = `ALERTA: Site de apostas/BET com ${matchedPatterns.length + foundTerms.length} sinais de GOLPE. Sites deste tipo frequentemente roubam depósitos e dados pessoais.`;
  } else if (riskPoints >= 20) {
    severity = 'high';
    message = 'Site de apostas/BET com múltiplos sinais suspeitos — provavelmente fraudulento. Nunca deposite dinheiro.';
  } else {
    severity = 'medium';
    message = 'Conteúdo de apostas/gambling detectado — verifique se o site possui licença e regulamentação válida antes de qualquer interação.';
  }

  return { detected: true, severity, message, score: Math.min(riskPoints, 50), details };
}

// ============================================================================
// ANÁLISE DE DOMÍNIO (via IP2WHOIS)
// ============================================================================

async function analyzeDomain(pageData, apiKeys) {
  const findings = [];
  let score = 0;

  if (apiKeys.whois) {
    try {
      const w = await fetchWhoisData(pageData.domain, apiKeys.whois);
      if (w && w.domain) {

        // Idade do domínio (IP2WHOIS fornece domain_age em dias)
        if (typeof w.domain_age === 'number' && w.domain_age >= 0) {
          const ageMonths = w.domain_age / 30;
          if (ageMonths < 3) {
            findings.push({ severity: 'high', message: `Domínio criado há ${w.domain_age} dias — muito recente para ser confiável.` });
            score += 25;
          } else if (ageMonths < 12) {
            findings.push({ severity: 'medium', message: `Domínio criado há ${Math.floor(ageMonths)} meses — relativamente novo.` });
            score += 10;
          } else {
            findings.push({ severity: 'positive', message: `Domínio registrado há ${Math.floor(ageMonths / 12)} ano(s) (${w.domain_age} dias) — boa antiguidade.` });
          }
        } else if (w.create_date) {
          // Fallback: calcular pela data de criação
          const created = new Date(w.create_date);
          if (!isNaN(created.getTime())) {
            const ageMonths = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24 * 30);
            if (ageMonths < 3) {
              findings.push({ severity: 'high', message: `Domínio criado há menos de 3 meses — muito recente.` });
              score += 25;
            } else if (ageMonths < 12) {
              findings.push({ severity: 'medium', message: `Domínio criado há ${Math.floor(ageMonths)} meses — relativamente novo.` });
              score += 10;
            } else {
              findings.push({ severity: 'positive', message: `Domínio registrado há ${Math.floor(ageMonths / 12)} ano(s) — boa antiguidade.` });
            }
          }
        }

        // Proprietário oculto (privacy/proxy)
        const regOrg = (w.registrant?.organization || '').toLowerCase();
        const regName = (w.registrant?.name || '').toLowerCase();
        const regEmail = (w.registrant?.email || '').toLowerCase();
        const combined = `${regOrg} ${regName} ${regEmail}`;
        if (combined.includes('privacy') || combined.includes('proxy') ||
            combined.includes('redacted') || combined.includes('withheld') ||
            combined.includes('domains by proxy') || combined.includes('contact privacy')) {
          findings.push({ severity: 'low', message: 'Dados do proprietário do domínio estão ocultos (serviço de privacidade).' });
          score += 5;
        }

        // Expiração
        if (w.expire_date) {
          const expires = new Date(w.expire_date);
          if (!isNaN(expires.getTime())) {
            const monthsLeft = (expires.getTime() - Date.now()) / (1000 * 60 * 60 * 24 * 30);
            if (monthsLeft < 2) {
              findings.push({ severity: 'medium', message: 'Domínio expira em breve — sites legítimos mantêm registro por vários anos.' });
              score += 12;
            }
          }
        }

        // Registrador (info)
        if (w.registrar?.name) {
          findings.push({ severity: 'info', message: `Registrador: ${w.registrar.name}` });
        }

      } else {
        findings.push({ severity: 'info', message: 'WHOIS não retornou dados para este domínio.' });
      }
    } catch (error) {
      findings.push({ severity: 'info', message: `Não foi possível verificar WHOIS: ${error.message}` });
    }
  } else {
    findings.push({ severity: 'info', message: 'API WHOIS não configurada — configure nas settings para verificação de domínio.' });
  }

  if (!apiKeys.whois) {
    return { score: null, skipped: true, findings };
  }
  return { score: Math.min(score, 100), findings };
}

async function fetchWhoisData(domain, apiKey) {
  const response = await fetch(
    `https://api.ip2whois.com/v2?key=${encodeURIComponent(apiKey)}&domain=${encodeURIComponent(domain)}`
  );
  if (!response.ok) return null;
  const data = await response.json();
  // IP2WHOIS retorna erro como { error: { error_code, error_message } }
  if (data.error) return null;
  return data;
}

// ============================================================================
// ANÁLISE DE SEGURANÇA
// ============================================================================

function analyzeSecurity(pageData) {
  const findings = [];
  let score = 0;

  // FIX #12: Scoring HTTP concentrado apenas aqui (não mais em analyzeURL)
  if (!pageData.security.isHTTPS) {
    findings.push({ severity: 'high', message: 'Conexão não criptografada (HTTP). Dados podem ser interceptados.' });
    score += 25;
  } else {
    findings.push({ severity: 'positive', message: 'Conexão criptografada (HTTPS) ativa.' });
  }

  if (pageData.security.hasMixedContent) {
    findings.push({ severity: 'medium', message: 'Conteúdo misto detectado — alguns recursos carregados sem criptografia.' });
    score += 10;
  }

  if (pageData.scripts.suspiciousExternal > 0 || pageData.scripts.suspiciousInline > 0) {
    findings.push({
      severity: 'high',
      message: `Scripts potencialmente maliciosos detectados (${pageData.scripts.suspiciousExternal} externo(s), ${pageData.scripts.suspiciousInline} inline).`
    });
    score += 20;
  }

  if (pageData.suspiciousPatterns.hasHiddenIframes) {
    findings.push({ severity: 'high', message: 'Iframes ocultos detectados — pode ser tentativa de clickjacking ou rastreamento.' });
    score += 15;
  }

  if (pageData.suspiciousPatterns.hasRightClickDisabled) {
    findings.push({ severity: 'low', message: 'Clique direito desabilitado — sites legítimos raramente fazem isso.' });
    score += 5;
  }

  if (pageData.suspiciousPatterns.hasHiddenText) {
    findings.push({ severity: 'medium', message: 'Texto oculto detectado na página — possível SEO manipulation ou conteúdo enganoso.' });
    score += 10;
  }

  if (pageData.scripts.externalDomains.length > 15) {
    findings.push({ severity: 'low', message: `Scripts de ${pageData.scripts.externalDomains.length} domínios externos — quantidade acima do normal.` });
    score += 5;
  }

  return { score: Math.min(score, 100), findings };
}

// ============================================================================
// ANÁLISE DE FORMULÁRIOS
// ============================================================================

function analyzeForms(pageData) {
  const findings = [];
  let score = 0;

  if (pageData.forms.length === 0) {
    return { score: 0, findings: [{ severity: 'info', message: 'Nenhum formulário detectado na página.' }] };
  }

  for (const form of pageData.forms) {
    const sensitiveTypes = form.sensitiveFields;

    if (sensitiveTypes.includes('credit_card') || sensitiveTypes.includes('cvv')) {
      if (!pageData.security.isHTTPS) {
        findings.push({ severity: 'critical', message: 'Formulário coleta dados de cartão de crédito SEM HTTPS — NUNCA insira seus dados!' });
        score += 40;
      } else {
        findings.push({ severity: 'medium', message: 'Formulário coleta dados de cartão — verifique se o site é legítimo antes de preencher.' });
        score += 10;
      }
    }
    if (sensitiveTypes.includes('document_id')) {
      findings.push({ severity: 'high', message: 'Formulário solicita CPF/documento — dados altamente sensíveis.' });
      score += 15;
    }
    if (sensitiveTypes.includes('bank_info') || sensitiveTypes.includes('pix_key')) {
      findings.push({ severity: 'high', message: 'Formulário solicita dados bancários ou chave PIX — risco elevado.' });
      score += 20;
    }
    if (sensitiveTypes.includes('password')) {
      findings.push({ severity: 'medium', message: 'Formulário solicita senha — certifique-se de estar no site correto.' });
      score += 8;
    }
    if (form.submitsExternally) {
      findings.push({ severity: 'high', message: `Formulário envia dados para domínio externo (${form.externalDomain}) — comportamento suspeito.` });
      score += 20;
    }
    if (sensitiveTypes.length >= 3) {
      findings.push({ severity: 'high', message: `Formulário coleta ${sensitiveTypes.length} tipos de dados sensíveis simultaneamente — incomum para sites legítimos.` });
      score += 15;
    }
  }

  return { score: Math.min(score, 100), findings };
}

// ============================================================================
// VERIFICAÇÕES EXTERNAS (Safe Browsing)
// ============================================================================

async function runExternalChecks(pageData, apiKeys) {
  const findings = [];
  let score = 0;

  if (apiKeys.safeBrowsing) {
    try {
      const result = await checkSafeBrowsing(pageData.url, apiKeys.safeBrowsing);
      if (result.isMalicious) {
        findings.push({ severity: 'critical', message: `Google Safe Browsing MARCOU este site como perigoso: ${result.threats.join(', ')}.` });
        score += 50;
      } else {
        findings.push({ severity: 'positive', message: 'Site não aparece na lista de ameaças do Google Safe Browsing.' });
      }
    } catch {
      findings.push({ severity: 'info', message: 'Não foi possível consultar Google Safe Browsing.' });
    }
  } else {
    findings.push({ severity: 'info', message: 'API Safe Browsing não configurada — configure para verificação contra lista negra do Google.' });
  }

  if (pageData.links.suspicious > 0) {
    findings.push({ severity: 'medium', message: `${pageData.links.suspicious} link(s) suspeito(s) encontrado(s) na página (encurtadores, IPs, javascript:).` });
    score += Math.min(pageData.links.suspicious * 5, 15);
  }

  if (pageData.links.uniqueDomains > 20) {
    findings.push({ severity: 'low', message: `Links para ${pageData.links.uniqueDomains} domínios diferentes — quantidade incomum.` });
    score += 5;
  }

  return { score: Math.min(score, 100), findings };
}

async function checkSafeBrowsing(url, apiKey) {
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const body = {
    client: { clientId: 'alertaweb-extension', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await response.json();
  return {
    isMalicious: data.matches && data.matches.length > 0,
    threats: data.matches ? data.matches.map(m => m.threatType) : []
  };
}

// ============================================================================
// VERIFICAÇÃO VIRUSTOTAL
// ============================================================================

async function runVirusTotalCheck(pageData, apiKeys) {
  const findings = [];
  let score = 0;

  if (!apiKeys.virusTotal) {
    return { score: null, skipped: true, findings: [{ severity: 'info', message: 'API VirusTotal não configurada — configure nas settings para verificação por 70+ antivírus.' }] };
  }

  try {
    // URL ID = base64url sem padding
    let urlId;
    try {
      const utf8Url = unescape(encodeURIComponent(pageData.url));
      urlId = btoa(utf8Url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    } catch {
      throw new Error('Não foi possível codificar a URL.');
    }

    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: 'GET',
      headers: { 'x-apikey': apiKeys.virusTotal, 'Accept': 'application/json' }
    });

    if (response.status === 404) {
      const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': apiKeys.virusTotal, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodeURIComponent(pageData.url)}`
      });
      findings.push({
        severity: 'info',
        message: submitResponse.ok
          ? 'URL enviada ao VirusTotal para primeira análise. Reanalise em alguns minutos.'
          : 'Não foi possível enviar URL ao VirusTotal. Verifique sua API key.'
      });
      return { score: 0, findings };
    }

    if (!response.ok) throw new Error(`VirusTotal retornou status ${response.status}`);

    const data = await response.json();
    const stats = data?.data?.attributes?.last_analysis_stats;
    const results = data?.data?.attributes?.last_analysis_results;
    const reputation = data?.data?.attributes?.reputation;
    const totalVotes = data?.data?.attributes?.total_votes;
    const categories = data?.data?.attributes?.categories || {};

    if (stats) {
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;
      const undetected = stats.undetected || 0;
      const total = malicious + suspicious + harmless + undetected;

      if (malicious > 0 || suspicious > 0) {
        const detectingEngines = [];
        if (results) {
          for (const [engine, r] of Object.entries(results)) {
            if (r.category === 'malicious' || r.category === 'suspicious') {
              detectingEngines.push(`${engine}: ${r.result || r.category}`);
            }
          }
        }

        if (malicious >= 5) {
          findings.push({ severity: 'critical', message: `VirusTotal: ${malicious} antivírus marcaram como MALICIOSO e ${suspicious} como suspeito (de ${total} engines).` });
          score += 45;
        } else if (malicious >= 2) {
          findings.push({ severity: 'high', message: `VirusTotal: ${malicious} antivírus marcaram como malicioso e ${suspicious} como suspeito (de ${total} engines).` });
          score += 30;
        } else if (malicious >= 1 || suspicious >= 2) {
          findings.push({ severity: 'medium', message: `VirusTotal: ${malicious} detecção(ões) maliciosa(s) e ${suspicious} suspeita(s) em ${total} engines.` });
          score += 18;
        } else {
          findings.push({ severity: 'low', message: `VirusTotal: ${suspicious} engine(s) marcou como suspeito em ${total} analisados.` });
          score += 8;
        }

        if (detectingEngines.length > 0) {
          const sample = detectingEngines.slice(0, 5).join(', ');
          const extra = detectingEngines.length > 5 ? ` e mais ${detectingEngines.length - 5}` : '';
          findings.push({ severity: 'info', message: `Engines que detectaram: ${sample}${extra}.` });
        }
      } else {
        findings.push({ severity: 'positive', message: `VirusTotal: Nenhuma detecção em ${total} engines antivírus — URL aparenta ser limpa.` });
      }

      if (reputation !== undefined && reputation !== null) {
        if (reputation < -10) {
          findings.push({ severity: 'medium', message: `Reputação VirusTotal negativa (${reputation}) — comunidade reportou como suspeito.` });
          score += 10;
        } else if (reputation > 10) {
          findings.push({ severity: 'positive', message: `Boa reputação na comunidade VirusTotal (${reputation}).` });
        }
      }

      if (totalVotes) {
        const hv = totalVotes.harmless || 0;
        const mv = totalVotes.malicious || 0;
        if (mv > hv && mv > 2) {
          findings.push({ severity: 'medium', message: `Comunidade VirusTotal: ${mv} voto(s) "malicioso" vs ${hv} "inofensivo".` });
          score += 8;
        }
      }

      const categoryValues = Object.values(categories);
      if (categoryValues.length > 0) {
        const dangerous = categoryValues.filter(c => /phish|malware|spam|scam|fraud|gambling|adult/i.test(c));
        if (dangerous.length > 0) {
          findings.push({ severity: 'high', message: `VirusTotal categoriza este site como: ${dangerous.join(', ')}.` });
          score += 20;
        }
      }
    }

    return { score: Math.min(score, 100), findings };
  } catch (error) {
    return { score: 0, findings: [{ severity: 'info', message: `VirusTotal indisponível: ${error.message}` }] };
  }
}

// ============================================================================
// ANÁLISE POR IA (Gemini API) — com retry, backoff e fallback de modelo
// ============================================================================

// Modelos em ordem de preferência: lite tem limits mais altos no free tier
const GEMINI_MODELS = [
  'gemini-3.1-flash-lite',   // 15 RPM, 500 RPD (conta Pro)
  'gemini-2.5-flash-lite'    // fallback
];
const MAX_RETRIES = 2;
const BASE_DELAY_MS = 3000;

async function runAIAnalysis(pageData, apiKeys) {
  if (!apiKeys.gemini) {
    return { score: null, skipped: true, findings: [{ severity: 'info', message: 'API Gemini não configurada — configure nas settings para análise inteligente por IA.' }] };
  }

  const prompt = buildAIPrompt(pageData);

  // Tentar cada modelo com retry
  for (const model of GEMINI_MODELS) {
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        // Backoff exponencial: 0s, 3s, 9s
        if (attempt > 0) {
          await sleep(BASE_DELAY_MS * Math.pow(3, attempt - 1));
        }

        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKeys.gemini}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: { temperature: 0.1, maxOutputTokens: 800 }
            })
          }
        );

        // Rate limited — retry com backoff
        if (response.status === 429) {
          console.log(`[AlertaWeb] Gemini ${model} rate limited (tentativa ${attempt + 1}/${MAX_RETRIES + 1})`);
          if (attempt === MAX_RETRIES) break; // Tenta próximo modelo
          continue;
        }

        if (!response.ok) throw new Error(`Gemini ${model} retornou status ${response.status}`);

        const data = await response.json();

        // Verificar se foi bloqueado por safety
        if (data?.candidates?.[0]?.finishReason === 'SAFETY') {
          return { score: null, skipped: true, findings: [{ severity: 'info', message: 'Análise IA bloqueada por filtro de segurança do Gemini.' }] };
        }

        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        const aiResult = parseAIResponse(text);

        if (aiResult) {
          return {
            score: Math.min(Math.max(aiResult.riskScore || 0, 0), 100),
            findings: (aiResult.findings || []).map(f => ({
              severity: f.severity || 'medium',
              message: f.message || ''
            })),
            summary: aiResult.summary || '',
            recommendation: aiResult.recommendation || ''
          };
        }

        return { score: null, skipped: true, findings: [{ severity: 'info', message: 'Análise IA retornou formato inesperado.' }] };

      } catch (error) {
        if (attempt === MAX_RETRIES) {
          console.log(`[AlertaWeb] Gemini ${model} falhou após ${MAX_RETRIES + 1} tentativas: ${error.message}`);
        }
      }
    }
  }

  // Todos os modelos falharam
  return {
    score: null, skipped: true,
    findings: [{
      severity: 'info',
      message: 'Análise IA indisponível (rate limit). Aguarde 1 min e reanalise, ou verifique sua quota em aistudio.google.com.'
    }]
  };
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// FIX #3: Parser JSON robusto — tenta parse direto, depois extrai bloco JSON com balanceamento
function parseAIResponse(text) {
  // Tentativa 1: texto inteiro é JSON
  try {
    return JSON.parse(text.trim());
  } catch { /* não é JSON puro */ }

  // Tentativa 2: Encontrar o primeiro bloco JSON balanceado começando com { "riskScore"
  // Isso evita o bug do regex greedy que capturava de { a } errado
  const start = text.indexOf('{');
  if (start === -1) return null;

  let depth = 0;
  for (let i = start; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') {
      depth--;
      if (depth === 0) {
        try {
          return JSON.parse(text.substring(start, i + 1));
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

function buildAIPrompt(pageData) {
  // Compactar forms para economizar tokens
  const formsCompact = pageData.forms.length > 0
    ? pageData.forms.map(f => `${f.method} ${f.sensitiveFields.join(',')||'none'} ext:${f.submitsExternally}`).join('; ')
    : 'nenhum';

  // Limitar amostra de texto a 1000 chars
  const textSample = (pageData.text.sample || '').substring(0, 1000);

  return `Analise esta página web e diga se é golpe. Foco em golpes brasileiros, BETs falsas (convide e ganhe, Fortune Tiger, R$x20, login diário, sem licença LOTERJ/SPA-MF).

URL: ${pageData.url}
Título: ${pageData.title}
HTTPS: ${pageData.security.isHTTPS}
Forms: ${formsCompact}
Links: ${pageData.links.total} total, ${pageData.links.suspicious} suspeitos
Urgência: ${pageData.text.hasUrgencyLanguage.count} termos
Garantias: ${pageData.text.hasGuaranteePatterns.count} termos
Countdown: ${pageData.suspiciousPatterns.hasCountdownTimers}
Typosquatting: ${pageData.suspiciousPatterns.domainTyposquatting.detected}
Contato: ${pageData.suspiciousPatterns.hasContactInfo}
Legal: ${pageData.suspiciousPatterns.hasLegalPages}
CNPJ: ${pageData.suspiciousPatterns.hasPhysicalAddress}

Texto: ${textSample}

Responda SÓ com JSON (sem markdown):
{"riskScore":<0-100>,"summary":"<1 frase>","recommendation":"<1 frase>","findings":[{"severity":"critical|high|medium|low|positive","message":"<fato>"}]}`;
}

// ============================================================================
// CONSOLIDAÇÃO DE RESULTADOS
// ============================================================================

function consolidateResults(analyses) {
  const weights = {
    urlAnalysis: 0.15,
    contentAnalysis: 0.12,
    domainAnalysis: 0.12,
    securityAnalysis: 0.12,
    formAnalysis: 0.12,
    externalChecks: 0.09,
    virusTotalCheck: 0.18,
    aiAnalysis: 0.10
  };

  let weightedScore = 0;
  let totalWeight = 0;
  const allFindings = [];

  for (const [key, weight] of Object.entries(weights)) {
    const analysis = analyses[key];
    // CRITICAL FIX: Só incluir no peso se o módulo realmente rodou (score !== null e não skipped)
    if (analysis && typeof analysis.score === 'number' && !analysis.error && !analysis.skipped) {
      weightedScore += analysis.score * weight;
      totalWeight += weight;
    }
    if (analysis?.findings) {
      allFindings.push(...analysis.findings);
    }
  }

  // Calcular a média ponderada
  const weightedAvg = totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 0;

  // CRITICAL FIX: Evitar que módulos com score 0 diluam a detecção de um módulo que
  // encontrou alto risco. Se o conteúdo da página GRITA golpe (score 80+), mas a URL
  // e segurança parecem ok, a média cai muito. Solução: usar o maior score individual
  // como piso proporcional.
  let maxModuleScore = 0;
  for (const [key, weight] of Object.entries(weights)) {
    const analysis = analyses[key];
    if (analysis && typeof analysis.score === 'number' && !analysis.skipped) {
      maxModuleScore = Math.max(maxModuleScore, analysis.score);
    }
  }

  // O score final é o MAIOR entre a média ponderada e 70% do pior módulo encontrado
  const peakFloor = Math.round(maxModuleScore * 0.7);
  const finalScore = Math.min(Math.max(weightedAvg, peakFloor), 100);

  let riskLevel, riskLabel, riskColor;
  if (finalScore >= CONFIG.RISK_THRESHOLDS.CRITICAL) {
    riskLevel = 'critical'; riskLabel = 'CRÍTICO — Golpe Provável'; riskColor = '#dc2626';
  } else if (finalScore >= CONFIG.RISK_THRESHOLDS.HIGH) {
    riskLevel = 'high'; riskLabel = 'ALTO — Muito Suspeito'; riskColor = '#ea580c';
  } else if (finalScore >= CONFIG.RISK_THRESHOLDS.MEDIUM) {
    riskLevel = 'medium'; riskLabel = 'MÉDIO — Suspeito'; riskColor = '#d97706';
  } else if (finalScore >= CONFIG.RISK_THRESHOLDS.LOW) {
    riskLevel = 'low'; riskLabel = 'BAIXO — Atenção'; riskColor = '#65a30d';
  } else {
    riskLevel = 'safe'; riskLabel = 'SEGURO — Aparentemente Legítimo'; riskColor = '#16a34a';
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, positive: 5 };
  allFindings.sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

  return {
    url: analyses.url,
    domain: analyses.domain,
    title: analyses.title,
    score: finalScore,
    riskLevel, riskLabel, riskColor,
    findings: allFindings,
    aiSummary: analyses.aiAnalysis?.summary || null,
    aiRecommendation: analyses.aiAnalysis?.recommendation || null,
    breakdown: {
      url: analyses.urlAnalysis?.score || 0,
      content: analyses.contentAnalysis?.score || 0,
      domain: analyses.domainAnalysis?.score || 0,
      security: analyses.securityAnalysis?.score || 0,
      forms: analyses.formAnalysis?.score || 0,
      external: analyses.externalChecks?.score || 0,
      virusTotal: analyses.virusTotalCheck?.score || 0,
      ai: analyses.aiAnalysis?.score || 0
    },
    timestamp: analyses.timestamp
  };
}

// ============================================================================
// UTILIDADES
// ============================================================================

async function getSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get('settings', (data) => resolve(data.settings || {}));
  });
}

function saveToHistory(result) {
  chrome.storage.local.get('history', (data) => {
    const history = data.history || [];
    history.unshift({
      url: result.url, domain: result.domain, score: result.score,
      riskLevel: result.riskLevel, riskLabel: result.riskLabel, timestamp: result.timestamp
    });
    if (history.length > 100) history.splice(100);
    chrome.storage.local.set({ history });
  });
}
