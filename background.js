// ============================================================================
// AlertaWeb — Background Service Worker
// Motor de análise principal com verificações multi-camada
// ============================================================================

'use strict';

// Carregar chaves embutidas (se existirem)
try { importScripts('keys.js'); } catch { /* keys.js é opcional */ }

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

  if (request.action === 'checkEmailLinks') {
    checkEmailLinksWithAPIs(request.urls)
      .then(results => sendResponse({ success: true, results }))
      .catch(() => sendResponse({ success: false }));
    return true;
  }

  if (request.action === 'analyzeEmailWithAPIs') {
    analyzeEmailFullWithAPIs(request.emailData)
      .then(result => sendResponse({ success: true, result }))
      .catch(e => sendResponse({ success: false, error: e.message }));
    return true;
  }

  if (request.action === 'getCachedResult') {
    getCachedAnalysis(request.url).then(result => {
      if (result) sendResponse({ success: true, result });
      else sendResponse({ success: false });
    }).catch(() => sendResponse({ success: false }));
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

  if (!forceReanalyze) {
    const cached = await getCachedAnalysis(pageData.url);
    if (cached) return cached;
  }

  // ====== WHITELIST ======
  const domainInfo = classifyDomain(pageData.domain);

  if (domainInfo.whitelisted) {
    const result = {
      url: pageData.url, domain: pageData.domain, title: pageData.title,
      riskLevel: 'seguro',
      riskLabel: 'Seguro',
      riskColor: '#16a34a',
      summary: `O domínio "${pageData.domain}" é reconhecido como um site legítimo e confiável.`,
      findings: [{ severity: 'positive', message: 'Site presente na lista de domínios confiáveis.' }],
      apisUsed: ['whitelist'],
      timestamp: Date.now()
    };
    await setCachedAnalysis(pageData.url, result);
    saveToHistory(result);
    return result;
  }

  pageData._context = { isUGC: domainInfo.isUGC, isCommercial: domainInfo.isCommercial };

  // ====== FASE 1: Rodar heurísticas + APIs em paralelo (tudo MENOS Gemini) ======
  const [
    urlAnalysis, contentAnalysis, domainAnalysis, securityAnalysis,
    formAnalysis, externalChecks, virusTotalCheck
  ] = await Promise.allSettled([
    analyzeURL(pageData),
    analyzeContent(pageData),
    analyzeDomain(pageData, apiKeys),
    analyzeSecurity(pageData),
    analyzeForms(pageData),
    runExternalChecks(pageData, apiKeys),
    runVirusTotalCheck(pageData, apiKeys)
  ]);

  // Coletar todos os dados
  const allData = {
    url: pageData.url,
    domain: pageData.domain,
    title: pageData.title,
    urlAnalysis: getSettledValue(urlAnalysis),
    contentAnalysis: getSettledValue(contentAnalysis),
    domainAnalysis: getSettledValue(domainAnalysis),
    securityAnalysis: getSettledValue(securityAnalysis),
    formAnalysis: getSettledValue(formAnalysis),
    externalChecks: getSettledValue(externalChecks),
    virusTotalCheck: getSettledValue(virusTotalCheck)
  };

  // ====== FASE 2: Enviar dossiê completo ao Gemini para veredito final ======
  const result = await buildFinalJudgment(allData, apiKeys);

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
// VERIFICAÇÃO DE LINKS DE EMAIL (usado pelo email-scanner.js)
// ============================================================================

async function checkEmailLinksWithAPIs(urls) {
  const settings = await getSettings();
  const apiKeys = settings.apiKeys || {};

  // Verificar todos os links em PARALELO (não sequencial)
  const checks = urls.map(url => checkSingleLink(url, apiKeys));
  const settled = await Promise.allSettled(checks);

  return settled.map((s, i) => s.status === 'fulfilled' ? s.value : { url: urls[i], safeBrowsing: null, virusTotal: null });
}

async function checkSingleLink(url, apiKeys) {
  const result = { url, safeBrowsing: null, virusTotal: null };

  // Fetch com timeout de 8 segundos
  const fetchWithTimeout = (fetchUrl, options = {}, timeoutMs = 8000) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(fetchUrl, { ...options, signal: controller.signal })
      .finally(() => clearTimeout(timer));
  };

  // Safe Browsing e VirusTotal em paralelo para cada link
  const tasks = [];

  if (apiKeys.safeBrowsing) {
    tasks.push(
      (async () => {
        try {
          result.safeBrowsing = await checkSafeBrowsing(url, apiKeys.safeBrowsing);
        } catch { /* silenciar */ }
      })()
    );
  }

  if (apiKeys.virusTotal) {
    tasks.push(
      (async () => {
        try {
          const utf8Url = unescape(encodeURIComponent(url));
          const urlId = btoa(utf8Url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
          const vtResponse = await fetchWithTimeout(
            `https://www.virustotal.com/api/v3/urls/${urlId}`,
            { headers: { 'x-apikey': apiKeys.virusTotal, 'Accept': 'application/json' } }
          );
          if (vtResponse.ok) {
            const vtData = await vtResponse.json();
            const stats = vtData?.data?.attributes?.last_analysis_stats;
            if (stats) {
              result.virusTotal = { malicious: stats.malicious || 0, suspicious: stats.suspicious || 0 };
            }
          }
        } catch { /* silenciar — timeout ou erro de rede */ }
      })()
    );
  }

  await Promise.allSettled(tasks);
  return result;
}

// ============================================================================
// ANÁLISE COMPLETA DE EMAIL (Links + Gemini IA)
// ============================================================================

async function analyzeEmailFullWithAPIs(emailData) {
  const settings = await getSettings();
  const apiKeys = settings.apiKeys || {};

  const results = { linkResults: [], aiAnalysis: null };

  // 1. Verificar links contra Safe Browsing + VirusTotal
  const urls = (emailData.urls || []).slice(0, 10);
  if (urls.length > 0) {
    try {
      results.linkResults = await checkEmailLinksWithAPIs(urls);
    } catch { /* silenciar */ }
  }

  // 2. Análise por Gemini IA
  if (apiKeys.gemini && emailData.bodyText) {
    try {
      const prompt = buildEmailAIPrompt(emailData);
      const aiResult = await callGeminiForEmail(prompt, apiKeys.gemini);
      if (aiResult) {
        results.aiAnalysis = aiResult;
      }
    } catch { /* silenciar */ }
  }

  return results;
}

async function callGeminiForEmail(prompt, apiKey) {
  for (const model of GEMINI_MODELS) {
    for (let attempt = 0; attempt <= 1; attempt++) {
      try {
        if (attempt > 0) await sleep(2000);

        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: { temperature: 0.1, maxOutputTokens: 600 }
            })
          }
        );

        if (response.status === 429) { if (attempt === 1) break; continue; }
        if (!response.ok) continue;

        const data = await response.json();
        if (data?.candidates?.[0]?.finishReason === 'SAFETY') return null;

        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        return parseAIResponse(text);
      } catch { if (attempt === 1) break; }
    }
  }
  return null;
}

function buildEmailAIPrompt(emailData) {
  const linksInfo = (emailData.urls || []).slice(0, 5).join(', ') || 'nenhum';
  const body = (emailData.bodyText || '').substring(0, 800);

  return `Analise este email e diga se é phishing/golpe. Seja direto.

De: ${emailData.sender || 'desconhecido'}
Assunto: ${emailData.subject || 'sem assunto'}
Links: ${linksInfo}

Corpo:
${body}

Responda SÓ com JSON (sem markdown):
{"riskScore":<0-100>,"summary":"<1 frase>","findings":[{"severity":"critical|high|medium|low|positive","message":"<fato>"}]}`;
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

// Parser JSON robusto
function parseAIResponse(text) {
  try { return JSON.parse(text.trim()); } catch { /* */ }
  const start = text.indexOf('{');
  if (start === -1) return null;
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') { depth--; if (depth === 0) { try { return JSON.parse(text.substring(start, i + 1)); } catch { return null; } } }
  }
  return null;
}

// ============================================================================
// JULGAMENTO FINAL — Gemini como analista sênior, heurísticas como fallback
// ============================================================================

const RISK_LEVELS = {
  seguro:  { label: 'Seguro',  color: '#16a34a' },
  baixo:   { label: 'Baixo',   color: '#65a30d' },
  medio:   { label: 'Médio',   color: '#d97706' },
  alto:    { label: 'Alto',    color: '#ea580c' },
  critico: { label: 'Crítico', color: '#dc2626' }
};

async function buildFinalJudgment(allData, apiKeys) {
  // Coletar todos os findings e calcular score interno (para fallback)
  const allFindings = [];
  let internalScore = 0;
  let totalWeight = 0;
  const apisUsed = [];

  const modules = {
    urlAnalysis: 0.15, contentAnalysis: 0.15, domainAnalysis: 0.12,
    securityAnalysis: 0.12, formAnalysis: 0.12, externalChecks: 0.15,
    virusTotalCheck: 0.19
  };

  let maxModuleScore = 0;
  for (const [key, weight] of Object.entries(modules)) {
    const m = allData[key];
    if (m?.findings) allFindings.push(...m.findings);
    if (m && typeof m.score === 'number' && !m.skipped) {
      internalScore += m.score * weight;
      totalWeight += weight;
      maxModuleScore = Math.max(maxModuleScore, m.score);
    }
  }

  const weightedAvg = totalWeight > 0 ? Math.round(internalScore / totalWeight) : 0;
  const fallbackScore = Math.min(Math.max(weightedAvg, Math.round(maxModuleScore * 0.7)), 100);

  // Registrar quais APIs rodaram
  if (allData.externalChecks && !allData.externalChecks.skipped) apisUsed.push('Safe Browsing');
  if (allData.virusTotalCheck && !allData.virusTotalCheck.skipped) apisUsed.push('VirusTotal');
  if (allData.domainAnalysis && !allData.domainAnalysis.skipped) apisUsed.push('IP2WHOIS');

  // ====== TENTAR GEMINI COMO ANALISTA FINAL ======
  if (apiKeys.gemini) {
    try {
      const dossier = buildDossier(allData, allFindings);
      const geminiResult = await callGeminiJudgment(dossier, apiKeys.gemini);

      if (geminiResult && geminiResult.riskLevel) {
        const level = geminiResult.riskLevel.toLowerCase();
        const riskInfo = RISK_LEVELS[level] || RISK_LEVELS.medio;
        apisUsed.push('Gemini IA');

        // Combinar findings da IA com os das heurísticas
        const aiFindings = (geminiResult.findings || []).map(f => ({
          severity: f.severity || 'medium',
          message: f.message
        }));

        return {
          url: allData.url, domain: allData.domain, title: allData.title,
          riskLevel: level,
          riskLabel: riskInfo.label,
          riskColor: riskInfo.color,
          summary: geminiResult.summary || '',
          findings: aiFindings.length > 0 ? aiFindings : allFindings.slice(0, 8),
          apisUsed,
          timestamp: Date.now()
        };
      }
    } catch { /* Gemini falhou, usar fallback */ }
  }

  // ====== FALLBACK: heurísticas determinam o nível ======
  let fallbackLevel;
  if (fallbackScore >= 75) fallbackLevel = 'critico';
  else if (fallbackScore >= 55) fallbackLevel = 'alto';
  else if (fallbackScore >= 35) fallbackLevel = 'medio';
  else if (fallbackScore >= 15) fallbackLevel = 'baixo';
  else fallbackLevel = 'seguro';

  const riskInfo = RISK_LEVELS[fallbackLevel];

  // Gerar resumo automático a partir dos findings
  const criticalFindings = allFindings.filter(f => f.severity === 'critical' || f.severity === 'high');
  let autoSummary = '';
  if (criticalFindings.length > 0) {
    autoSummary = `Foram detectados ${criticalFindings.length} alerta(s) importante(s) neste site. ${criticalFindings[0].message}.`;
  } else if (allFindings.length > 0) {
    autoSummary = `Análise baseada em heurísticas locais. ${allFindings.filter(f => f.severity !== 'positive' && f.severity !== 'info').length} ponto(s) de atenção encontrado(s).`;
  } else {
    autoSummary = 'Nenhum sinal de risco detectado pelas verificações locais.';
  }

  if (!apiKeys.gemini) {
    autoSummary += ' Configure a API Gemini nas configurações para análise inteligente por IA.';
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, positive: 5 };
  allFindings.sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

  return {
    url: allData.url, domain: allData.domain, title: allData.title,
    riskLevel: fallbackLevel,
    riskLabel: riskInfo.label,
    riskColor: riskInfo.color,
    summary: autoSummary,
    findings: allFindings.slice(0, 10),
    apisUsed,
    timestamp: Date.now()
  };
}

// ============================================================================
// DOSSIÊ PARA O GEMINI
// ============================================================================

function buildDossier(allData, allFindings) {
  // Resumir dados de cada API
  const safeBrowsing = allData.externalChecks?.findings
    ?.filter(f => f.severity !== 'info')
    ?.map(f => f.message).join('; ') || 'Não verificado';

  const virusTotal = allData.virusTotalCheck?.findings
    ?.filter(f => f.severity !== 'info')
    ?.map(f => f.message).join('; ') || 'Não verificado';

  const whois = allData.domainAnalysis?.findings
    ?.filter(f => f.severity !== 'info')
    ?.map(f => f.message).join('; ') || 'Não verificado';

  const heuristicSummary = allFindings
    .filter(f => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium')
    .slice(0, 10)
    .map(f => `[${f.severity.toUpperCase()}] ${f.message}`)
    .join('\n');

  return `Você é um analista de segurança cibernética. Analise este dossiê e dê seu veredito.

SITE ANALISADO:
URL: ${allData.url}
Domínio: ${allData.domain}
Título: ${allData.title || 'sem título'}

RESULTADOS DAS VERIFICAÇÕES:

1. Google Safe Browsing: ${safeBrowsing}
2. VirusTotal (70+ antivírus): ${virusTotal}
3. WHOIS (dados do domínio): ${whois}

4. Alertas das heurísticas locais:
${heuristicSummary || 'Nenhum alerta relevante.'}

TAREFA:
Com base em TODOS os dados acima, determine o nível de risco deste site.
Considere especialmente: BETs falsas, phishing bancário, lojas fraudulentas, e golpes comuns no Brasil.

Responda SÓ com JSON (sem markdown, sem backticks):
{"riskLevel":"seguro|baixo|medio|alto|critico","summary":"<2-3 frases explicando o veredito para um leigo>","findings":[{"severity":"critical|high|medium|low|positive","message":"<fato objetivo>"}]}`;
}

async function callGeminiJudgment(prompt, apiKey) {
  for (const model of GEMINI_MODELS) {
    for (let attempt = 0; attempt <= 1; attempt++) {
      try {
        if (attempt > 0) await sleep(2000);
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: { temperature: 0.1, maxOutputTokens: 600 }
            })
          }
        );
        if (response.status === 429) { if (attempt === 1) break; continue; }
        if (!response.ok) continue;

        const data = await response.json();
        if (data?.candidates?.[0]?.finishReason === 'SAFETY') return null;
        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        return parseAIResponse(text);
      } catch { if (attempt === 1) break; }
    }
  }
  return null;
}

// ============================================================================
// UTILIDADES
// ============================================================================

async function getSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get('settings', (data) => {
      const settings = data.settings || {};
      const userKeys = settings.apiKeys || {};

      // Merge: chaves do usuário têm prioridade, embutidas são fallback
      if (typeof getEmbeddedKeys === 'function') {
        const embedded = getEmbeddedKeys();
        settings.apiKeys = {
          gemini: userKeys.gemini || embedded.gemini || '',
          safeBrowsing: userKeys.safeBrowsing || embedded.safeBrowsing || '',
          virusTotal: userKeys.virusTotal || embedded.virusTotal || '',
          whois: userKeys.whois || embedded.whois || ''
        };
      }

      resolve(settings);
    });
  });
}

function saveToHistory(result) {
  chrome.storage.local.get('history', (data) => {
    const history = data.history || [];
    history.unshift({
      url: result.url, domain: result.domain,
      riskLevel: result.riskLevel, riskLabel: result.riskLabel, timestamp: result.timestamp
    });
    if (history.length > 100) history.splice(100);
    chrome.storage.local.set({ history });
  });
}
