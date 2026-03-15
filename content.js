// ============================================================================
// AlertaWeb — Content Script (AUDITED)
// Extrai dados da página para análise de golpes
// ============================================================================

(() => {
  'use strict';

  if (window.__scamGuardInjected) return;
  window.__scamGuardInjected = true;

  // FIX #11: Limite de texto para funções de detecção (performance)
  const TEXT_LIMIT = 30000;

  function extractPageData() {
    return {
      url: window.location.href,
      domain: window.location.hostname,
      protocol: window.location.protocol,
      pathname: window.location.pathname,
      title: document.title || '',
      meta: extractMetaData(),
      links: extractLinks(),
      forms: extractForms(),
      text: extractTextContent(),
      images: extractImageData(),
      scripts: extractScriptData(),
      security: extractSecurityInfo(),
      suspiciousPatterns: detectSuspiciousPatterns(),
      timestamps: { extracted: Date.now() }
    };
  }

  function extractMetaData() {
    const metas = {};
    document.querySelectorAll('meta').forEach(meta => {
      const name = meta.getAttribute('name') || meta.getAttribute('property') || meta.getAttribute('http-equiv');
      const content = meta.getAttribute('content');
      if (name && content) {
        metas[name.toLowerCase()] = content;
      }
    });
    return metas;
  }

  function extractLinks() {
    const anchors = document.querySelectorAll('a[href]');
    const currentDomain = window.location.hostname;
    let externalCount = 0;
    let suspiciousCount = 0;
    const domains = new Set();

    anchors.forEach(a => {
      try {
        const url = new URL(a.href, window.location.origin);
        const isExternal = url.hostname !== currentDomain;
        if (isExternal) {
          externalCount++;
          domains.add(url.hostname);
        }
        const isSuspicious =
          url.protocol === 'javascript:' ||
          a.href.includes('data:') ||
          (isExternal && a.textContent.includes(currentDomain)) ||
          url.hostname.includes('bit.ly') ||
          url.hostname.includes('tinyurl') ||
          url.hostname.includes('t.co') ||
          /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname);
        if (isSuspicious) suspiciousCount++;
      } catch (e) { /* URL inválida */ }
    });

    return {
      total: anchors.length,
      external: externalCount,
      suspicious: suspiciousCount,
      uniqueDomains: domains.size,
      domains: [...domains].slice(0, 20)
    };
  }

  function extractForms() {
    const forms = [];
    document.querySelectorAll('form').forEach(form => {
      const inputs = form.querySelectorAll('input');
      const sensitiveFields = [];

      inputs.forEach(input => {
        const type = (input.type || '').toLowerCase();
        const name = (input.name || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        const id = input.id || '';
        const wrappingLabel = input.closest('label')?.textContent?.toLowerCase() || '';
        const forLabel = id ? (document.querySelector(`label[for="${id}"]`)?.textContent?.toLowerCase() || '') : '';
        const label = `${wrappingLabel} ${forLabel}`;
        const combined = `${name} ${placeholder} ${label}`;

        if (type === 'password' || combined.includes('senha') || combined.includes('password')) {
          sensitiveFields.push('password');
        }
        if (type === 'tel' || combined.includes('telefone') || combined.includes('phone') || combined.includes('celular')) {
          sensitiveFields.push('phone');
        }
        if (combined.includes('cpf') || combined.includes('ssn') || combined.includes('document')) {
          sensitiveFields.push('document_id');
        }
        if (combined.includes('cartão') || combined.includes('card') || combined.includes('credit') || combined.includes('crédito')) {
          sensitiveFields.push('credit_card');
        }
        if (combined.includes('cvv') || combined.includes('cvc') || combined.includes('security code')) {
          sensitiveFields.push('cvv');
        }
        if (combined.includes('bank') || combined.includes('banco') || combined.includes('agência') ||
            combined.includes('número da conta') || combined.includes('conta bancária') || combined.includes('conta corrente')) {
          sensitiveFields.push('bank_info');
        }
        if (type === 'email' || combined.includes('email') || combined.includes('e-mail')) {
          sensitiveFields.push('email');
        }
        if (combined.includes('chave pix') || combined.includes('pix key') || (combined.includes('pix') && combined.includes('chave'))) {
          sensitiveFields.push('pix_key');
        }
      });

      const action = form.action || '';
      let actionDomain = '';
      try {
        actionDomain = new URL(action, window.location.origin).hostname;
      } catch (e) {}

      // FIX #13: Consistência — variável única para lógica de domínio externo
      const isExternal = !!(actionDomain && actionDomain !== window.location.hostname);

      forms.push({
        action: action.substring(0, 200),
        method: (form.method || 'GET').toUpperCase(),
        inputCount: inputs.length,
        sensitiveFields: [...new Set(sensitiveFields)],
        submitsExternally: isExternal,
        externalDomain: isExternal ? actionDomain : null
      });
    });
    return forms;
  }

  function extractTextContent() {
    const body = document.body?.innerText || '';
    // FIX #11: Limita texto ANTES de processar para evitar lag em páginas enormes
    const capped = body.substring(0, TEXT_LIMIT);
    const truncated = body.substring(0, 5000);

    return {
      length: body.length,
      sample: truncated,
      hasUrgencyLanguage: detectUrgencyLanguage(capped),
      hasPricePatterns: detectPricePatterns(capped),
      hasGuaranteePatterns: detectGuaranteePatterns(capped)
    };
  }

  function detectUrgencyLanguage(text) {
    const lower = text.toLowerCase();
    const urgencyTerms = [
      'última chance', 'last chance', 'urgente', 'urgent',
      'não perca', "don't miss", 'tempo limitado', 'limited time',
      'oferta expira', 'offer expires', 'restam apenas',
      'aja agora', 'act now', 'imediatamente', 'immediately',
      'conta suspensa', 'account suspended', 'conta bloqueada', 'account blocked',
      'verificação obrigatória', 'verify your account', 'confirme sua identidade',
      'clique aqui imediatamente', 'click here immediately',
      'você foi selecionado', 'you have been selected', 'you won',
      'você ganhou', 'parabéns', 'congratulations',
      'promoção imperdível',
      'prêmio', 'prize', 'sorteio', 'lottery',
      'risco de perder', 'risk of losing', 'antes que acabe',
      'vagas limitadas', 'limited spots', 'exclusivo para você'
    ];
    // Apenas includes() — sem regex perigoso (FIX implícito do "only .* left")
    const found = urgencyTerms.filter(term => lower.includes(term));
    return { detected: found.length > 0, count: found.length, terms: found.slice(0, 10) };
  }

  function detectPricePatterns(text) {
    const patterns = {
      hugDiscount: /(\d{2,3})%\s*(off|desconto|de desconto)/gi,
      freeShipping: /(frete\s*gr[áa]tis|free\s*shipping)/gi,
      fromTo: /(de\s*R\$\s*[\d.,]+\s*por\s*R\$\s*[\d.,]+|was\s*\$[\d.,]+\s*now\s*\$[\d.,]+)/gi,
      tooGoodPrices: /R\$\s*0[.,]\d{2}\b/g,
      cryptocurrency: /(bitcoin|btc|ethereum|eth|crypto|criptomoeda|carteira\s*digital)/gi,
      pix: /(transferência\s*pix|chave\s*pix|pagamento\s*pix|somente\s*pix)/gi,
      gamblingMultiplier: /R\$\s*\d{1,4}\s*x\s*\d{1,3}|ganhe\s*(até\s*)?R\$\s*\d{2,}/gi
    };
    const results = {};
    for (const [key, regex] of Object.entries(patterns)) {
      const matches = text.match(regex);
      results[key] = matches ? matches.length : 0;
    }
    return results;
  }

  function detectGuaranteePatterns(text) {
    const lower = text.toLowerCase();
    const guaranteeTerms = [
      'garantido', 'guaranteed', '100% seguro', '100% safe',
      'sem risco', 'no risk', 'dinheiro de volta', 'money back',
      'resultados garantidos', 'guaranteed results',
      'enriqueça', 'get rich', 'ganhe dinheiro', 'make money',
      'renda extra', 'extra income', 'trabalhe de casa', 'work from home',
      'investimento seguro', 'safe investment', 'retorno garantido',
      'lucro certo', 'guaranteed profit', 'sem esforço', 'effortless'
    ];
    const found = guaranteeTerms.filter(term => lower.includes(term));
    return { detected: found.length > 0, count: found.length, terms: found.slice(0, 10) };
  }

  function extractImageData() {
    const images = document.querySelectorAll('img');
    let brokenCount = 0;
    let stockImageIndicators = 0;
    images.forEach(img => {
      if (!img.naturalWidth || img.naturalWidth === 0) brokenCount++;
      const src = (img.src || '').toLowerCase();
      if (src.includes('stock') || src.includes('shutterstock') ||
          src.includes('unsplash') || src.includes('pexels') ||
          src.includes('placeholder') || src.includes('lorem')) {
        stockImageIndicators++;
      }
    });
    return { total: images.length, broken: brokenCount, stockIndicators: stockImageIndicators };
  }

  function extractScriptData() {
    const scripts = document.querySelectorAll('script[src]');
    const inlineScripts = document.querySelectorAll('script:not([src])');
    const externalDomains = new Set();
    let suspiciousScripts = 0;

    scripts.forEach(script => {
      try {
        const url = new URL(script.src, window.location.origin);
        if (url.hostname !== window.location.hostname) {
          externalDomains.add(url.hostname);
        }
        const src = script.src.toLowerCase();
        if (src.includes('miner') || src.includes('coinhive') ||
            src.includes('cryptoloot') || src.includes('obfuscate')) {
          suspiciousScripts++;
        }
      } catch (e) { }
    });

    let suspiciousInline = 0;
    inlineScripts.forEach(script => {
      const content = script.textContent || '';
      // FIX #14: Condição de tamanho envolve TODOS os checks, não só o último
      if (content.length > 500) {
        if (content.includes('eval(') || content.includes('document.write(') ||
            content.includes('unescape(') || content.includes('fromCharCode') ||
            content.includes('atob(')) {
          suspiciousInline++;
        }
      }
    });

    return {
      external: scripts.length,
      inline: inlineScripts.length,
      externalDomains: [...externalDomains],
      suspiciousExternal: suspiciousScripts,
      suspiciousInline: suspiciousInline
    };
  }

  function extractSecurityInfo() {
    return {
      isHTTPS: window.location.protocol === 'https:',
      hasMixedContent: detectMixedContent(),
      hasCSP: !!document.querySelector('meta[http-equiv="Content-Security-Policy"]'),
    };
  }

  function detectMixedContent() {
    if (window.location.protocol !== 'https:') return false;
    const elements = [
      ...document.querySelectorAll('img[src^="http:"]'),
      ...document.querySelectorAll('script[src^="http:"]'),
      ...document.querySelectorAll('link[href^="http:"]'),
      ...document.querySelectorAll('iframe[src^="http:"]')
    ];
    return elements.length > 0;
  }

  function detectSuspiciousPatterns() {
    return {
      hasAggressivePopups: !!document.querySelector('[class*="popup"][class*="urgent"], [class*="overlay"][class*="force"], [id*="popup"][id*="exit"]'),

      hasCountdownTimers: !!document.querySelector('[class*="countdown"], [class*="timer"], [id*="countdown"], [id*="timer"]') ||
                          !!(document.body?.innerText.match(/\b\d{1,2}:\d{2}:\d{2}\b/g)?.length > 0),

      hasHiddenIframes: (() => {
        const iframes = document.querySelectorAll('iframe');
        let hidden = 0;
        iframes.forEach(iframe => {
          const style = window.getComputedStyle(iframe);
          if (style.opacity === '0' || style.visibility === 'hidden' ||
              (parseInt(style.width) < 3 && parseInt(style.height) < 3)) {
            hidden++;
          }
        });
        return hidden > 0;
      })(),

      // FIX #8: Detecta contextmenu tanto via atributo HTML quanto via property JS
      hasRightClickDisabled: (() => {
        const bodyAttr = document.body?.getAttribute('oncontextmenu') || '';
        const htmlAttr = document.documentElement?.getAttribute('oncontextmenu') || '';
        const hasInline = (bodyAttr + htmlAttr).includes('return false') ||
                          (bodyAttr + htmlAttr).includes('preventDefault');
        const hasProperty = typeof document.oncontextmenu === 'function';
        return hasInline || hasProperty;
      })(),

      hasCopyDisabled: !!document.querySelector('[oncopy="return false"], [onpaste="return false"]'),

      hasHiddenText: (() => {
        const els = document.querySelectorAll('p, span, div, h1, h2, h3, h4, h5, h6, a, li');
        let hidden = 0;
        for (let i = 0; i < Math.min(els.length, 500); i++) {
          const el = els[i];
          if (el.textContent.trim().length < 20) continue;
          const style = window.getComputedStyle(el);
          const fontSize = parseFloat(style.fontSize);
          const opacity = parseFloat(style.opacity);
          if (fontSize <= 1 || opacity === 0 ||
              style.color === style.backgroundColor ||
              (style.position === 'absolute' && (parseInt(style.left) < -900 || parseInt(style.top) < -900))) {
            hidden++;
          }
        }
        return hidden > 0;
      })(),

      hasFavicon: !!document.querySelector('link[rel*="icon"]'),

      // FIX #6: Regex mais específica — evita falso-positivo por "email" isolado
      hasContactInfo: !!(document.body?.innerText.match(
        /(contato|contact us|suporte|support|fale conosco|atendimento|telefone|phone|whatsapp|sac@|contato@|\(\d{2}\)\s*\d{4,5}-?\d{4})/i
      )),

      hasLegalPages: !!document.querySelector('a[href*="privacy"], a[href*="privacidade"], a[href*="terms"], a[href*="termos"], a[href*="policy"]'),

      hasPhysicalAddress: !!(document.body?.innerText.match(/(CEP\s*\d{5}|zip\s*code|endereço|CNPJ\s*[\d.\/\-]+|cnpj\s*[\d.\/\-]+)/i)),

      hasSocialMedia: !!document.querySelector('a[href*="facebook.com"], a[href*="instagram.com"], a[href*="twitter.com"], a[href*="linkedin.com"], a[href*="youtube.com"]'),

      hasSecurityBadges: !!document.querySelector('img[src*="ssl"], img[src*="secure"], img[src*="norton"], img[src*="mcafee"], img[alt*="seguro"], img[alt*="secure"]'),

      domainTyposquatting: checkTyposquatting(window.location.hostname)
    };
  }

  function checkTyposquatting(domain) {
    const knownBrands = [
      'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
      'paypal', 'instagram', 'twitter', 'whatsapp', 'mercadolivre',
      'mercadopago', 'nubank', 'itau', 'bradesco', 'santander',
      'bancodobrasil', 'caixa', 'correios', 'magazineluiza', 'americanas',
      'casasbahia', 'shopee', 'aliexpress', 'ebay', 'walmart'
    ];
    const parts = domain.toLowerCase().split('.');
    const domainName = parts.length >= 2 ? parts.slice(0, -1).join('').replace(/-/g, '') : parts[0].replace(/-/g, '');
    const domainClean = domain.replace(/\./g, '').replace(/-/g, '').toLowerCase();
    const suspicious = [];
    for (const brand of knownBrands) {
      if (domainClean.includes(brand) && !domain.endsWith(getOfficialDomain(brand))) {
        suspicious.push(brand);
      }
      if (domainName !== brand && domainName.length > 3 && levenshteinDistance(domainName, brand) <= 2) {
        suspicious.push(brand + ' (similar)');
      }
    }
    return { detected: suspicious.length > 0, brands: [...new Set(suspicious)] };
  }

  function getOfficialDomain(brand) {
    const map = {
      'google': 'google.com', 'facebook': 'facebook.com', 'amazon': 'amazon.com.br',
      'apple': 'apple.com', 'microsoft': 'microsoft.com', 'netflix': 'netflix.com',
      'paypal': 'paypal.com', 'instagram': 'instagram.com', 'twitter': 'twitter.com',
      'whatsapp': 'whatsapp.com', 'mercadolivre': 'mercadolivre.com.br',
      'mercadopago': 'mercadopago.com.br', 'nubank': 'nubank.com.br',
      'itau': 'itau.com.br', 'bradesco': 'bradesco.com.br',
      'santander': 'santander.com.br', 'bancodobrasil': 'bb.com.br',
      'caixa': 'caixa.gov.br', 'correios': 'correios.com.br',
      'magazineluiza': 'magazineluiza.com.br', 'americanas': 'americanas.com.br',
      'casasbahia': 'casasbahia.com.br', 'shopee': 'shopee.com.br',
      'aliexpress': 'aliexpress.com', 'ebay': 'ebay.com', 'walmart': 'walmart.com'
    };
    return map[brand] || brand + '.com';
  }

  function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
        }
      }
    }
    return matrix[b.length][a.length];
  }

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'extractPageData') {
      try {
        const data = extractPageData();
        sendResponse({ success: true, data });
      } catch (error) {
        sendResponse({ success: false, error: error.message });
      }
    }
    return true;
  });

})();
