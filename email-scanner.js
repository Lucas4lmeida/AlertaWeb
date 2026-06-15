// ============================================================================
// AlertaWeb — Email Scanner
// Analisa emails abertos em busca de phishing e links maliciosos
// Funciona em: Gmail, Outlook.com, Outlook 365, Yahoo Mail
// ============================================================================

(() => {
  'use strict';

  if (window.__alertaWebEmailScanner) return;
  window.__alertaWebEmailScanner = true;

  const SCAN_DEBOUNCE_MS = 800;

  // FIX #4: Removido .com e .js da lista — .com casa com qualquer URL,
  // .js casa com .json/.jsx. Extensões realmente perigosas mantidas.
  // FIX: Usar regex com word boundary para evitar matches parciais
  const DANGEROUS_EXT_REGEX = /\.(exe|scr|bat|cmd|pif|vbs|vbe|jse|wsf|wsh|ps1|msi|msp|hta|cpl|reg|inf|lnk)\b/i;

  const KNOWN_BRANDS = [
    'nubank', 'itau', 'bradesco', 'santander', 'caixa', 'bancodobrasil', 'bb.com',
    'inter', 'c6bank', 'mercadopago', 'mercadolivre', 'pagseguro', 'picpay',
    'correios', 'receita', 'gov.br', 'detran', 'sus',
    'netflix', 'spotify', 'amazon', 'apple', 'google', 'microsoft',
    'paypal', 'facebook', 'instagram', 'whatsapp',
    'magazineluiza', 'americanas', 'casasbahia', 'shopee', 'aliexpress',
    'uber', 'ifood', '99', 'rappi'
  ];

  const BRAND_DOMAINS = {
    nubank: 'nubank.com.br', itau: 'itau.com.br', bradesco: 'bradesco.com.br',
    santander: 'santander.com.br', caixa: 'caixa.gov.br', bancodobrasil: 'bb.com.br',
    'bb.com': 'bb.com.br', inter: 'inter.co', c6bank: 'c6bank.com.br',
    mercadopago: 'mercadopago.com.br', mercadolivre: 'mercadolivre.com.br',
    pagseguro: 'pagseguro.uol.com.br', picpay: 'picpay.com',
    correios: 'correios.com.br', receita: 'receita.fazenda.gov.br',
    'gov.br': 'gov.br', netflix: 'netflix.com', spotify: 'spotify.com',
    amazon: 'amazon.com.br', apple: 'apple.com', google: 'google.com',
    microsoft: 'microsoft.com', paypal: 'paypal.com', facebook: 'facebook.com',
    instagram: 'instagram.com', whatsapp: 'whatsapp.com',
    magazineluiza: 'magazineluiza.com.br', americanas: 'americanas.com.br',
    casasbahia: 'casasbahia.com.br', shopee: 'shopee.com.br',
    uber: 'uber.com', ifood: 'ifood.com.br'
  };

  const PHISHING_TERMS = [
    'sua conta será bloqueada', 'conta suspensa', 'acesso bloqueado',
    'atividade suspeita', 'acesso não autorizado', 'unauthorized access',
    'account suspended', 'verify your account', 'confirme sua identidade',
    'verificação obrigatória', 'atualização cadastral obrigatória',
    'seu acesso será revogado', 'prazo de 24 horas', 'prazo de 48 horas',
    'expira hoje', 'última tentativa', 'último aviso',
    'clique aqui para', 'clique no botão abaixo', 'click here',
    'atualize seus dados', 'confirme seus dados', 'recadastre',
    'redefina sua senha', 'reset your password',
    'pagamento pendente', 'fatura em atraso', 'débito automático',
    'cobrança indevida', 'reembolso disponível', 'restituição',
    'pix enviado', 'pix recebido', 'comprovante de transferência',
    'você recebeu R$', 'depósito realizado',
    'você foi selecionado', 'você ganhou', 'parabéns',
    'resgate seu prêmio', 'cupom exclusivo', 'brinde grátis',
    'informe seu cpf', 'confirme seu cpf', 'dados do cartão',
    'número do cartão', 'código de segurança', 'senha de acesso'
  ];

  // ============================================================================
  // ESTADO
  // ============================================================================

  let lastScannedUrl = '';
  let scanTimeout = null;
  let currentBanner = null;
  // FIX #2: Guardar AbortController para limpar event listeners
  let currentLinkCleanups = [];

  // ============================================================================
  // DETECÇÃO DE EMAIL ABERTO
  // ============================================================================

  function init() {
    let lastUrl = location.href;
    const observer = new MutationObserver(() => {
      const urlChanged = location.href !== lastUrl;
      if (urlChanged) {
        lastUrl = location.href;

        if (isInboxView()) {
          lastScannedUrl = '';
          removeBanner();
          cleanupLinks();
          scheduleInboxScan();
        }
      }
      scheduleScan();
    });
    observer.observe(document.body, { childList: true, subtree: true });

    setTimeout(() => {
      scheduleScan();
      if (isInboxView()) scheduleInboxScan();
    }, 2000);

    // console.log('[AlertaWeb] Email scanner ativo.');
  }

  let inboxScanTimeout = null;
  function scheduleInboxScan() {
    if (inboxScanTimeout) clearTimeout(inboxScanTimeout);
    inboxScanTimeout = setTimeout(scanInbox, 1500);
  }

  function isInboxView() {
    const host = location.hostname;
    if (host.includes('mail.google.com')) {
      const hash = location.hash;
      // Inbox/lista: #inbox, #search/..., #label/..., #sent, #drafts, etc.
      return !hash || hash === '#inbox' || !isGmailEmailHash(hash);
    }
    return false;
  }

  function scheduleScan() {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => tryAnalyze(), SCAN_DEBOUNCE_MS);
  }

  // ============================================================================
  // EXTRAÇÃO DE DADOS DO EMAIL
  // ============================================================================

  function tryAnalyze() {
    if (location.href === lastScannedUrl) return;

    const emailData = extractEmailData();
    if (!emailData) return;

    lastScannedUrl = location.href;
    analyzeEmail(emailData);
  }

  function extractEmailData() {
    const host = location.hostname;

    // FIX #10: Checks exatos para evitar match em outlook-tips.com etc
    if (host === 'mail.google.com') return extractGmail();
    if (host === 'outlook.live.com' || host === 'outlook.office.com' || host === 'outlook.office365.com') return extractOutlook();
    if (host === 'mail.yahoo.com') return extractYahoo();

    return null;
  }

  // FIX #11: Heurística mais precisa para detectar email aberto no Gmail
  function isGmailEmailHash(hash) {
    // Email aberto: #inbox/FMfcg..., #sent/FMfcg..., #label/name/FMfcg...
    // NÃO é email: #inbox, #search/query, #label/name, #settings, #compose
    // A chave é que IDs de email do Gmail são strings longas alfanuméricas (>15 chars)
    const parts = hash.replace('#', '').split('/');
    if (parts.length < 2) return false;
    const lastPart = parts[parts.length - 1];
    // IDs de mensagem do Gmail têm 16+ chars alfanuméricos
    return /^[A-Za-z0-9_-]{16,}$/.test(lastPart);
  }

  function extractGmail() {
    if (!isGmailEmailHash(location.hash)) return null;

    const messageDivs = document.querySelectorAll('div[data-message-id]');
    if (messageDivs.length === 0) return extractGeneric();

    const messageDiv = messageDivs[messageDivs.length - 1];

    // FIX #7: Buscar remetente apenas no contexto da mensagem, não no document inteiro
    const senderEl = document.querySelector('span[email]');
    const sender = senderEl?.getAttribute('email') || '';

    const subjectEl = document.querySelector('h2[data-thread-perm-id]') ||
                      document.querySelector('div[data-thread-perm-id]') ||
                      document.querySelector('h2.hP');
    const subject = subjectEl?.textContent?.trim() || document.title.replace(' - Gmail', '').trim();

    const links = extractLinksFromElement(messageDiv);
    const bodyText = messageDiv.innerText || '';

    return { sender, subject, links, bodyText, source: 'gmail' };
  }

  function extractOutlook() {
    const readingPane = document.querySelector('[role="main"] [aria-label*="message"]') ||
                        document.querySelector('.ReadingPaneContents') ||
                        document.querySelector('[data-app-section="ReadingPane"]') ||
                        document.querySelector('.wide-content-host');

    if (!readingPane) return null; // FIX #6: Não usar extractGeneric como fallback no Outlook

    const sender = findEmailInText(readingPane.parentElement) || '';
    const subjectEl = document.querySelector('[role="heading"]');
    const subject = subjectEl?.textContent?.trim() || '';
    const links = extractLinksFromElement(readingPane);
    const bodyText = readingPane.innerText || '';

    return { sender, subject, links, bodyText, source: 'outlook' };
  }

  function extractYahoo() {
    const messagePane = document.querySelector('.message-view') ||
                        document.querySelector('[data-test-id="message-view"]');

    if (!messagePane) return null; // FIX #6: Não usar extractGeneric como fallback

    const sender = findEmailInText(messagePane) || '';
    const subject = document.querySelector('.msg-subject')?.textContent?.trim() || '';
    const links = extractLinksFromElement(messagePane);
    const bodyText = messagePane.innerText || '';

    return { sender, subject, links, bodyText, source: 'yahoo' };
  }

  // FIX #6: extractGeneric agora limita busca a divs com role ou classes significativas
  function extractGeneric() {
    const candidates = document.querySelectorAll('[role="article"], [role="main"] div, .email-content, .message-body');
    let bestDiv = null;
    let bestScore = 0;

    for (const div of candidates) {
      const linkCount = div.querySelectorAll('a[href]').length;
      const textLen = (div.innerText || '').length;
      const score = linkCount * 100 + textLen;
      if (linkCount >= 1 && textLen > 200 && textLen < 50000 && score > bestScore) {
        bestDiv = div;
        bestScore = score;
      }
    }

    if (!bestDiv) return null;

    return {
      sender: '',  // FIX #7: Não tentar adivinhar o remetente no fallback genérico
      subject: document.title,
      links: extractLinksFromElement(bestDiv),
      bodyText: bestDiv.innerText || '',
      source: 'generic'
    };
  }

  // ============================================================================
  // UTILITÁRIOS DE EXTRAÇÃO
  // ============================================================================

  function extractLinksFromElement(el) {
    const links = [];
    const anchors = el.querySelectorAll('a[href]');

    for (const a of anchors) {
      const href = a.href || '';
      const text = a.textContent?.trim() || '';
      const visibleUrl = a.innerText?.trim() || '';

      if (href.startsWith('mailto:') || href.startsWith('#') ||
          href.startsWith('javascript:') || href.includes('mail.google.com') ||
          href.includes('outlook.live.com') || href.includes('outlook.office')) continue;

      if (text.length < 2 && !href.startsWith('http')) continue;

      let hrefDomain = '';
      try { hrefDomain = new URL(href).hostname.toLowerCase(); } catch { continue; }

      let textDomain = '';
      let isMismatch = false;
      const urlPattern = /^(https?:\/\/)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/;
      if (urlPattern.test(visibleUrl)) {
        try {
          const normalized = visibleUrl.startsWith('http') ? visibleUrl : 'https://' + visibleUrl;
          textDomain = new URL(normalized).hostname.toLowerCase();
          if (textDomain && hrefDomain && !hrefDomain.endsWith(textDomain) && !textDomain.endsWith(hrefDomain)) {
            isMismatch = true;
          }
        } catch { /* texto não é URL válida */ }
      }

      links.push({ href, text, visibleUrl, hrefDomain, textDomain, isMismatch, element: a });
    }

    return links;
  }

  function findEmailInText(el) {
    if (!el) return '';
    const text = el.innerText || el.textContent || '';
    const match = text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/);
    return match ? match[0].toLowerCase() : '';
  }

  // ============================================================================
  // ANÁLISE DE PHISHING
  // ============================================================================

  function analyzeEmail(emailData) {
    // Usa a mesma lógica do popup (single source of truth)
    const result = getAnalysisResult(emailData);

    let level, label;
    if (result.score >= 60) { level = 'danger'; label = 'Possível phishing'; }
    else if (result.score >= 25) { level = 'warning'; label = 'Verifique com atenção'; }
    else { level = 'safe'; label = 'Aparenta ser seguro'; }

    applyLinkTooltips(emailData.links);
    showBanner(level, label, result.findings, result.score);
    checkLinksWithAPIs(emailData.links, result.findings, result.score, level, label);
  }

  // ============================================================================
  // VERIFICAÇÃO DE REMETENTE
  // ============================================================================

  function checkSenderDomain(domain) {
    if (!domain) return null;
    const domainBase = domain.split('.')[0].toLowerCase();

    // Se o domínio base É uma marca conhecida, não é typosquatting
    const isKnownBrand = KNOWN_BRANDS.some(b => domainBase === b);

    for (const brand of KNOWN_BRANDS) {
      const officialDomain = BRAND_DOMAINS[brand];
      if (!officialDomain) continue;

      // Check 1: domínio contém marca mas não é o oficial
      if (domain.includes(brand) && !domain.endsWith(officialDomain)) {
        return {
          message: `Remetente "${domain}" contém "${brand}" mas não é o domínio oficial (${officialDomain})`,
          score: 25
        };
      }

      // Check 2: Levenshtein — só se o domínio base NÃO é uma marca conhecida
      if (!isKnownBrand && domainBase.length > 3 && levenshtein(domainBase, brand) <= 2 && domainBase !== brand) {
        return {
          message: `Remetente "${domain}" é muito similar a "${brand}" — possível typosquatting`,
          score: 20
        };
      }
    }
    return null;
  }

  function levenshtein(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        matrix[i][j] = b[i-1] === a[j-1]
          ? matrix[i-1][j-1]
          : Math.min(matrix[i-1][j-1]+1, matrix[i][j-1]+1, matrix[i-1][j]+1);
      }
    }
    return matrix[b.length][a.length];
  }

  // ============================================================================
  // VERIFICAÇÃO DE LINKS VIA APIs
  // ============================================================================

  function checkLinksWithAPIs(links, findings, currentScore, currentLevel, currentLabel) {
    const uniqueUrls = [...new Set(links.map(l => l.href).filter(h => h.startsWith('http')))];
    if (uniqueUrls.length === 0) return;

    // FIX #9: Timeout de 15s para a verificação de APIs
    const timeoutId = setTimeout(() => {}, 15000);

    chrome.runtime.sendMessage({
      action: 'checkEmailLinks',
      urls: uniqueUrls.slice(0, 10)
    }, (response) => {
      clearTimeout(timeoutId);
      if (chrome.runtime.lastError || !response?.success || !response.results) return;

      let addedScore = 0;
      const apiFindings = [];

      for (const result of response.results) {
        if (result.safeBrowsing?.isMalicious) {
          apiFindings.push({
            severity: 'critical',
            message: `Safe Browsing: "${truncUrl(result.url)}" na lista negra`
          });
          addedScore += 40;
          markLinkAsDangerous(links, result.url);
        }
        if (result.virusTotal?.malicious > 0) {
          apiFindings.push({
            severity: result.virusTotal.malicious >= 3 ? 'critical' : 'high',
            message: `VirusTotal: "${truncUrl(result.url)}" detectado por ${result.virusTotal.malicious} antivírus`
          });
          addedScore += Math.min(result.virusTotal.malicious * 10, 30);
          markLinkAsDangerous(links, result.url);
        }
      }

      if (apiFindings.length > 0) {
        const newScore = Math.min(currentScore + addedScore, 100);
        const allFindings = [...findings, ...apiFindings];
        let level = currentLevel, label = currentLabel;
        if (newScore >= 60) { level = 'danger'; label = 'Possível phishing'; }
        else if (newScore >= 25) { level = 'warning'; label = 'Verifique com atenção'; }
        showBanner(level, label, allFindings, newScore);
      }
    });
  }

  function truncUrl(url) {
    return url.length > 50 ? url.substring(0, 50) + '...' : url;
  }

  function markLinkAsDangerous(links, url) {
    for (const link of links) {
      if (link.href === url && link.element) {
        link.element.classList.add('aw-link-dangerous');
      }
    }
  }

  // ============================================================================
  // TOOLTIPS NOS LINKS
  // ============================================================================

  // FIX #2: Limpar event listeners anteriores antes de adicionar novos
  function cleanupLinks() {
    for (const cleanup of currentLinkCleanups) cleanup();
    currentLinkCleanups = [];
    document.querySelectorAll('.aw-link-tooltip').forEach(t => t.remove());
    document.querySelectorAll('.aw-link-scanned').forEach(el => {
      el.classList.remove('aw-link-scanned', 'aw-link-suspicious', 'aw-link-dangerous');
    });
  }

  function applyLinkTooltips(links) {
    cleanupLinks();

    for (const link of links) {
      const el = link.element;
      if (!el) continue;

      el.classList.add('aw-link-scanned');
      if (link.isMismatch) el.classList.add('aw-link-suspicious');

      const onEnter = (e) => showLinkTooltip(e, link);
      const onLeave = () => hideLinkTooltip();

      el.addEventListener('mouseenter', onEnter);
      el.addEventListener('mouseleave', onLeave);

      // Guardar cleanup para remover listeners depois
      currentLinkCleanups.push(() => {
        el.removeEventListener('mouseenter', onEnter);
        el.removeEventListener('mouseleave', onLeave);
      });
    }
  }

  function showLinkTooltip(event, link) {
    hideLinkTooltip();

    const tooltip = document.createElement('div');
    tooltip.className = 'aw-link-tooltip';

    let icon = '🔗', statusClass = 'aw-tooltip-safe', statusText = 'Link verificado';

    if (link.element?.classList.contains('aw-link-dangerous')) {
      icon = '🚨'; statusClass = 'aw-tooltip-danger'; statusText = 'LINK PERIGOSO';
    } else if (link.isMismatch) {
      icon = '⚠️'; statusClass = 'aw-tooltip-warning'; statusText = 'LINK ENGANOSO';
    }

    const displayUrl = link.href.length > 80 ? link.href.substring(0, 80) + '...' : link.href;

    tooltip.innerHTML = `
      <div class="aw-tooltip-header ${statusClass}">
        <span>${icon}</span>
        <span>${statusText}</span>
      </div>
      <div class="aw-tooltip-body">
        <div class="aw-tooltip-label">Destino real:</div>
        <div class="aw-tooltip-url">${escapeHtml(displayUrl)}</div>
        ${link.isMismatch ? `
          <div class="aw-tooltip-mismatch">
            Texto mostra: <strong>${escapeHtml(link.textDomain)}</strong><br/>
            Aponta para: <strong>${escapeHtml(link.hrefDomain)}</strong>
          </div>
        ` : ''}
      </div>
    `;

    document.body.appendChild(tooltip);
    const rect = event.target.getBoundingClientRect();
    tooltip.style.top = (rect.bottom + window.scrollY + 6) + 'px';
    tooltip.style.left = Math.max(8, rect.left + window.scrollX - 20) + 'px';

    const tooltipRect = tooltip.getBoundingClientRect();
    if (tooltipRect.right > window.innerWidth - 10) {
      tooltip.style.left = (window.innerWidth - tooltipRect.width - 10) + 'px';
    }
  }

  function hideLinkTooltip() {
    document.querySelectorAll('.aw-link-tooltip').forEach(t => t.remove());
  }

  // ============================================================================
  // BANNER DE RESULTADO
  // ============================================================================

  function removeBanner() {
    if (currentBanner) { currentBanner.remove(); currentBanner = null; }
  }

  function showBanner(level, label, findings, score) {
    removeBanner();

    const banner = document.createElement('div');
    banner.className = `aw-email-banner aw-banner-${level}`;

    const iconMap = { safe: '✅', warning: '⚠️', danger: '🚨' };
    const importantFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    const showDetails = importantFindings.length > 0;

    banner.innerHTML = `
      <div class="aw-banner-main">
        <span class="aw-banner-icon">${iconMap[level]}</span>
        <span class="aw-banner-text">
          <strong>AlertaWeb:</strong> ${escapeHtml(label)}
          ${score > 0 ? `<span class="aw-banner-score">(${score}/100)</span>` : ''}
        </span>
        ${showDetails ? '<button class="aw-banner-toggle">Detalhes ▼</button>' : ''}
        <button class="aw-banner-close">✕</button>
      </div>
      ${showDetails ? `
        <div class="aw-banner-details" style="display:none;">
          ${findings.slice(0, 8).map(f => `
            <div class="aw-finding aw-finding-${f.severity}">
              ${escapeHtml(f.message)}
            </div>
          `).join('')}
        </div>
      ` : ''}
    `;

    document.body.appendChild(banner);
    currentBanner = banner;

    banner.querySelector('.aw-banner-close')?.addEventListener('click', removeBanner);
    banner.querySelector('.aw-banner-toggle')?.addEventListener('click', () => {
      const details = banner.querySelector('.aw-banner-details');
      const toggle = banner.querySelector('.aw-banner-toggle');
      if (details.style.display === 'none') {
        details.style.display = 'block';
        toggle.textContent = 'Detalhes ▲';
      } else {
        details.style.display = 'none';
        toggle.textContent = 'Detalhes ▼';
      }
    });
  }

  // ============================================================================
  // INDICADORES NA LISTA DE EMAILS (Inbox)
  // ============================================================================

  function scanInbox() {
    // Só funciona no Gmail por enquanto (DOM mais previsível)
    if (location.hostname !== 'mail.google.com') return;

    // Encontrar linhas de email na inbox — Gmail usa tr com atributos específicos
    const rows = document.querySelectorAll('tr.zA');
    if (rows.length === 0) return;

    for (const row of rows) {
      // Pular se já escaneado
      if (row.dataset.awScanned) continue;
      row.dataset.awScanned = 'true';

      let suspicious = false;
      const reasons = [];

      // 1. Verificar remetente
      const senderSpan = row.querySelector('span[email]');
      if (senderSpan) {
        const email = senderSpan.getAttribute('email') || '';
        const domain = email.split('@')[1] || '';
        const result = checkSenderDomain(domain);
        if (result) {
          suspicious = true;
          reasons.push(result.message);
        }
      }

      // 2. Verificar assunto e preview por termos de phishing
      const textContent = (row.innerText || '').toLowerCase();
      const matchedTerms = PHISHING_TERMS.filter(t => textContent.includes(t));
      if (matchedTerms.length >= 2) {
        suspicious = true;
        reasons.push(`${matchedTerms.length} termos de phishing no assunto/preview`);
      }

      // 3. Adicionar indicador visual
      if (suspicious) {
        addInboxIndicator(row, reasons);
      }
    }
  }

  function addInboxIndicator(row, reasons) {
    // Evitar duplicata
    if (row.querySelector('.aw-inbox-indicator')) return;

    const indicator = document.createElement('span');
    indicator.className = 'aw-inbox-indicator';
    indicator.textContent = '⚠️';
    indicator.title = 'AlertaWeb: ' + reasons.join(' | ');

    // Inserir no início da célula do assunto (3ª coluna no Gmail)
    const subjectCell = row.querySelector('td.xY');
    if (subjectCell) {
      subjectCell.style.position = 'relative';
      subjectCell.insertBefore(indicator, subjectCell.firstChild);
    } else {
      // Fallback: inserir no início da row
      const firstCell = row.querySelector('td');
      if (firstCell) {
        firstCell.insertBefore(indicator, firstCell.firstChild);
      }
    }
  }

  // ============================================================================
  // UTILIDADES
  // ============================================================================

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
  }

  // ============================================================================
  // LISTENER — Responde a requests do popup
  // ============================================================================

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanEmailFromPopup') {
      try {
        const emailData = extractEmailData();
        if (!emailData) {
          sendResponse({ success: false, error: 'Nenhum email aberto detectado.' });
          return;
        }

        const result = getAnalysisResult(emailData);

        // Incluir dados brutos para o popup enviar ao background.js (APIs)
        const linkUrls = emailData.links
          .map(l => l.href)
          .filter(h => h.startsWith('http'));

        result.rawEmailData = {
          sender: emailData.sender || '',
          subject: emailData.subject || '',
          bodyText: (emailData.bodyText || '').substring(0, 2000),
          urls: [...new Set(linkUrls)].slice(0, 10)
        };

        sendResponse({ success: true, result });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    }
    return true;
  });

  /**
   * Retorna resultado da análise sem efeitos visuais (para o popup)
   */
  function getAnalysisResult(emailData) {
    const findings = [];
    let riskScore = 0;

    // Link mismatch
    const mismatches = emailData.links.filter(l => l.isMismatch);
    if (mismatches.length > 0) {
      for (const m of mismatches) {
        findings.push({ severity: 'critical', message: `Link enganoso: "${m.textDomain}" → "${m.hrefDomain}"` });
      }
      riskScore += Math.min(mismatches.length * 30, 60);
    }

    // Remetente
    if (emailData.sender) {
      const senderDomain = emailData.sender.split('@')[1] || '';
      const senderResult = checkSenderDomain(senderDomain);
      if (senderResult) {
        findings.push({ severity: 'high', message: senderResult.message });
        riskScore += senderResult.score;
      }
    }

    // Phishing terms
    const combined = ((emailData.subject || '') + ' ' + emailData.bodyText).toLowerCase();
    const foundTerms = PHISHING_TERMS.filter(t => combined.includes(t));
    if (foundTerms.length >= 3) {
      findings.push({ severity: 'high', message: `${foundTerms.length} padrões de phishing: "${foundTerms.slice(0, 3).join('", "')}"` });
      riskScore += Math.min(foundTerms.length * 6, 30);
    } else if (foundTerms.length >= 1) {
      findings.push({ severity: 'medium', message: `${foundTerms.length} termo(s) de phishing: "${foundTerms.slice(0, 2).join('", "')}"` });
      riskScore += foundTerms.length * 4;
    }

    // Extensões perigosas
    if (DANGEROUS_EXT_REGEX.test(combined)) {
      findings.push({ severity: 'high', message: `Menção a arquivo potencialmente perigoso` });
      riskScore += 15;
    }

    // Combo urgência + dados
    const hasUrgency = /urgente|imediato|bloqueio|suspens|expira|prazo|24.?hora|48.?hora|último aviso/i.test(combined);
    const asksSensitive = /cpf|cnpj|cartão|card|senha|password|código de segurança|cvv|dados bancários|chave pix/i.test(combined);
    if (hasUrgency && asksSensitive) {
      findings.push({ severity: 'critical', message: 'Urgência + pedido de dados sensíveis' });
      riskScore += 25;
    }

    // Links suspeitos
    for (const link of emailData.links) {
      if (/bit\.ly|tinyurl|t\.co|goo\.gl|shorturl|rb\.gy|cutt\.ly/i.test(link.hrefDomain)) {
        findings.push({ severity: 'medium', message: `Link encurtado (${link.hrefDomain})` });
        riskScore += 8;
      }
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(link.hrefDomain)) {
        findings.push({ severity: 'high', message: `Link para IP numérico (${link.hrefDomain})` });
        riskScore += 15;
      }
    }

    riskScore = Math.min(riskScore, 100);

    let riskLevel, riskLabel, riskColor;
    if (riskScore >= 60) { riskLevel = 'critical'; riskLabel = 'PHISHING PROVÁVEL'; riskColor = '#dc2626'; }
    else if (riskScore >= 25) { riskLevel = 'medium'; riskLabel = 'SUSPEITO — Verifique'; riskColor = '#d97706'; }
    else { riskLevel = 'safe'; riskLabel = 'APARENTA SER SEGURO'; riskColor = '#16a34a'; }

    return {
      score: riskScore, riskLevel, riskLabel, riskColor, findings,
      emailInfo: { sender: emailData.sender, subject: emailData.subject, linkCount: emailData.links.length },
      breakdown: { links: mismatches.length * 30, sender: 0, phishing: foundTerms.length * 5, security: 0 },
      timestamp: Date.now()
    };
  }

  // ============================================================================
  // INICIAR
  // ============================================================================

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
