// ============================================================================
// AlertaWeb — Popup Controller (AUDITED)
// ============================================================================

'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const DOM = {
  viewMain: $('#view-main'),
  viewSettings: $('#view-settings'),
  viewHistory: $('#view-history'),
  btnHistory: $('#btn-history'),
  btnSettings: $('#btn-settings'),
  siteDomain: $('#site-domain'),
  siteUrl: $('#site-url'),
  siteFavicon: $('#site-favicon'),
  btnAnalyze: $('#btn-analyze'),
  btnScanEmail: $('#btn-scan-email'),
  loadingState: $('#loading-state'),
  loadingSteps: $('#loading-steps'),
  resultContainer: $('#result-container'),
  riskLevelBadge: $('#risk-level-badge'),
  riskIcon: $('#risk-icon'),
  riskText: $('#risk-text'),
  summaryText: $('#summary-text'),
  apisUsed: $('#apis-used'),
  findingsList: $('#findings-list'),
  btnReport: $('#btn-report'),
  btnReanalyze: $('#btn-reanalyze'),
  btnBackSettings: $('#btn-back-settings'),
  apiGemini: $('#api-gemini'),
  apiWhois: $('#api-whois'),
  apiSafeBrowsing: $('#api-safebrowsing'),
  apiVirusTotal: $('#api-virustotal'),
  settingNotifications: $('#setting-notifications'),
  btnSaveSettings: $('#btn-save-settings'),
  btnBackHistory: $('#btn-back-history'),
  btnClearHistory: $('#btn-clear-history'),
  historyList: $('#history-list')
};

let currentTabId = null;
let currentUrl = '';
// FIX #7 e #9: Referências explícitas para cleanup de timers/animações
let loadingInterval = null;

// ============================================================================
// INICIALIZAÇÃO
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  await initializePopup();
  attachEventListeners();
});

async function initializePopup() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    currentTabId = tab.id;
    currentUrl = tab.url || '';

    try {
      const url = new URL(currentUrl);
      DOM.siteDomain.textContent = url.hostname;
      DOM.siteUrl.textContent = currentUrl.length > 50
        ? currentUrl.substring(0, 50) + '...'
        : currentUrl;

      // FIX #1/#2: usar createElement ao invés de innerHTML (CSP + XSS safe)
      const faviconImg = document.createElement('img');
      faviconImg.src = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(url.hostname)}&sz=32`;
      faviconImg.alt = '';
      faviconImg.addEventListener('error', () => { faviconImg.style.display = 'none'; });
      DOM.siteFavicon.textContent = '';
      DOM.siteFavicon.appendChild(faviconImg);
    } catch {
      DOM.siteDomain.textContent = 'Página local ou interna';
      DOM.siteUrl.textContent = currentUrl;
    }

    // Verificar cache
    chrome.runtime.sendMessage({ action: 'getCachedResult', url: currentUrl }, (response) => {
      if (response?.success && response.result) {
        // FIX #5: Esconder botão "Analisar" quando mostrando resultado cacheado
        DOM.btnAnalyze.classList.add('hidden');
        displayResults(response.result);
      }
    });

    // Desabilitar para páginas especiais
    if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://') ||
        currentUrl.startsWith('about:') || currentUrl === '') {
      DOM.btnAnalyze.disabled = true;
      DOM.btnAnalyze.textContent = 'Não disponível para esta página';
    }

    // Detectar webmail e mostrar botão de scan de email
    const WEBMAIL_DOMAINS = ['mail.google.com', 'outlook.live.com', 'outlook.office.com', 'outlook.office365.com', 'mail.yahoo.com'];
    try {
      const hostname = new URL(currentUrl).hostname;
      if (WEBMAIL_DOMAINS.includes(hostname)) {
        DOM.btnScanEmail.classList.remove('hidden');
      }
    } catch { /* URL inválida */ }
  }

  loadSettings();
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function attachEventListeners() {
  DOM.btnSettings.addEventListener('click', () => switchView('settings'));
  DOM.btnHistory.addEventListener('click', () => {
    loadHistory();
    switchView('history');
  });
  DOM.btnBackSettings.addEventListener('click', () => switchView('main'));
  DOM.btnBackHistory.addEventListener('click', () => switchView('main'));
  DOM.btnClearHistory.addEventListener('click', clearHistory);
  DOM.btnAnalyze.addEventListener('click', () => startAnalysis(false));
  DOM.btnScanEmail.addEventListener('click', startEmailScan);
  DOM.btnReanalyze.addEventListener('click', () => {
    DOM.resultContainer.classList.add('hidden');
    startAnalysis(true);  // forçar reanálise, ignorando cache
  });
  DOM.btnSaveSettings.addEventListener('click', saveSettings);
  DOM.btnReport.addEventListener('click', () => {
    const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(currentUrl)}`;
    chrome.tabs.create({ url: reportUrl });
  });
}

// ============================================================================
// NAVEGAÇÃO
// ============================================================================

function switchView(viewName) {
  $$('.view').forEach(v => v.classList.remove('active'));
  const target = $(`#view-${viewName}`);
  if (target) target.classList.add('active');
  const header = $('.header');
  header.style.display = viewName === 'main' ? '' : 'none';
}

// ============================================================================
// ANÁLISE
// ============================================================================

async function startAnalysis(forceReanalyze = false) {
  if (!currentTabId) return;

  DOM.btnAnalyze.classList.add('hidden');
  DOM.resultContainer.classList.add('hidden');
  DOM.loadingState.classList.remove('hidden');

  animateLoadingSteps();

  try {
    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { action: 'analyzeTab', tabId: currentTabId, forceReanalyze },
        (resp) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (resp?.success) resolve(resp.result);
          else reject(new Error(resp?.error || 'Erro desconhecido'));
        }
      );
    });

    // FIX #7: Limpar loading interval ANTES de mostrar resultado
    cleanupLoading();
    DOM.loadingState.classList.add('hidden');
    displayResults(response);

  } catch (error) {
    // FIX #7: Limpar loading interval também em caso de erro
    cleanupLoading();
    DOM.loadingState.classList.add('hidden');
    DOM.btnAnalyze.classList.remove('hidden');
    showToast(`Erro: ${error.message}`);
  }
}

async function startEmailScan() {
  if (!currentTabId) return;

  DOM.btnScanEmail.classList.add('hidden');
  DOM.btnAnalyze.classList.add('hidden');
  DOM.resultContainer.classList.add('hidden');
  DOM.loadingState.classList.remove('hidden');

  try {
    // 1. Análise local via email-scanner.js
    const localResult = await new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(currentTabId, { action: 'scanEmailFromPopup' }, (resp) => {
        if (chrome.runtime.lastError) {
          reject(new Error('Scanner de email não disponível. Recarregue a página.'));
          return;
        }
        if (resp?.success) resolve(resp.result);
        else reject(new Error(resp?.error || 'Nenhum email aberto detectado.'));
      });
    });

    // 2. Mostrar resultado local imediatamente
    DOM.loadingState.classList.add('hidden');
    displayResults({
      riskLevel: localResult.riskLevel,
      riskLabel: localResult.riskLabel,
      riskColor: localResult.riskColor,
      summary: localResult.emailInfo
        ? `De: ${localResult.emailInfo.sender || '?'} | ${localResult.emailInfo.linkCount || 0} link(s). Verificando APIs...`
        : 'Analisando...',
      findings: localResult.findings,
      apisUsed: []
    });

    // 3. Chamar APIs em background
    if (localResult.rawEmailData) {
      const apiTimeout = setTimeout(() => {
        DOM.apisUsed.textContent = 'APIs não responderam (timeout).';
      }, 20000);

      chrome.runtime.sendMessage({
        action: 'analyzeEmailWithAPIs',
        emailData: localResult.rawEmailData
      }, (apiResponse) => {
        clearTimeout(apiTimeout);
        if (chrome.runtime.lastError || !apiResponse?.success) {
          DOM.apisUsed.textContent = 'APIs indisponíveis.';
          return;
        }

        const apiResult = apiResponse.result;
        const apiFindings = [...localResult.findings];
        const apisUsed = [];

        if (apiResult.linkResults?.length > 0) {
          apisUsed.push('Safe Browsing', 'VirusTotal');
          for (const lr of apiResult.linkResults) {
            if (lr.safeBrowsing?.isMalicious)
              apiFindings.push({ severity: 'critical', message: 'Safe Browsing: link na lista negra' });
            if (lr.virusTotal?.malicious > 0)
              apiFindings.push({ severity: 'high', message: `VirusTotal: link detectado por ${lr.virusTotal.malicious} antivírus` });
          }
        }

        if (apiResult.aiAnalysis) {
          apisUsed.push('Gemini IA');
          const ai = apiResult.aiAnalysis;
          if (ai.findings) apiFindings.push(...ai.findings.map(f => ({ severity: f.severity || 'medium', message: f.message })));

          // Se Gemini deu veredito, usar como principal
          if (ai.riskLevel) {
            const RISK_COLORS = { seguro: '#16a34a', baixo: '#65a30d', medio: '#d97706', alto: '#ea580c', critico: '#dc2626' };
            const RISK_LABELS = { seguro: 'Seguro', baixo: 'Baixo', medio: 'Médio', alto: 'Alto', critico: 'Crítico' };
            displayResults({
              riskLevel: ai.riskLevel, riskLabel: RISK_LABELS[ai.riskLevel] || ai.riskLevel,
              riskColor: RISK_COLORS[ai.riskLevel] || '#d97706',
              summary: ai.summary || '', findings: apiFindings, apisUsed
            });
            return;
          }
        }

        // Atualizar com dados das APIs
        DOM.apisUsed.textContent = apisUsed.length > 0 ? 'Verificado por: ' + apisUsed.join(', ') : '';
        DOM.summaryText.textContent = `De: ${localResult.rawEmailData.sender || '?'} | ${localResult.rawEmailData.urls?.length || 0} link(s) verificado(s).`;
        if (apiFindings.length > localResult.findings.length) renderFindings(apiFindings);
      });
    }

  } catch (error) {
    DOM.loadingState.classList.add('hidden');
    DOM.btnScanEmail.classList.remove('hidden');
    DOM.btnAnalyze.classList.remove('hidden');
    showToast(error.message);
  }
}

function displayEmailResults(result) {
  displayResults(result);
}

function cleanupLoading() {
  if (loadingInterval) {
    clearInterval(loadingInterval);
    loadingInterval = null;
  }
}

function animateLoadingSteps() {
  cleanupLoading();
  const steps = DOM.loadingSteps.querySelectorAll('.step');
  steps.forEach(s => s.classList.remove('active', 'done'));
  let current = 0;
  loadingInterval = setInterval(() => {
    if (current > 0 && current <= steps.length) {
      steps[current - 1].classList.remove('active');
      steps[current - 1].classList.add('done');
    }
    if (current < steps.length) {
      steps[current].classList.add('active');
      current++;
    } else { cleanupLoading(); }
  }, 800);
}

// ============================================================================
// EXIBIÇÃO DE RESULTADOS
// ============================================================================

const RISK_ICONS = {
  seguro: '🛡️', baixo: '🔵', medio: '🟡', alto: '🟠', critico: '🔴',
  safe: '🛡️', low: '🔵', medium: '🟡', high: '🟠', critical: '🔴'
};

function displayResults(result) {
  DOM.resultContainer.classList.remove('hidden');

  // Nível de risco
  const level = result.riskLevel || 'seguro';
  const color = result.riskColor || '#16a34a';
  const label = result.riskLabel || 'Seguro';

  DOM.riskLevelBadge.style.borderColor = color;
  DOM.riskLevelBadge.style.background = color + '15';
  DOM.riskIcon.textContent = RISK_ICONS[level] || '●';
  DOM.riskText.textContent = label;
  DOM.riskText.style.color = color;

  // Resumo
  DOM.summaryText.textContent = result.summary || '';

  // APIs usadas
  const apis = result.apisUsed || [];
  if (apis.length > 0) {
    DOM.apisUsed.textContent = 'Verificado por: ' + apis.join(', ');
  } else {
    DOM.apisUsed.textContent = '';
  }

  // Findings
  renderFindings(result.findings);
}

function renderFindings(findings) {
  DOM.findingsList.innerHTML = '';

  if (!findings || findings.length === 0) {
    DOM.findingsList.innerHTML = '<p class="empty-state">Nenhuma descoberta.</p>';
    return;
  }

  const limited = findings.slice(0, 15);
  limited.forEach((finding, index) => {
    const item = document.createElement('div');
    item.className = `finding-item ${finding.severity}`;
    item.style.animationDelay = `${index * 50}ms`;
    item.innerHTML = `
      <span class="finding-icon">${getFindingIcon(finding.severity)}</span>
      <span class="finding-text">${escapeHtml(finding.message)}</span>
    `;
    DOM.findingsList.appendChild(item);
  });

  if (findings.length > 15) {
    const more = document.createElement('p');
    more.style.cssText = 'text-align:center; color:var(--text-muted); font-size:11px; padding:8px;';
    more.textContent = `+ ${findings.length - 15} outras descobertas`;
    DOM.findingsList.appendChild(more);
  }
}

// ============================================================================
// SETTINGS
// ============================================================================

function loadSettings() {
  chrome.runtime.sendMessage({ action: 'getSettings' }, (response) => {
    if (response?.success && response.settings) {
      const keys = response.settings.apiKeys || {};
      DOM.apiGemini.value = keys.gemini || '';
      DOM.apiWhois.value = keys.whois || '';
      DOM.apiSafeBrowsing.value = keys.safeBrowsing || '';
      DOM.apiVirusTotal.value = keys.virusTotal || '';
      DOM.settingNotifications.checked = response.settings.showNotifications !== false;
    }
  });
}

function saveSettings() {
  const settings = {
    apiKeys: {
      gemini: DOM.apiGemini.value.trim(),
      whois: DOM.apiWhois.value.trim(),
      safeBrowsing: DOM.apiSafeBrowsing.value.trim(),
      virusTotal: DOM.apiVirusTotal.value.trim()
    },
    showNotifications: DOM.settingNotifications.checked
  };

  chrome.runtime.sendMessage({ action: 'saveSettings', settings }, (response) => {
    if (response?.success) {
      showToast('Configurações salvas!');
      setTimeout(() => switchView('main'), 800);
    }
  });
}

// ============================================================================
// HISTÓRICO
// ============================================================================

function loadHistory() {
  chrome.runtime.sendMessage({ action: 'getHistory' }, (response) => {
    if (response?.success) renderHistory(response.history || []);
  });
}

function renderHistory(history) {
  DOM.historyList.innerHTML = '';
  if (history.length === 0) {
    DOM.historyList.innerHTML = '<p class="empty-state">Nenhuma análise realizada ainda.</p>';
    return;
  }

  history.forEach(item => {
    const div = document.createElement('div');
    div.className = 'history-item';
    const icon = RISK_ICONS[item.riskLevel] || '●';
    div.innerHTML = `
      <div class="history-score ${item.riskLevel}">${icon}</div>
      <div class="history-details">
        <div class="history-domain">${escapeHtml(item.domain)}</div>
        <div class="history-meta">${escapeHtml(item.riskLabel)} · ${formatTimeAgo(item.timestamp)}</div>
      </div>
    `;
    DOM.historyList.appendChild(div);
  });
}

function clearHistory() {
  if (!confirm('Limpar todo o histórico de análises?')) return;
  chrome.runtime.sendMessage({ action: 'clearHistory' }, (response) => {
    if (response?.success) {
      renderHistory([]);
      showToast('Histórico limpo!');
    }
  });
}

// ============================================================================
// UTILIDADES
// ============================================================================

function getFindingIcon(severity) {
  return { critical: '🚨', high: '⚠️', medium: '🔶', low: '🔸', positive: '✅', info: 'ℹ️' }[severity] || '•';
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatTimeAgo(timestamp) {
  const diff = Date.now() - timestamp;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (minutes < 1) return 'agora';
  if (minutes < 60) return `${minutes}min atrás`;
  if (hours < 24) return `${hours}h atrás`;
  if (days < 7) return `${days}d atrás`;
  return new Date(timestamp).toLocaleDateString('pt-BR');
}

function showToast(message) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.classList.add('visible'), 10);
  setTimeout(() => {
    toast.classList.remove('visible');
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}
