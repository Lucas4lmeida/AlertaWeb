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
  loadingState: $('#loading-state'),
  loadingSteps: $('#loading-steps'),
  resultContainer: $('#result-container'),
  scoreRingFill: $('#score-ring-fill'),
  scoreNumber: $('#score-number'),
  riskBadge: $('#risk-badge'),
  aiSummary: $('#ai-summary'),
  aiText: $('#ai-text'),
  aiRecommendation: $('#ai-recommendation'),
  breakdownBars: $('#breakdown-bars'),
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
let scoreAnimationId = null;

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
      DOM.siteFavicon.innerHTML = `<img src="https://www.google.com/s2/favicons?domain=${url.hostname}&sz=32" alt="" onerror="this.style.display='none'"/>`;
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

function cleanupLoading() {
  if (loadingInterval) {
    clearInterval(loadingInterval);
    loadingInterval = null;
  }
}

function animateLoadingSteps() {
  // FIX #7: Limpar intervalo anterior antes de criar novo
  cleanupLoading();

  const steps = DOM.loadingSteps.querySelectorAll('.step');
  // Resetar todos os steps
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
    } else {
      cleanupLoading();
    }
  }, 800);
}

// ============================================================================
// EXIBIÇÃO DE RESULTADOS
// ============================================================================

function displayResults(result) {
  DOM.resultContainer.classList.remove('hidden');

  animateScore(result.score, result.riskColor);

  DOM.riskBadge.textContent = result.riskLabel;
  DOM.riskBadge.className = `risk-badge ${result.riskLevel}`;

  if (result.aiSummary) {
    DOM.aiSummary.classList.remove('hidden');
    DOM.aiText.textContent = result.aiSummary;
    DOM.aiRecommendation.textContent = result.aiRecommendation || '';
    DOM.aiRecommendation.style.display = result.aiRecommendation ? '' : 'none';
  } else {
    DOM.aiSummary.classList.add('hidden');
  }

  renderBreakdown(result.breakdown);
  renderFindings(result.findings);
}

function animateScore(targetScore, color) {
  // FIX #9: Cancelar animação anterior antes de iniciar nova
  if (scoreAnimationId) {
    cancelAnimationFrame(scoreAnimationId);
    scoreAnimationId = null;
  }

  const circumference = 326.7;
  const offset = circumference - (circumference * targetScore / 100);

  DOM.scoreRingFill.style.stroke = color;
  setTimeout(() => { DOM.scoreRingFill.style.strokeDashoffset = offset; }, 100);

  const duration = 1500;
  const startTime = performance.now();

  function animate(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    DOM.scoreNumber.textContent = Math.round(eased * targetScore);
    DOM.scoreNumber.style.color = color;

    if (progress < 1) {
      scoreAnimationId = requestAnimationFrame(animate);
    } else {
      scoreAnimationId = null;
    }
  }

  scoreAnimationId = requestAnimationFrame(animate);
}

function renderBreakdown(breakdown) {
  const labels = {
    url: 'URL', content: 'Conteúdo', domain: 'Domínio', security: 'Segurança',
    forms: 'Formulários', external: 'Reputação', virusTotal: 'VirusTotal', ai: 'IA'
  };

  DOM.breakdownBars.innerHTML = '';

  for (const [key, value] of Object.entries(breakdown)) {
    const color = getScoreColor(value);
    const row = document.createElement('div');
    row.className = 'breakdown-row';
    row.innerHTML = `
      <span class="breakdown-label">${labels[key] || key}</span>
      <div class="breakdown-bar-wrapper">
        <div class="breakdown-bar-fill" style="background: ${color};" data-width="${value}%"></div>
      </div>
      <span class="breakdown-value" style="color: ${color};">${value}</span>
    `;
    DOM.breakdownBars.appendChild(row);
    setTimeout(() => {
      row.querySelector('.breakdown-bar-fill').style.width = `${value}%`;
    }, 200);
  }
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
    div.innerHTML = `
      <div class="history-score ${item.riskLevel}">${item.score}</div>
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

function getScoreColor(score) {
  if (score >= 75) return '#ef4444';
  if (score >= 50) return '#f97316';
  if (score >= 25) return '#eab308';
  if (score >= 10) return '#84cc16';
  return '#22c55e';
}

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
