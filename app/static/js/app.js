// ThreatRadar - Cyber Threat Intelligence Platform Logic
let currentTab = 'panel-dashboard';
let searchDebounceTimeout = null;
let syncPollingInterval = null;
let headerResizeObserver = null;
let integrationAdminToken = '';
let integrationSettingsPoll = null;
let updateStatusData = null;
let updateStatusPoll = null;
const loadedAppVersion = document.body.dataset.version || '';
let appSettings = {
  timezone: document.body.dataset.timezone || 'UTC',
  locale: document.body.dataset.locale || 'en'
};

function watchlistReadHeaders() {
  return integrationAdminToken ? { 'X-Admin-Token': integrationAdminToken } : {};
}

const messageCatalogs = Object.freeze({
  en: {
    admin_required: 'Administrative authentication is required.',
    enter_admin: 'Enter the administrative access code.',
    verifying_admin: 'Verifying administrative access...',
    admin_verified: 'Administrative access verified. Keys remain server-side only.',
    unlock_first: 'Unlock administrative access first.',
    saving_settings: 'Saving global display settings...',
    settings_saved: 'Settings saved. Dates now use {timezone}.',
    display_timezone: 'DISPLAY TIMEZONE: {timezone}'
  },
  'pt-BR': {
    admin_required: 'A autenticação administrativa é obrigatória.',
    enter_admin: 'Informe o código de acesso administrativo.',
    verifying_admin: 'Validando o acesso administrativo...',
    admin_verified: 'Acesso administrativo validado. As chaves permanecem somente no servidor.',
    unlock_first: 'Desbloqueie primeiro o acesso administrativo.',
    saving_settings: 'Salvando as configurações globais de exibição...',
    settings_saved: 'Configurações salvas. As datas agora usam {timezone}.',
    display_timezone: 'FUSO DE EXIBIÇÃO: {timezone}'
  },
  es: {
    admin_required: 'Se requiere autenticación administrativa.',
    enter_admin: 'Ingrese el código de acceso administrativo.',
    verifying_admin: 'Verificando el acceso administrativo...',
    admin_verified: 'Acceso administrativo verificado. Las claves permanecen solo en el servidor.',
    unlock_first: 'Desbloquee primero el acceso administrativo.',
    saving_settings: 'Guardando la configuración global de visualización...',
    settings_saved: 'Configuración guardada. Las fechas ahora usan {timezone}.',
    display_timezone: 'ZONA HORARIA DE VISUALIZACIÓN: {timezone}'
  }
});

function translateMessage(key, values = {}, locale = appSettings.locale) {
  const catalog = messageCatalogs[locale] || messageCatalogs.en;
  const template = catalog[key] || messageCatalogs.en[key] || key;
  return Object.entries(values).reduce(
    (text, [name, value]) => text.replaceAll(`{${name}}`, String(value)),
    template
  );
}

function intlLocale(locale = appSettings.locale) {
  return locale === 'pt-BR' ? 'pt-BR' : (locale === 'es' ? 'es-ES' : 'en-US');
}

function parseUtcDate(value) {
  if (!value) return null;
  let normalized = String(value).trim();
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2}(\.\d+)?)? UTC$/.test(normalized)) {
    normalized = normalized.replace(' UTC', 'Z').replace(' ', 'T');
  } else if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(normalized)) {
    normalized = `${normalized.replace(' ', 'T')}Z`;
  } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(normalized)) {
    normalized = `${normalized}Z`;
  }
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function formatDateTime(value, timezone = appSettings.timezone, locale = appSettings.locale) {
  const raw = String(value || '').trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    const [year, month, day] = raw.split('-').map(Number);
    return new Intl.DateTimeFormat(intlLocale(locale), {
      timeZone: 'UTC', year: 'numeric', month: '2-digit', day: '2-digit'
    }).format(new Date(Date.UTC(year, month - 1, day)));
  }
  const parsed = parseUtcDate(value);
  if (!parsed) return value || 'N/A';
  try {
    return new Intl.DateTimeFormat(intlLocale(locale), {
      timeZone: timezone,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false, timeZoneName: 'short'
    }).format(parsed);
  } catch (_) {
    return parsed.toISOString().replace('T', ' ').replace('Z', ' UTC');
  }
}

function formatSourceDate(value) {
  const raw = String(value || '').trim();
  const match = raw.match(/^\d{4}-\d{2}-\d{2}/);
  return match ? match[0] : (raw || 'N/A');
}

function tableTimestampMarkup(value) {
  const formatted = String(formatDateTime(value) || 'N/A');
  const separator = formatted.indexOf(',');
  const date = separator >= 0 ? formatted.slice(0, separator).trim() : formatted;
  const time = separator >= 0 ? formatted.slice(separator + 1).trim() : '';
  return `<span class="table-timestamp"><span>${escapeHtml(date)}</span>${time ? `<span>${escapeHtml(time)}</span>` : ''}</span>`;
}

function applyConfiguredDates(root = document) {
  root.querySelectorAll('[data-utc-datetime]').forEach(element => {
    const raw = element.dataset.utcDatetime;
    element.textContent = formatDateTime(raw);
    element.title = raw ? `UTC source: ${raw}` : '';
  });
}

function updateSettingsPreview() {
  const timezone = document.getElementById('settings-timezone')?.value || appSettings.timezone;
  const locale = document.getElementById('settings-locale')?.value || appSettings.locale;
  const preview = document.getElementById('settings-date-preview');
  if (preview) preview.textContent = formatDateTime(new Date().toISOString(), timezone, locale);
}

async function loadPublicSettings() {
  try {
    const response = await fetch('/api/settings', { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    appSettings = { timezone: data.timezone || 'UTC', locale: data.locale || 'en' };
    document.body.dataset.timezone = appSettings.timezone;
    document.body.dataset.locale = appSettings.locale;
    document.documentElement.lang = appSettings.locale;

    const timezoneSelect = document.getElementById('settings-timezone');
    if (timezoneSelect) {
      timezoneSelect.innerHTML = (data.supported_timezones || [appSettings.timezone])
        .map(zone => `<option value="${escapeHtml(zone)}">${escapeHtml(zone)}</option>`).join('');
      timezoneSelect.value = appSettings.timezone;
    }
    const localeSelect = document.getElementById('settings-locale');
    if (localeSelect) localeSelect.value = appSettings.locale;
    const zoneStatus = document.getElementById('settings-current-zone');
    if (zoneStatus) zoneStatus.textContent = translateMessage('display_timezone', { timezone: appSettings.timezone });
    applyConfiguredDates();
    updateSettingsPreview();
  } catch (error) {
    console.error('Failed to load presentation settings:', error);
    applyConfiguredDates();
    updateSettingsPreview();
  }
}

function updateStickyNavigationOffset() {
  const header = document.querySelector('header.app-header');
  if (!header) return;

  const headerHeight = Math.ceil(header.getBoundingClientRect().height);
  document.documentElement.style.setProperty('--app-header-height', `${headerHeight}px`);
}

// Pagination states
const cveState = { page: 1, limit: 50, total: 0 };
const ransomwareState = { page: 1, limit: 50, total: 0 };
const malwareState = { page: 1, limit: 50, total: 0 };
const newsState = { page: 1, limit: 20, total: 0 };
const iocState = { page: 1, limit: 50, total: 0 };
const attackState = { page: 1, limit: 50, total: 0 };
let intelMode = 'iocs';

// Initial bootstrap
document.addEventListener('DOMContentLoaded', () => {
  // Keep the navigation fixed immediately below the responsive app header.
  // ResizeObserver also covers header wrapping caused by viewport or font changes.
  updateStickyNavigationOffset();
  requestAnimationFrame(updateStickyNavigationOffset);
  loadPublicSettings();
  window.addEventListener('resize', updateStickyNavigationOffset, { passive: true });
  const appHeader = document.querySelector('header.app-header');
  if (appHeader && 'ResizeObserver' in window) {
    headerResizeObserver = new ResizeObserver(updateStickyNavigationOffset);
    headerResizeObserver.observe(appHeader);
  }

  // Initial background load of telemetry
  loadDshield();

  // Close drawer on ESC
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeUpdateModal();
      closeDrawer();
    }
  });

  // Start periodic status check (every 15s)
  pollStatus();
  setInterval(pollStatus, 15000);
  // The public bootstrap only needs the cached, verified release state.
  // Bypassing the cache is an administrative operation and must never be
  // attempted by an anonymous page load.
  checkForUpdate();
  setInterval(() => checkForUpdate(), 21600000);

  // Dynamic CTI records use data attributes instead of inline JavaScript.
  document.addEventListener('click', (event) => {
    const artifactTarget = event.target.closest('[data-artifact-type][data-artifact-id]');
    if (artifactTarget) {
      event.preventDefault();
      openArtifact(artifactTarget.dataset.artifactType, artifactTarget.dataset.artifactId);
      return;
    }
    const filterTarget = event.target.closest('[data-filter-panel][data-filter-query]');
    if (filterTarget) {
      event.preventDefault();
      goToTabWithFilter(filterTarget.dataset.filterPanel, { query: filterTarget.dataset.filterQuery });
      return;
    }
  });
});

// ==================== SAFE APPLICATION UPDATE ====================

function updateStateIsActive(state) {
  return ['queued', 'validating', 'testing', 'installing'].includes(state);
}

function setUpdateMessage(message, type = '') {
  const element = document.getElementById('update-message');
  if (!element) return;
  element.textContent = message;
  element.className = `integration-message mono ${type}`.trim();
}

function renderUpdateStatus(data) {
  updateStatusData = data;
  const pill = document.getElementById('update-available-pill');
  const pillText = document.getElementById('update-pill-text');
  const current = document.getElementById('update-current-version');
  const latest = document.getElementById('update-latest-version');
  const operation = document.getElementById('update-operation-state');
  const changelog = document.getElementById('update-changelog');
  const installButton = document.getElementById('update-install-button');
  const releaseLink = document.getElementById('update-release-link');
  const progress = document.getElementById('update-progress');
  const progressBar = document.getElementById('update-progress-bar');
  const state = data.update_state || 'idle';
  const active = updateStateIsActive(state);

  if (pill) {
    pill.className = 'update-status-pill';
    if (data.check_error) {
      pill.classList.add('is-error');
      pill.title = 'The stable release channel could not be checked';
    } else if (data.check_warning) {
      pill.classList.add('is-warning');
      pill.title = 'Showing the last verified release status; the live check is temporarily limited';
    } else if (active) {
      pill.classList.add('is-active');
      pill.title = 'A validated system update is in progress';
    } else if (data.update_available) {
      pill.classList.add('is-available');
      pill.title = `Dark Threat Radar v${data.latest_version} is available`;
    } else {
      pill.classList.add('is-current');
      pill.title = `Dark Threat Radar v${data.current_version} is up to date`;
    }
  }
  if (pillText) {
    if (data.check_error) pillText.textContent = 'UPDATE CHECK DEGRADED';
    else if (data.check_warning) pillText.textContent = data.update_available ? `UPDATE v${data.latest_version} AVAILABLE` : 'SYSTEM UPDATED';
    else if (active) pillText.textContent = `UPDATING v${data.update_target_version || data.latest_version || ''}`.trim();
    else if (data.update_available) pillText.textContent = `UPDATE v${data.latest_version} AVAILABLE`;
    else pillText.textContent = 'SYSTEM UPDATED';
  }
  if (current) current.textContent = `v${data.current_version}`;
  if (latest) latest.textContent = `v${data.latest_version}`;
  if (operation) operation.textContent = state.replaceAll('_', ' ').toUpperCase();
  if (changelog) changelog.textContent = data.changelog || 'Release notes are available on GitHub.';
  if (releaseLink) releaseLink.href = safeHttpUrl(data.release_url) || 'https://github.com/fr3dux/dark-threat-radar/releases';
  if (installButton) installButton.disabled = !data.update_available || !data.updater_enabled || active;
  if (progress) progress.hidden = !active;
  if (progressBar) progressBar.style.width = `${Math.max(0, Math.min(100, Number(data.update_progress || 0)))}%`;

  if (data.check_error) {
    setUpdateMessage(data.check_error, 'error');
  } else if (data.check_warning) {
    setUpdateMessage(`${data.check_warning} Showing the last verified release status.`);
  } else if (active) {
    setUpdateMessage(data.update_message || 'Update is running. This page will reconnect automatically.');
  } else if (state === 'rolled_back' || state === 'failed') {
    setUpdateMessage(data.update_message || 'Update failed.', 'error');
  } else if (!data.update_available) {
    setUpdateMessage('This installation is up to date.', 'ok');
  } else if (!data.updater_enabled) {
    setUpdateMessage('An update is available, but one-click installation is not enabled on this host.');
  } else {
    setUpdateMessage('Update verified. Enter the administrative access code to install it.', 'ok');
  }
}

async function checkForUpdate(force = false) {
  try {
    const endpoint = force ? '/api/update/status?force=true' : '/api/update/status';
    const response = await fetch(endpoint, { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    renderUpdateStatus(data);
    if (loadedAppVersion && data.current_version !== loadedAppVersion) {
      window.location.reload();
      return;
    }
    if (updateStateIsActive(data.update_state) && !updateStatusPoll) {
      updateStatusPoll = setInterval(() => checkForUpdate(), 3000);
    } else if (!updateStateIsActive(data.update_state) && updateStatusPoll) {
      clearInterval(updateStatusPoll);
      updateStatusPoll = null;
    }
  } catch (_error) {
    const pill = document.getElementById('update-available-pill');
    const pillText = document.getElementById('update-pill-text');
    if (pill) {
      pill.className = 'update-status-pill is-error';
      pill.title = 'The stable release channel could not be checked';
    }
    if (pillText) pillText.textContent = 'UPDATE CHECK UNAVAILABLE';
    if (updateStatusPoll) {
      setUpdateMessage('Service is restarting; waiting to reconnect...');
    } else {
      setUpdateMessage('The release status could not be checked. Try again later.', 'error');
    }
  }
}

function openUpdateModal() {
  const overlay = document.getElementById('update-modal-overlay');
  if (!overlay) return;
  overlay.classList.add('open');
  overlay.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  checkForUpdate();
}

function closeUpdateModal() {
  const overlay = document.getElementById('update-modal-overlay');
  if (!overlay || !overlay.classList.contains('open')) return;
  overlay.classList.remove('open');
  overlay.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
  const token = document.getElementById('update-admin-token');
  if (token) token.value = '';
}

async function installLatestUpdate() {
  const tokenInput = document.getElementById('update-admin-token');
  const installButton = document.getElementById('update-install-button');
  const token = tokenInput?.value.trim() || '';
  if (!token) {
    setUpdateMessage('Enter the administrative access code.', 'error');
    tokenInput?.focus();
    return;
  }
  if (!updateStatusData?.update_available || !updateStatusData?.updater_enabled) return;
  if (!confirm(`Install Dark Threat Radar v${updateStatusData.latest_version}? The service will restart automatically.`)) return;

  if (installButton) installButton.disabled = true;
  setUpdateMessage('Submitting authenticated update request...');
  try {
    const response = await fetch('/api/admin/update', {
      method: 'POST',
      headers: { 'X-Admin-Token': token }
    });
    let data = {};
    try { data = await response.json(); } catch (_) { /* no response body */ }
    if (!response.ok) throw new Error(data.error || data.detail || `HTTP ${response.status}`);
    if (tokenInput) tokenInput.value = '';
    setUpdateMessage(`Update v${data.target_version} queued. Validation is starting.`, 'ok');
    if (!updateStatusPoll) updateStatusPoll = setInterval(() => checkForUpdate(), 3000);
    await checkForUpdate();
  } catch (error) {
    setUpdateMessage(error.message, 'error');
    if (installButton) installButton.disabled = false;
  }
}

// ==================== NAVIGATION & TAB SWITCHING ====================

function switchTab(panelId, btnElement) {
  currentTab = panelId;

  // Update tab buttons
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  if (btnElement) {
    btnElement.classList.add('active');
  } else {
    const defaultBtn = document.querySelector(`.tab-btn[data-target="${panelId}"]`);
    if (defaultBtn) defaultBtn.classList.add('active');
  }

  // Update panels
  document.querySelectorAll('.view-panel').forEach(panel => panel.classList.remove('active'));
  const target = document.getElementById(panelId);
  if (target) target.classList.add('active');

  // Toolbar visibility
  const toolbar = document.getElementById('explorer-toolbar');
  const cveFilters = document.getElementById('cve-filters');
  const malwareFilters = document.getElementById('malware-filters');
  const newsFilters = document.getElementById('news-filters');
  const ransomwareFilters = document.getElementById('ransomware-filters');
  const iocFilters = document.getElementById('ioc-filters');
  const attackFilters = document.getElementById('attack-filters');
  const metricsStrip = document.querySelector('.metrics-strip');
  const mainContent = document.querySelector('main.main-content');

  // The executive dashboard needs the wider canvas for the global map and
  // live telemetry. Operational pages keep the focused 1180px workspace.
  if (mainContent) mainContent.classList.toggle('dashboard-active', panelId === 'panel-dashboard');

  // The executive KPI strip belongs to the dashboard. Hiding it in explorer
  // views gives tables and filters the visual priority they need.
  if (metricsStrip) metricsStrip.style.display = panelId === 'panel-dashboard' ? 'grid' : 'none';

  const panelsWithFilters = ['panel-cves', 'panel-malware', 'panel-intel', 'panel-news'];
  if (!panelsWithFilters.includes(panelId)) {
    toolbar.style.display = 'none';
  } else {
    toolbar.style.display = 'flex';
    cveFilters.style.display = (panelId === 'panel-cves') ? 'flex' : 'none';
    malwareFilters.style.display = (panelId === 'panel-malware') ? 'flex' : 'none';
    newsFilters.style.display = (panelId === 'panel-news') ? 'flex' : 'none';
    if (ransomwareFilters) ransomwareFilters.style.display = (panelId === 'panel-ransomware') ? 'flex' : 'none';
    if (iocFilters) iocFilters.style.display = (panelId === 'panel-intel' && intelMode === 'iocs') ? 'flex' : 'none';
    if (attackFilters) attackFilters.style.display = (panelId === 'panel-intel' && intelMode === 'attack') ? 'flex' : 'none';
  }

  // Lazy load data on tab switch if not already populated
  if (panelId === 'panel-attackmap') {
    initAttackMap();
  } else if (panelId === 'panel-ransomware') {
    loadRansomware();
  } else if (panelId === 'panel-cves') {
    loadCves();
  } else if (panelId === 'panel-intel') {
    if (intelMode === 'attack') loadAttackKnowledge(); else loadIocs();
  } else if (panelId === 'panel-malware') {
    loadMalware();
  } else if (panelId === 'panel-dshield') {
    loadDshield();
  } else if (panelId === 'panel-news') {
    loadNews();
  } else if (panelId === 'panel-settings') {
    loadPublicSettings();
  }
}

function goToTabWithFilter(panelId, filters) {
  const searchIds = {
    'panel-cves': 'cve-search',
    'panel-malware': 'malware-search',
    'panel-intel': intelMode === 'attack' ? 'attack-search' : 'ioc-search',
    'panel-dshield': 'dshield-search',
    'panel-ransomware': 'ransomware-search',
    'panel-news': 'news-search'
  };
  const searchInput = document.getElementById(searchIds[panelId]);
  if (filters.query) {
    if (searchInput) searchInput.value = filters.query;
  } else if (searchInput) {
    searchInput.value = '';
  }

  // Apply filters
  if (panelId === 'panel-ransomware') {
    loadRansomware();
  } else if (panelId === 'panel-cves') {
    if (filters.severity) document.getElementById('filter-cve-severity').value = filters.severity;
    else if (!filters.keepSeverity) document.getElementById('filter-cve-severity').value = 'all';

    if (filters.source) document.getElementById('filter-cve-source').value = filters.source;
    else if (!filters.keepSource) document.getElementById('filter-cve-source').value = 'all';

    if (filters.ransomware) document.getElementById('filter-cve-ransomware').value = filters.ransomware;
    else if (!filters.keepRansomware) document.getElementById('filter-cve-ransomware').value = 'all';

    cveState.page = 1;
  } else if (panelId === 'panel-malware') {
    if (filters.type) document.getElementById('filter-malware-type').value = filters.type;
    else document.getElementById('filter-malware-type').value = 'all';
    malwareState.page = 1;
  } else if (panelId === 'panel-intel') {
    if (filters.type) document.getElementById('filter-ioc-type').value = filters.type;
    else if (!filters.keepType) document.getElementById('filter-ioc-type').value = 'all';
    if (filters.source) document.getElementById('filter-ioc-source').value = filters.source;
    else if (!filters.keepSource) document.getElementById('filter-ioc-source').value = 'all';
    iocState.page = 1;
  } else if (panelId === 'panel-news') {
    if (filters.source) document.getElementById('filter-news-source').value = filters.source;
    else document.getElementById('filter-news-source').value = 'all';
    newsState.page = 1;
  }

  const targetBtn = document.querySelector(`.tab-btn[data-target="${panelId}"]`);
  switchTab(panelId, targetBtn);
}

function debouncePageSearch(page) {
  clearTimeout(searchDebounceTimeout);
  searchDebounceTimeout = setTimeout(() => {
    if (page === 'cves') {
      cveState.page = 1;
      loadCves();
    } else if (page === 'malware') {
      malwareState.page = 1;
      loadMalware();
    } else if (page === 'iocs') {
      iocState.page = 1;
      loadIocs();
    } else if (page === 'attack') {
      attackState.page = 1;
      loadAttackKnowledge();
    } else if (page === 'dshield') {
      loadDshield();
    } else if (page === 'ransomware') {
      ransomwareState.page = 1;
      loadRansomware();
    } else if (page === 'news') {
      newsState.page = 1;
      loadNews();
    }
  }, 250);
}

// ==================== CORRELATED IOC & ATT&CK EXPLORER ====================

function showIntelMode(mode) {
  intelMode = mode === 'attack' ? 'attack' : 'iocs';
  const iocView = document.getElementById('intel-ioc-view');
  const attackView = document.getElementById('intel-attack-view');
  const iocButton = document.getElementById('intel-mode-iocs');
  const attackButton = document.getElementById('intel-mode-attack');
  const iocFilters = document.getElementById('ioc-filters');
  const attackFilters = document.getElementById('attack-filters');
  if (iocView) iocView.style.display = intelMode === 'iocs' ? 'block' : 'none';
  if (attackView) attackView.style.display = intelMode === 'attack' ? 'block' : 'none';
  iocButton?.classList.toggle('active', intelMode === 'iocs');
  attackButton?.classList.toggle('active', intelMode === 'attack');
  if (currentTab === 'panel-intel') {
    if (iocFilters) iocFilters.style.display = intelMode === 'iocs' ? 'flex' : 'none';
    if (attackFilters) attackFilters.style.display = intelMode === 'attack' ? 'flex' : 'none';
    if (intelMode === 'attack') loadAttackKnowledge(); else loadIocs();
  }
}

async function loadIocs() {
  const tbody = document.getElementById('ioc-tbody');
  if (!tbody) return;
  const q = document.getElementById('ioc-search')?.value.trim() || '';
  const type = document.getElementById('filter-ioc-type')?.value || 'all';
  const source = document.getElementById('filter-ioc-source')?.value || 'all';
  const offset = (iocState.page - 1) * iocState.limit;
  const params = new URLSearchParams({ limit: iocState.limit, offset, active: 'true' });
  if (q) params.set('q', q);
  if (type !== 'all') params.set('indicator_type', type);
  if (source !== 'all') params.set('source', source);
  tbody.innerHTML = '<tr><td colspan="6" class="loading-row">Querying normalized public intelligence...</td></tr>';
  try {
    const response = await fetch(`/api/iocs?${params}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    iocState.total = data.total;
    const pages = Math.max(1, Math.ceil(data.total / iocState.limit));
    if (iocState.page > pages) { iocState.page = pages; return loadIocs(); }
    tbody.innerHTML = data.items.length ? data.items.map(item => {
      const sources = (item.sources || item.source_name || '').split(',').map(value => value.trim()).filter(Boolean);
      return `<tr class="clickable-row" data-artifact-type="ioc" data-artifact-id="${escapeHtml(item.id)}">
        <td><span class="badge badge-filetype mono">${escapeHtml((item.indicator_type || '').toUpperCase())}</span></td>
        <td class="wrap-cell"><div class="mono font-bold intel-table-value">${escapeHtml(item.normalized_value)}</div><div class="mono text-muted">${escapeHtml(item.malware_family || '')}</div></td>
        <td>${escapeHtml(item.threat_type || 'indicator')}</td>
        <td><span class="badge ${Number(item.confidence) >= 80 ? 'badge-crit' : 'badge-warn'} mono">${Number(item.confidence) || 0}%</span></td>
        <td><div class="source-chip-list">${sources.slice(0, 3).map(name => `<span class="source-chip mono">${escapeHtml(name.replaceAll('_', ' '))}</span>`).join('')}${sources.length > 3 ? `<span class="source-chip mono">+${sources.length - 3}</span>` : ''}</div></td>
        <td class="mono text-muted timestamp-cell" title="${escapeHtml(formatDateTime(item.last_seen))}">${tableTimestampMarkup(item.last_seen)}</td>
      </tr>`;
    }).join('') : '<tr><td colspan="6" class="loading-row">No active indicators match these filters.</td></tr>';
    const start = data.total ? offset + 1 : 0;
    const end = Math.min(offset + data.items.length, data.total);
    document.getElementById('ioc-page-info').textContent = `Showing ${start.toLocaleString()} - ${end.toLocaleString()} of ${data.total.toLocaleString()} IOCs`;
    document.getElementById('ioc-page-num').textContent = `PAGE ${iocState.page} / ${pages}`;
    document.getElementById('ioc-btn-prev').disabled = iocState.page <= 1;
    document.getElementById('ioc-btn-next').disabled = iocState.page >= pages;
  } catch (error) {
    tbody.innerHTML = `<tr><td colspan="6" class="loading-row crit">${escapeHtml(error.message)}</td></tr>`;
  }
}

function changeIocPageSize(value) { iocState.limit = Number(value) || 50; iocState.page = 1; loadIocs(); }
function iocPrevPage() { if (iocState.page > 1) { iocState.page--; loadIocs(); } }
function iocNextPage() { if (iocState.page * iocState.limit < iocState.total) { iocState.page++; loadIocs(); } }

function parseJsonArray(value) {
  try { const parsed = JSON.parse(value || '[]'); return Array.isArray(parsed) ? parsed : []; }
  catch (_) { return []; }
}

async function loadAttackKnowledge() {
  const tbody = document.getElementById('attack-tbody');
  if (!tbody) return;
  const q = document.getElementById('attack-search')?.value.trim() || '';
  const type = document.getElementById('filter-attack-type')?.value || 'all';
  const offset = (attackState.page - 1) * attackState.limit;
  const params = new URLSearchParams({ limit: attackState.limit, offset });
  if (q) params.set('q', q);
  if (type !== 'all') params.set('object_type', type);
  tbody.innerHTML = '<tr><td colspan="5" class="loading-row">Querying MITRE ATT&CK knowledge...</td></tr>';
  try {
    const response = await fetch(`/api/attack-knowledge?${params}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    attackState.total = data.total;
    const pages = Math.max(1, Math.ceil(data.total / attackState.limit));
    if (attackState.page > pages) { attackState.page = pages; return loadAttackKnowledge(); }
    tbody.innerHTML = data.items.length ? data.items.map(item => {
      const context = [...parseJsonArray(item.tactics), ...parseJsonArray(item.platforms)].slice(0, 4);
      const description = String(item.description || '').replace(/\s+/g, ' ').slice(0, 240);
      return `<tr class="clickable-row" data-artifact-type="attack" data-artifact-id="${escapeHtml(item.id)}">
        <td><span class="badge badge-filetype mono">${escapeHtml((item.object_type || '').replaceAll('-', ' ').toUpperCase())}</span></td>
        <td class="mono info font-bold">${escapeHtml(item.external_id || 'N/A')}</td>
        <td class="font-bold">${escapeHtml(item.name)}</td><td>${escapeHtml(description)}${description.length >= 240 ? '…' : ''}</td>
        <td><div class="source-chip-list">${context.map(value => `<span class="source-chip mono">${escapeHtml(value)}</span>`).join('')}</div></td>
      </tr>`;
    }).join('') : '<tr><td colspan="5" class="loading-row">No ATT&CK objects match these filters.</td></tr>';
    const start = data.total ? offset + 1 : 0;
    const end = Math.min(offset + data.items.length, data.total);
    document.getElementById('attack-page-info').textContent = `Showing ${start.toLocaleString()} - ${end.toLocaleString()} of ${data.total.toLocaleString()} ATT&CK objects`;
    document.getElementById('attack-page-num').textContent = `PAGE ${attackState.page} / ${pages}`;
    document.getElementById('attack-btn-prev').disabled = attackState.page <= 1;
    document.getElementById('attack-btn-next').disabled = attackState.page >= pages;
  } catch (error) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-row crit">${escapeHtml(error.message)}</td></tr>`;
  }
}

function changeAttackPageSize(value) { attackState.limit = Number(value) || 50; attackState.page = 1; loadAttackKnowledge(); }
function attackPrevPage() { if (attackState.page > 1) { attackState.page--; loadAttackKnowledge(); } }
function attackNextPage() { if (attackState.page * attackState.limit < attackState.total) { attackState.page++; loadAttackKnowledge(); } }

// ==================== CVE EXPLORER ====================

async function loadCves() {
  const q = document.getElementById('cve-search')?.value.trim() || '';
  const source = document.getElementById('filter-cve-source').value;
  const ransomware = document.getElementById('filter-cve-ransomware').value;
  const severity = document.getElementById('filter-cve-severity').value;

  const tbody = document.getElementById('cve-tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="loading-row">Querying CVE intelligence index...</td></tr>';

  const offset = (cveState.page - 1) * cveState.limit;

  try {
    const params = new URLSearchParams({
      limit: cveState.limit,
      offset: offset
    });
    if (q) params.set('q', q);
    if (source !== 'all') params.set('source', source);
    if (ransomware !== 'all') params.set('ransomware', ransomware);
    if (severity !== 'all') params.set('severity', severity);

    const res = await fetch(`/api/cves?${params.toString()}`);
    const data = await res.json();

    cveState.total = data.total;
    updateCvePagination();

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-row">No CVE records match the current filter criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = data.items.map(item => {
      // CVSS badge
      let cvssBadge = '<span class="badge badge-med">N/A</span>';
      if (item.cvss_score) {
        const score = parseFloat(item.cvss_score).toFixed(1);
        let sevClass = 'badge-med';
        if (item.cvss_score >= 9.0) sevClass = 'badge-crit';
        else if (item.cvss_score >= 7.0) sevClass = 'badge-high';
        else if (item.cvss_score < 4.0) sevClass = 'badge-low';
        cvssBadge = `<span class="badge ${sevClass}">${score}</span>`;
      }

      // Source badge
      const srcBadge = item.source === 'cisa_kev'
        ? '<span class="badge badge-kev">CISA KEV</span>'
        : '<span class="badge badge-nvd">NVD</span>';

      // Ransomware badge
      const rwBadge = item.known_ransomware_campaign_use === 'Known'
        ? '<span class="badge badge-ransomware">KNOWN</span>'
        : '<span class="mono" style="color: var(--text-muted);">-</span>';

      const epssValue = Number(item.epss_score);
      const epssBadge = Number.isFinite(epssValue) && epssValue >= 0
        ? `<span class="mono ${epssValue >= 0.5 ? 'crit' : (epssValue >= 0.1 ? 'warn' : 'text-muted')}">${(epssValue * 100).toFixed(1)}%</span>`
        : '<span class="mono text-muted">-</span>';

      const vendor = escapeHtml((item.vendor_project || '') + (item.product ? ` / ${item.product}` : '')) || 'n/a';
      const desc = escapeHtml(item.short_description || item.vulnerability_name || '');

      return `
        <tr class="clickable-row" data-artifact-type="cve" data-artifact-id="${escapeHtml(item.cve_id)}">
          <td class="mono font-bold" style="color: var(--accent-blue);" title="${escapeHtml(item.cve_id)}">${escapeHtml(item.cve_id)}</td>
          <td>${srcBadge}</td>
          <td title="${vendor}">${vendor.length > 28 ? vendor.slice(0, 26) + '..' : vendor}</td>
          <td title="${desc}">${desc.length > 95 ? desc.slice(0, 92) + '...' : desc}</td>
          <td>${cvssBadge}</td>
          <td>${epssBadge}</td>
          <td>${rwBadge}</td>
          <td class="mono text-muted" title="${escapeHtml(item.date_added || '')}">${escapeHtml(formatSourceDate(item.date_added))}</td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-row" style="color: var(--accent-red);">Error loading CVEs: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function updateCvePagination() {
  const totalPages = Math.ceil(cveState.total / cveState.limit) || 1;
  const start = cveState.total === 0 ? 0 : (cveState.page - 1) * cveState.limit + 1;
  const end = Math.min(cveState.page * cveState.limit, cveState.total);
  const infoText = `Showing ${start.toLocaleString()} - ${end.toLocaleString()} of ${cveState.total.toLocaleString()} CVEs`;

  document.getElementById('cve-page-info').textContent = infoText;
  document.getElementById('cve-page-info-bottom').textContent = infoText;
  document.getElementById('cve-page-num').textContent = `PAGE ${cveState.page} / ${totalPages}`;

  const prevDisabled = cveState.page <= 1;
  const nextDisabled = cveState.page >= totalPages;

  document.getElementById('cve-btn-prev').disabled = prevDisabled;
  document.getElementById('cve-btn-prev-b').disabled = prevDisabled;
  document.getElementById('cve-btn-next').disabled = nextDisabled;
  document.getElementById('cve-btn-next-b').disabled = nextDisabled;

}

function cvePrevPage() {
  if (cveState.page > 1) {
    cveState.page--;
    loadCves();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function cveNextPage() {
  const totalPages = Math.ceil(cveState.total / cveState.limit);
  if (cveState.page < totalPages) {
    cveState.page++;
    loadCves();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function changeCvePageSize(val) {
  cveState.limit = parseInt(val, 10);
  cveState.page = 1;
  loadCves();
}

// ==================== MALWARE SAMPLES ====================

async function loadMalware() {
  const q = document.getElementById('malware-search')?.value.trim() || '';
  const fileType = document.getElementById('filter-malware-type').value;

  const tbody = document.getElementById('malware-tbody');
  tbody.innerHTML = '<tr><td colspan="6" class="loading-row">Querying MalwareBazaar indicators...</td></tr>';

  const offset = (malwareState.page - 1) * malwareState.limit;

  try {
    const params = new URLSearchParams({
      limit: malwareState.limit,
      offset: offset
    });
    if (q) params.set('q', q);
    if (fileType !== 'all') params.set('file_type', fileType);

    const res = await fetch(`/api/malware?${params.toString()}`);
    const data = await res.json();

    malwareState.total = data.total;
    updateMalwarePagination();

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No malware samples found.</td></tr>';
      return;
    }

    tbody.innerHTML = data.items.map(item => {
      const sha256 = item.sha256_hash;
      const sha256Short = sha256 ? `${sha256.slice(0, 12)}...${sha256.slice(-8)}` : 'n/a';
      const sig = item.signature && item.signature !== 'n/a'
        ? `<span class="badge badge-high">${escapeHtml(item.signature)}</span>`
        : '<span class="mono text-muted">Unclassified</span>';

      return `
        <tr class="clickable-row" data-artifact-type="malware" data-artifact-id="${escapeHtml(sha256)}">
          <td class="mono text-muted timestamp-cell" title="${escapeHtml(formatDateTime(item.first_seen))}">${tableTimestampMarkup(item.first_seen)}</td>
          <td class="mono" style="color: var(--accent-purple);" title="${escapeHtml(sha256)}">${sha256Short}</td>
          <td class="mono" title="${escapeHtml(item.file_name || '')}">${escapeHtml((item.file_name || 'unknown').slice(0, 26))}</td>
          <td><span class="badge badge-filetype">${escapeHtml((item.file_type || 'bin').toUpperCase())}</span></td>
          <td>${sig}</td>
          <td class="mono text-muted">${escapeHtml(item.reporter || 'abuse_ch')}</td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-row" style="color: var(--accent-red);">Error loading malware: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function updateMalwarePagination() {
  const totalPages = Math.ceil(malwareState.total / malwareState.limit) || 1;
  const start = malwareState.total === 0 ? 0 : (malwareState.page - 1) * malwareState.limit + 1;
  const end = Math.min(malwareState.page * malwareState.limit, malwareState.total);
  const infoText = `Showing ${start.toLocaleString()} - ${end.toLocaleString()} of ${malwareState.total.toLocaleString()} samples`;

  document.getElementById('malware-page-info').textContent = infoText;
  document.getElementById('malware-page-info-bottom').textContent = infoText;
  document.getElementById('malware-page-num').textContent = `PAGE ${malwareState.page} / ${totalPages}`;

  const prevDisabled = malwareState.page <= 1;
  const nextDisabled = malwareState.page >= totalPages;

  document.getElementById('malware-btn-prev').disabled = prevDisabled;
  document.getElementById('malware-btn-prev-b').disabled = prevDisabled;
  document.getElementById('malware-btn-next').disabled = nextDisabled;
  document.getElementById('malware-btn-next-b').disabled = nextDisabled;

}

function malwarePrevPage() {
  if (malwareState.page > 1) {
    malwareState.page--;
    loadMalware();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function malwareNextPage() {
  const totalPages = Math.ceil(malwareState.total / malwareState.limit);
  if (malwareState.page < totalPages) {
    malwareState.page++;
    loadMalware();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function changeMalwarePageSize(val) {
  malwareState.limit = parseInt(val, 10);
  malwareState.page = 1;
  loadMalware();
}

// ==================== DSHIELD TELEMETRY ====================

function renderMapTopTargetedPorts(ports) {
  const container = document.getElementById('map-top-targeted-ports');
  if (!container) return;

  const topPorts = (ports || []).slice(0, 5);
  if (topPorts.length === 0) {
    container.innerHTML = '<div class="stream-item-placeholder">No DShield port telemetry available.</div>';
    return;
  }

  container.innerHTML = topPorts.map(item => `
    <div class="port-item" data-artifact-type="port" data-artifact-id="${Number(item.port)}">
      <div class="port-col-main">
        <span class="port-number mono font-bold" style="font-size: 11px;">${Number(item.port)}</span>
        <span class="badge badge-port-service mono" style="font-size: 9px;">${escapeHtml(item.service || `PORT/${item.port}`)}</span>
      </div>
      <div class="map-port-stats mono">
        <div class="map-port-records">${Number(item.records || 0).toLocaleString()} records</div>
        <div class="map-port-meta">${Number(item.count || 0).toLocaleString()} attacker IPs • ${Number(item.targets || 0).toLocaleString()} targets</div>
      </div>
    </div>
  `).join('');
}

async function loadDshield() {
  const sourcesTbody = document.getElementById('dshield-sources-tbody');
  const portsTbody = document.getElementById('dshield-ports-tbody');
  const q = (document.getElementById('dshield-search')?.value.trim() || '').toLowerCase();

  try {
    const res = await fetch('/api/dshield');
    const data = await res.json();

    // Sources
    const allSources = data.sources || [];
    const sources = q ? allSources.filter(item => [item.ip, item.as_name, item.attacks, item.count]
      .some(value => String(value ?? '').toLowerCase().includes(q))) : allSources;
    document.getElementById('dshield-sources-count').textContent = `${sources.length} Top IPs`;
    if (sources.length === 0) {
      sourcesTbody.innerHTML = '<tr><td colspan="5" class="empty-row">No attacking source telemetry logged.</td></tr>';
    } else {
      sourcesTbody.innerHTML = sources.map(item => `
        <tr class="clickable-row" data-artifact-type="ip" data-artifact-id="${escapeHtml(item.ip)}">
          <td class="mono font-bold" style="color: var(--accent-cyan);">${escapeHtml(item.ip)}</td>
          <td class="mono crit font-bold">${item.attacks.toLocaleString()}</td>
          <td class="mono">${item.count.toLocaleString()}</td>
          <td title="${escapeHtml(item.as_name || '')}">${escapeHtml((item.as_name || 'N/A').slice(0, 26))}</td>
          <td class="mono text-muted timestamp-cell" title="${escapeHtml(formatDateTime(item.lastseen || item.updated_at || ''))}">${tableTimestampMarkup(item.lastseen || item.updated_at || '')}</td>
        </tr>
      `).join('');
    }

    // Ports
    const allPorts = data.ports || [];
    const ports = q ? allPorts.filter(item => [item.port, item.service, item.records, item.targets, item.count]
      .some(value => String(value ?? '').toLowerCase().includes(q))) : allPorts;
    renderMapTopTargetedPorts(allPorts);
    document.getElementById('dshield-ports-count').textContent = `${ports.length} Monitored`;
    if (ports.length === 0) {
      portsTbody.innerHTML = '<tr><td colspan="5" class="empty-row">No port telemetry recorded.</td></tr>';
    } else {
      portsTbody.innerHTML = ports.map(item => `
        <tr class="clickable-row" data-artifact-type="port" data-artifact-id="${Number(item.port)}">
          <td class="mono font-bold" style="color: var(--accent-orange);">${Number(item.port)}</td>
          <td><span class="badge badge-filetype mono">${escapeHtml(item.service || 'Unknown')}</span></td>
          <td class="mono">${item.records.toLocaleString()}</td>
          <td class="mono">${item.targets.toLocaleString()}</td>
          <td class="mono warn font-bold">${item.count.toLocaleString()}</td>
        </tr>
      `).join('');
    }

  } catch (err) {
    sourcesTbody.innerHTML = `<tr><td colspan="5" class="empty-row">Telemetry fetch error</td></tr>`;
    portsTbody.innerHTML = `<tr><td colspan="5" class="empty-row">Telemetry fetch error</td></tr>`;
  }
}

// ==================== CTI NEWS & INTEL ====================

async function loadNews() {
  const q = document.getElementById('news-search')?.value.trim() || '';
  const source = document.getElementById('filter-news-source').value;
  const container = document.getElementById('news-container');

  container.innerHTML = '<div class="loading-row">Querying CTI news feed...</div>';

  const offset = (newsState.page - 1) * newsState.limit;

  try {
    const params = new URLSearchParams({
      limit: newsState.limit,
      offset: offset
    });
    if (q) params.set('q', q);
    if (source !== 'all') params.set('source', source);

    const res = await fetch(`/api/news?${params.toString()}`);
    const data = await res.json();

    newsState.total = data.total;
    updateNewsPagination();

    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<div class="empty-row">No threat intelligence advisories found.</div>';
      return;
    }

    container.innerHTML = data.items.map(item => `
      <div class="news-card" data-artifact-type="news" data-artifact-id="${escapeHtml(item.id)}">
        <div class="news-header">
          <div class="news-title font-bold">${escapeHtml(item.title)}</div>
          <span class="badge badge-nvd">${escapeHtml(item.source)}</span>
        </div>
        ${item.snippet ? `<div class="news-snippet">${escapeHtml(item.snippet)}</div>` : ''}
        <div class="news-meta">
          <span>PUBLISHED: ${escapeHtml(formatDateTime(item.published_at || item.published_date || item.updated_at || 'Recent'))}</span>
          <span class="text-muted">&bull;</span>
          <span class="mono" style="color: var(--accent-blue); text-decoration: underline;">INSPECT INTELLIGENCE &rarr;</span>
        </div>
      </div>
    `).join('');

  } catch (err) {
    container.innerHTML = `<div class="empty-row" style="color: var(--accent-red);">Error loading news: ${escapeHtml(err.message)}</div>`;
  }
}

function updateNewsPagination() {
  const totalPages = Math.ceil(newsState.total / newsState.limit) || 1;
  const start = newsState.total === 0 ? 0 : (newsState.page - 1) * newsState.limit + 1;
  const end = Math.min(newsState.page * newsState.limit, newsState.total);
  const infoText = `Showing ${start.toLocaleString()} - ${end.toLocaleString()} of ${newsState.total.toLocaleString()} news advisories`;

  document.getElementById('news-page-info').textContent = infoText;
  document.getElementById('news-page-info-bottom').textContent = infoText;
  document.getElementById('news-page-num').textContent = `PAGE ${newsState.page} / ${totalPages}`;

  const prevDisabled = newsState.page <= 1;
  const nextDisabled = newsState.page >= totalPages;

  document.getElementById('news-btn-prev').disabled = prevDisabled;
  document.getElementById('news-btn-prev-b').disabled = prevDisabled;
  document.getElementById('news-btn-next').disabled = nextDisabled;
  document.getElementById('news-btn-next-b').disabled = nextDisabled;

}

function newsPrevPage() {
  if (newsState.page > 1) {
    newsState.page--;
    loadNews();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function newsNextPage() {
  const totalPages = Math.ceil(newsState.total / newsState.limit);
  if (newsState.page < totalPages) {
    newsState.page++;
    loadNews();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function changeNewsPageSize(val) {
  newsState.limit = parseInt(val, 10);
  newsState.page = 1;
  loadNews();
}

// ==================== ARTIFACT LATERAL DRAWER ====================

async function openArtifact(type, identifier) {
  const drawer = document.getElementById('inspection-drawer');
  const overlay = document.getElementById('drawer-overlay');
  const badge = document.getElementById('drawer-badge');
  const title = document.getElementById('drawer-title');
  const content = document.getElementById('drawer-content');

  badge.textContent = type.toUpperCase();
  title.textContent = identifier;
  content.innerHTML = '<div class="loading-row">Loading deep artifact telemetry...</div>';

  drawer.classList.add('open');
  overlay.classList.add('open');

  try {
    const res = await fetch(`/api/artifact/${type}/${encodeURIComponent(identifier)}`, {
      cache: 'no-store',
      headers: watchlistReadHeaders()
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const result = await res.json();
    const d = result.data;

    let propsHtml = '';
    let actionsHtml = '';

    if (type === 'cve') {
      propsHtml = `
        <div class="drawer-section">
          <div class="drawer-section-title">CVE VULNERABILITY DETAILS</div>
          <div class="property-list">
            <span class="property-key">CVE ID</span><span class="property-value mono font-bold" style="color: var(--accent-blue);">${escapeHtml(d.cve_id)}</span>
            <span class="property-key">SOURCE</span><span class="property-value">${escapeHtml(d.source)}</span>
            <span class="property-key">VENDOR / PROJECT</span><span class="property-value font-bold">${escapeHtml(d.vendor_project || 'N/A')}</span>
            <span class="property-key">PRODUCT</span><span class="property-value">${escapeHtml(d.product || 'N/A')}</span>
            <span class="property-key">CVSS BASE SCORE</span><span class="property-value mono font-bold" style="color: var(--accent-red);">${d.cvss_score ? escapeHtml(d.cvss_score + ' (' + (d.cvss_severity || '') + ')') : 'N/A'}</span>
            <span class="property-key">RANSOMWARE USE</span><span class="property-value">${d.known_ransomware_campaign_use === 'Known' ? '<span class="badge badge-ransomware">KNOWN CAMPAIGN</span>' : 'Unknown / Not Reported'}</span>
            <span class="property-key">REQUIRED ACTION</span><span class="property-value warn">${escapeHtml(d.required_action || 'Apply vendor patches or mitigations.')}</span>
            <span class="property-key">DUE DATE</span><span class="property-value mono">${escapeHtml(d.due_date || 'N/A')}</span>
            <span class="property-key">DATE ADDED</span><span class="property-value mono text-muted">${escapeHtml(d.date_added || '')}</span>
          </div>
        </div>
        <div class="drawer-section">
          <div class="drawer-section-title">DESCRIPTION / IMPACT</div>
          <div style="font-size: 12px; line-height: 1.5; color: var(--text-primary);">${escapeHtml(d.short_description || d.vulnerability_name || 'No description provided.')}</div>
        </div>
      `;

      actionsHtml = `
        <a class="external-link" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(d.cve_id)}" target="_blank" rel="noopener">NVD NIST &rarr;</a>
        <a class="external-link" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA KEV Catalog &rarr;</a>
        <a class="external-link" href="https://vulncheck.com/cve/${encodeURIComponent(d.cve_id)}" target="_blank" rel="noopener">VulnCheck &rarr;</a>
        <a class="external-link" href="https://www.exploit-db.com/search?cve=${encodeURIComponent(d.cve_id.replace('CVE-', ''))}" target="_blank" rel="noopener">Exploit-DB &rarr;</a>
      `;

    } else if (type === 'ioc') {
      const observations = Array.isArray(d.source_observations) ? d.source_observations : [];
      propsHtml = `
        <div class="drawer-section"><div class="drawer-section-title">NORMALIZED INDICATOR</div><div class="property-list">
          <span class="property-key">TYPE</span><span class="property-value mono">${escapeHtml((d.indicator_type || '').toUpperCase())}</span>
          <span class="property-key">VALUE</span><span class="property-value mono font-bold info">${escapeHtml(d.normalized_value)}</span>
          <span class="property-key">THREAT</span><span class="property-value">${escapeHtml(d.threat_type || 'indicator')}</span>
          <span class="property-key">CONFIDENCE</span><span class="property-value mono font-bold">${Number(d.confidence) || 0}% · ${escapeHtml(d.severity || '')}</span>
          <span class="property-key">MALWARE FAMILY</span><span class="property-value">${escapeHtml(d.malware_family || 'N/A')}</span>
          <span class="property-key">FIRST / LAST SEEN</span><span class="property-value mono text-muted">${escapeHtml(formatDateTime(d.first_seen))}<br>${escapeHtml(formatDateTime(d.last_seen))}</span>
        </div></div>
        <div class="drawer-section"><div class="drawer-section-title">SOURCE CORRELATION (${observations.length})</div>
          <div class="source-observation-list">${observations.map(source => `<div class="source-observation">
            <div><strong class="mono">${escapeHtml((source.source_name || '').replaceAll('_', ' ').toUpperCase())}</strong> <span class="badge ${source.active ? 'badge-kev' : 'badge-filetype'}">${source.active ? 'ACTIVE' : 'EXPIRED'}</span></div>
            <div class="mono text-muted">Confidence ${Number(source.confidence) || 0}% · Last seen ${escapeHtml(formatDateTime(source.last_seen))}</div>
          </div>`).join('') || '<div class="text-muted">No source observations available.</div>'}</div>
        </div>`;
      const referenceUrl = safeHttpUrl(d.reference_url);
      actionsHtml = `${referenceUrl ? `<a class="external-link" href="${escapeHtml(referenceUrl)}" target="_blank" rel="noopener">Provider Reference &rarr;</a>` : ''}
        <a class="external-link" href="https://www.virustotal.com/gui/search/${encodeURIComponent(d.normalized_value || '')}" target="_blank" rel="noopener">VirusTotal Search &rarr;</a>`;

    } else if (type === 'attack') {
      const aliases = Array.isArray(d.parsed_aliases) ? d.parsed_aliases : [];
      const tactics = Array.isArray(d.parsed_tactics) ? d.parsed_tactics : [];
      const platforms = Array.isArray(d.parsed_platforms) ? d.parsed_platforms : [];
      propsHtml = `<div class="drawer-section"><div class="drawer-section-title">MITRE ATT&amp;CK KNOWLEDGE</div><div class="property-list">
        <span class="property-key">ATT&amp;CK ID</span><span class="property-value mono font-bold info">${escapeHtml(d.external_id || 'N/A')}</span>
        <span class="property-key">OBJECT TYPE</span><span class="property-value">${escapeHtml((d.object_type || '').replaceAll('-', ' ').toUpperCase())}</span>
        <span class="property-key">NAME</span><span class="property-value font-bold">${escapeHtml(d.name)}</span>
        <span class="property-key">ALIASES</span><span class="property-value">${escapeHtml(aliases.join(', ') || 'N/A')}</span>
        <span class="property-key">TACTICS</span><span class="property-value">${escapeHtml(tactics.join(', ') || 'N/A')}</span>
        <span class="property-key">PLATFORMS</span><span class="property-value">${escapeHtml(platforms.join(', ') || 'N/A')}</span>
      </div></div><div class="drawer-section"><div class="drawer-section-title">DESCRIPTION</div><div class="drawer-long-text">${escapeHtml(d.description || 'No description available.')}</div></div>`;
      const attackUrl = safeHttpUrl(d.reference_url);
      actionsHtml = attackUrl ? `<a class="external-link" href="${escapeHtml(attackUrl)}" target="_blank" rel="noopener">MITRE ATT&amp;CK &rarr;</a>` : '';

    } else if (type === 'advisory') {
      propsHtml = `<div class="drawer-section"><div class="drawer-section-title">OFFICIAL VENDOR ADVISORY</div><div class="property-list">
        <span class="property-key">VENDOR</span><span class="property-value font-bold">${escapeHtml(d.vendor)}</span>
        <span class="property-key">PRODUCT</span><span class="property-value">${escapeHtml(d.product || 'N/A')}</span>
        <span class="property-key">CVE / ADVISORY</span><span class="property-value mono info">${escapeHtml(d.cve_ids || d.advisory_id)}</span>
        <span class="property-key">SEVERITY</span><span class="property-value"><span class="badge badge-warn">${escapeHtml(d.severity || 'UNKNOWN')}</span></span>
        <span class="property-key">TITLE</span><span class="property-value">${escapeHtml(d.title)}</span>
        <span class="property-key">PUBLISHED</span><span class="property-value mono text-muted">${escapeHtml(formatDateTime(d.published_at || d.published_date || d.updated_at))}</span>
      </div></div>`;
      const advisoryUrl = safeHttpUrl(d.reference_url);
      actionsHtml = advisoryUrl ? `<a class="external-link" href="${escapeHtml(advisoryUrl)}" target="_blank" rel="noopener">Official Vendor Advisory &rarr;</a>` : '';

    } else if (type === 'malware') {
      propsHtml = `
        <div class="drawer-section">
          <div class="drawer-section-title">MALWARE SAMPLE INDICATORS</div>
          <div class="property-list">
            <span class="property-key">SHA256</span><span class="property-value mono font-bold" style="color: var(--accent-purple);">${escapeHtml(d.sha256_hash)}</span>
            <span class="property-key">MD5</span><span class="property-value mono">${escapeHtml(d.md5_hash || 'N/A')}</span>
            <span class="property-key">SHA1</span><span class="property-value mono">${escapeHtml(d.sha1_hash || 'N/A')}</span>
            <span class="property-key">FILE NAME</span><span class="property-value mono">${escapeHtml(d.file_name || 'unknown')}</span>
            <span class="property-key">FILE TYPE</span><span class="property-value mono uppercase">${escapeHtml(d.file_type || 'unknown')}</span>
            <span class="property-key">SIGNATURE</span><span class="property-value font-bold" style="color: var(--accent-red);">${escapeHtml(d.signature || 'Unclassified')}</span>
            <span class="property-key">REPORTER</span><span class="property-value mono text-muted">${escapeHtml(d.reporter || 'abuse_ch')}</span>
            <span class="property-key">FIRST SEEN</span><span class="property-value mono text-muted">${escapeHtml(formatDateTime(d.first_seen))}</span>
          </div>
        </div>
      `;

      actionsHtml = `
        <a class="external-link" href="https://bazaar.abuse.ch/sample/${encodeURIComponent(d.sha256_hash)}/" target="_blank" rel="noopener">MalwareBazaar &rarr;</a>
        <a class="external-link" href="https://www.virustotal.com/gui/file/${encodeURIComponent(d.sha256_hash)}" target="_blank" rel="noopener">VirusTotal &rarr;</a>
        <a class="external-link" href="https://www.hybrid-analysis.com/sample/${encodeURIComponent(d.sha256_hash)}" target="_blank" rel="noopener">Hybrid Analysis &rarr;</a>
        <a class="external-link" href="https://app.any.run/submissions/#query=${encodeURIComponent(d.sha256_hash)}" target="_blank" rel="noopener">ANY.RUN &rarr;</a>
      `;

    } else if (type === 'ip') {
      propsHtml = `
        <div class="drawer-section">
          <div class="drawer-section-title">DSHIELD ATTACKING IP INTELLIGENCE</div>
          <div class="property-list">
            <span class="property-key">IP ADDRESS</span><span class="property-value mono font-bold" style="color: var(--accent-cyan);">${escapeHtml(d.ip)}</span>
            <span class="property-key">ATTACKS COUNT</span><span class="property-value mono crit font-bold">${Number(d.attacks) || 0}</span>
            <span class="property-key">PACKETS COUNT</span><span class="property-value mono">${Number(d.count) || 0}</span>
            <span class="property-key">AS / ORG NAME</span><span class="property-value font-bold">${escapeHtml(d.as_name || 'N/A')}</span>
            <span class="property-key">FIRST SEEN</span><span class="property-value mono text-muted">${escapeHtml(d.firstseen || 'N/A')}</span>
            <span class="property-key">LAST SEEN</span><span class="property-value mono text-muted">${escapeHtml(d.lastseen || 'N/A')}</span>
          </div>
        </div>
      `;

      actionsHtml = `
        <a class="external-link" href="https://isc.sans.edu/ipinfo.html?ip=${encodeURIComponent(d.ip)}" target="_blank" rel="noopener">SANS DShield IP Info &rarr;</a>
        <a class="external-link" href="https://www.abuseipdb.com/check/${encodeURIComponent(d.ip)}" target="_blank" rel="noopener">AbuseIPDB &rarr;</a>
        <a class="external-link" href="https://www.shodan.io/host/${encodeURIComponent(d.ip)}" target="_blank" rel="noopener">Shodan &rarr;</a>
        <a class="external-link" href="https://viz.greynoise.io/ip/${encodeURIComponent(d.ip)}" target="_blank" rel="noopener">GreyNoise &rarr;</a>
      `;

    } else if (type === 'port') {
      propsHtml = `
        <div class="drawer-section">
          <div class="drawer-section-title">PORT TELEMETRY</div>
          <div class="property-list">
            <span class="property-key">PORT NUMBER</span><span class="property-value mono font-bold" style="color: var(--accent-orange);">${Number(d.port) || 0}</span>
            <span class="property-key">KNOWN SERVICE</span><span class="property-value mono font-bold">${escapeHtml(d.service || 'Unknown')}</span>
            <span class="property-key">ATTACK SOURCES</span><span class="property-value mono warn font-bold">${Number(d.count) || 0}</span>
            <span class="property-key">PACKET RECORDS</span><span class="property-value mono">${Number(d.records) || 0}</span>
            <span class="property-key">TARGET SYSTEMS</span><span class="property-value mono">${Number(d.targets) || 0}</span>
          </div>
        </div>
      `;

      actionsHtml = `
        <a class="external-link" href="https://isc.sans.edu/port.html?port=${Number(d.port) || 0}" target="_blank" rel="noopener">SANS DShield Port Report &rarr;</a>
        <a class="external-link" href="https://www.speedguide.net/port.php?port=${Number(d.port) || 0}" target="_blank" rel="noopener">SpeedGuide Port DB &rarr;</a>
      `;

    } else if (type === 'ransomware') {
      const observations = Array.isArray(d.source_observations) ? d.source_observations : [];
      const publicRecordUrl = safeHttpUrl(d.url);
      const claimUrl = safeHttpUrl(d.claim_url);
      const screenshotUrl = safeHttpUrl(d.screenshot);
      propsHtml = `
        <div class="drawer-section">
          <div class="drawer-section-title">${d.incident_type === 'data_breach' ? 'PUBLIC DATA BREACH REPORT' : 'RANSOMWARE EXTORTION DISCLOSURE'}</div>
          <div class="property-list">
            <span class="property-key">VICTIM</span><span class="property-value font-bold">${escapeHtml(d.victim_name || 'Unknown')}</span>
            <span class="property-key">THREAT ACTOR</span><span class="property-value"><span class="badge badge-ransomware mono font-bold">${escapeHtml((d.group_name || 'UNKNOWN').toUpperCase())}</span></span>
            <span class="property-key">COUNTRY</span><span class="property-value mono">${escapeHtml(d.country || 'N/A')}</span>
            <span class="property-key">DOMAIN / ACTIVITY</span><span class="property-value mono">${escapeHtml(d.domain || d.activity || 'N/A')}</span>
            <span class="property-key">DISCOVERED</span><span class="property-value mono text-muted">${escapeHtml(formatDateTime(d.discovered || d.updated_at))}</span>
            <span class="property-key">ATTACK DATE</span><span class="property-value mono text-muted">${escapeHtml(d.attackdate ? formatDateTime(d.attackdate) : 'N/A')}</span>
            <span class="property-key">INCIDENT TYPE</span><span class="property-value mono">${escapeHtml((d.incident_type || 'ransomware_extortion').replaceAll('_', ' ').toUpperCase())}</span>
            <span class="property-key">CONFIDENCE</span><span class="property-value mono font-bold">${Number(d.confidence_score) || 55}% · ${Number(d.source_count) || 1} SOURCE${Number(d.source_count) === 1 ? '' : 'S'}</span>
            <span class="property-key">FIRST / LAST SEEN</span><span class="property-value mono text-muted">${escapeHtml(formatDateTime(d.first_seen))}<br>${escapeHtml(formatDateTime(d.last_seen))}</span>
          </div>
        </div>
        ${d.description ? `
          <div class="drawer-section">
            <div class="drawer-section-title">DISCLOSURE DETAILS</div>
            <div style="font-size: 12px; line-height: 1.5; color: var(--text-secondary);">${escapeHtml(d.description)}</div>
          </div>
        ` : ''}
        <div class="drawer-section">
          <div class="drawer-section-title">SOURCE PROVENANCE (${observations.length})</div>
          <div class="source-observation-list">${observations.map(source => `<div class="source-observation">
            <div><strong class="mono">${escapeHtml(source.source_name || 'PUBLIC CTI')}</strong> <span class="badge badge-filetype">${escapeHtml((source.incident_type || '').replaceAll('_', ' ').toUpperCase())}</span></div>
            <div class="mono text-muted">First seen ${escapeHtml(formatDateTime(source.first_seen))} · Updated ${escapeHtml(formatDateTime(source.last_seen))}</div>
            ${safeHttpUrl(source.reference_url) ? `<a class="external-link" href="${escapeHtml(safeHttpUrl(source.reference_url))}" target="_blank" rel="noopener">Provider evidence &rarr;</a>` : ''}
          </div>`).join('') || '<div class="text-muted">No source observations available.</div>'}</div>
        </div>
      `;

      actionsHtml = `
        ${publicRecordUrl ? `<a class="external-link" href="${escapeHtml(publicRecordUrl)}" target="_blank" rel="noopener">Provider Record &rarr;</a>` : ''}
        ${claimUrl ? `<a class="external-link" href="${escapeHtml(claimUrl)}" target="_blank" rel="noopener">Public Claim Source &rarr;</a>` : ''}
        ${screenshotUrl ? `<a class="external-link" href="${escapeHtml(screenshotUrl)}" target="_blank" rel="noopener">Evidence Screenshot &rarr;</a>` : ''}
        ${!publicRecordUrl && !claimUrl && !screenshotUrl ? '<span class="mono text-muted">No public pivot URL supplied by the source.</span>' : ''}
      `;

    } else if (type === 'news') {
      propsHtml = `
        <div class="drawer-section">
          <div class="drawer-section-title">CTI ADVISORY DETAILS</div>
          <div class="property-list">
            <span class="property-key">TITLE</span><span class="property-value font-bold">${escapeHtml(d.title)}</span>
            <span class="property-key">SOURCE</span><span class="property-value">${escapeHtml(d.source)}</span>
            <span class="property-key">PUBLISHED</span><span class="property-value mono text-muted">${escapeHtml(formatDateTime(d.published_at || d.published_date || d.updated_at))}</span>
          </div>
        </div>
        ${d.snippet ? `
          <div class="drawer-section">
            <div class="drawer-section-title">SUMMARY / INTELLIGENCE SNIPPET</div>
            <div style="font-size: 12px; line-height: 1.5; color: var(--text-secondary);">${escapeHtml(d.snippet)}</div>
          </div>
        ` : ''}
      `;

      const articleUrl = safeHttpUrl(d.link);
      actionsHtml = articleUrl
        ? `<a class="external-link" href="${escapeHtml(articleUrl)}" target="_blank" rel="noopener">Open Original Article &rarr;</a>`
        : '<span class="mono text-muted">No safe public article URL supplied by the source.</span>';
    }

    let rawRecord = d;
    if (d.parsed_raw !== undefined) {
      rawRecord = d.parsed_raw;
    } else if (typeof d.raw_json === 'string' && d.raw_json) {
      try {
        rawRecord = JSON.parse(d.raw_json);
      } catch (_err) {
        rawRecord = d.raw_json;
      }
    } else if (d.raw_json && typeof d.raw_json === 'object') {
      rawRecord = d.raw_json;
    }
    const rawJsonStr = JSON.stringify(rawRecord, null, 2) || String(rawRecord);

    content.innerHTML = `
      ${propsHtml}
      <div class="drawer-section">
        <div class="drawer-section-title">EXTERNAL THREAT PIVOTS</div>
        <div class="external-actions">
          ${actionsHtml}
        </div>
      </div>
      <div class="drawer-section">
        <div class="drawer-section-title" style="display: flex; justify-content: space-between; align-items: center;">
          <span>RAW RECORD PAYLOAD</span>
          <button class="btn" id="copy-raw-json-button" style="padding: 2px 6px; font-size: 10px;">COPY JSON</button>
        </div>
        <pre class="json-viewer" id="raw-json-pre">${escapeHtml(rawJsonStr)}</pre>
      </div>
    `;
    document.getElementById('copy-raw-json-button')?.addEventListener('click', copyRawJson);

  } catch (err) {
    content.innerHTML = `<div class="empty-row" style="color: var(--accent-red);">Failed retrieving artifact: ${escapeHtml(err.message)}</div>`;
  }
}

function closeDrawer() {
  document.getElementById('inspection-drawer').classList.remove('open');
  document.getElementById('drawer-overlay').classList.remove('open');
}

function copyRawJson() {
  const pre = document.getElementById('raw-json-pre');
  if (pre) {
    navigator.clipboard.writeText(pre.textContent).then(() => {
      alert('Raw JSON payload copied to clipboard.');
    });
  }
}

// ==================== SYNC & REALTIME POLLING ====================

async function triggerManualSync() {
  const btn = document.getElementById('btn-sync');
  const spinner = document.getElementById('sync-spinner');
  const label = document.getElementById('sync-label');

  const adminToken = integrationAdminToken || document.getElementById('wl-admin-token')?.value.trim() || '';
  if (!adminToken) {
    alert('Administrative access code is required to start a manual synchronization.');
    return;
  }

  btn.disabled = true;
  spinner.style.display = 'inline-block';
  label.textContent = 'SYNCING...';

  try {
    const res = await fetch('/api/sync', {
      method: 'POST',
      headers: { 'X-Admin-Token': adminToken }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    await res.json();

    if (syncPollingInterval) clearInterval(syncPollingInterval);
    syncPollingInterval = setInterval(async () => {
      const isFinished = await pollStatus();
      if (isFinished) {
        clearInterval(syncPollingInterval);
        syncPollingInterval = null;
        btn.disabled = false;
        spinner.style.display = 'none';
        label.textContent = 'SYNC FEEDS';

        // Reload data if on active tab
        if (currentTab === 'panel-cves') loadCves();
        else if (currentTab === 'panel-malware') loadMalware();
        else if (currentTab === 'panel-dshield') loadDshield();
        else if (currentTab === 'panel-ransomware') loadRansomware();
  else if (currentTab === 'panel-news') loadNews();
      }
    }, 2500);

  } catch (err) {
    console.error('Sync failed:', err);
    btn.disabled = false;
    spinner.style.display = 'none';
    label.textContent = 'SYNC FEEDS';
  }
}

function connectorStateLabel(state) {
  if (state === 'failed') return 'ERROR';
  return String(state || 'never_run').replaceAll('_', ' ').toUpperCase();
}

function connectorGroupState(connectors) {
  const rank = {
    healthy: 0,
    disabled: 1,
    never_run: 2,
    auth_required: 3,
    degraded: 4,
    rate_limited: 4,
    failed: 5
  };
  const worst = [...connectors].sort((a, b) => (rank[b.state] ?? 2) - (rank[a.state] ?? 2))[0];
  if (!worst || worst.state === 'healthy') return 'healthy';
  if (worst.state === 'failed') return 'failed';
  if (worst.state === 'disabled') return 'muted';
  return 'attention';
}

function splitSourceHealthGroups(groupEntries) {
  const totals = [0, 0];
  return [...groupEntries].sort((a, b) => b[1].length - a[1].length).reduce((columns, entry) => {
    const target = totals[0] <= totals[1] ? 0 : 1;
    columns[target].push(entry);
    totals[target] += entry[1].length;
    return columns;
  }, [[], []]);
}

function sourceHealthGroupMarkup(category, items) {
  const categoryHealthy = items.filter(item => item.state === 'healthy').length;
  const groupState = connectorGroupState(items);
  return `<section class="source-category-group ${groupState}">
    <div class="source-category-heading mono"><span>${escapeHtml(category.toUpperCase())}</span><strong>${categoryHealthy}/${items.length}</strong></div>
    <div class="source-category-items">${items.map(item => {
      const detail = item.last_error || `Last success: ${formatDateTime(item.last_success)}`;
      return `<div class="source-health-item ${escapeHtml(item.state)}" title="${escapeHtml(detail)}">
        <i class="status-dot ${escapeHtml(item.state)}"></i>
        <span class="mono">${escapeHtml(item.source_name.replaceAll('_', ' ').toUpperCase())}</span>
        <small class="mono">${escapeHtml(connectorStateLabel(item.state))}</small>
        <span class="source-health-sparkline" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i></span>
      </div>`;
    }).join('')}</div>
  </section>`;
}

function renderSourceHealthColumn(side, groupEntries) {
  const categories = document.getElementById(`source-health-categories-${side}`);
  if (categories) categories.innerHTML = groupEntries.map(([category, items]) => sourceHealthGroupMarkup(category, items)).join('');
}

function renderSourceHealthFlow(side, groupEntries) {
  const flow = document.getElementById(`source-health-flow-${side}`);
  if (!flow) return;
  const height = 320;
  const targetY = height / 2;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const routes = groupEntries.map(([category, connectors], index) => {
    const y = groupEntries.length === 1 ? targetY : 20 + (index * ((height - 40) / (groupEntries.length - 1)));
    const state = connectorGroupState(connectors);
    const pathId = `source-route-${side}-${index}`;
    const path = side === 'left'
      ? `M 4 ${y.toFixed(1)} C 105 ${y.toFixed(1)}, 176 ${targetY.toFixed(1)}, 316 ${targetY.toFixed(1)}`
      : `M 316 ${y.toFixed(1)} C 215 ${y.toFixed(1)}, 144 ${targetY.toFixed(1)}, 4 ${targetY.toFixed(1)}`;
    const packet = reduceMotion ? '' : `
      <circle class="source-flow-packet ${state}" r="3.2">
        <animateMotion dur="${(3.2 + (index * 0.22)).toFixed(2)}s" begin="-${(index * 0.48).toFixed(2)}s" repeatCount="indefinite">
          <mpath href="#${pathId}"></mpath>
        </animateMotion>
      </circle>`;
    return `
      <path class="source-flow-track" d="${path}"></path>
      <path id="${pathId}" class="source-flow-route ${state}" d="${path}"></path>
      ${packet}`;
  }).join('');
  flow.innerHTML = `<svg viewBox="0 0 320 ${height}" preserveAspectRatio="none" focusable="false">${routes}</svg>`;
}

function renderSourceHealth(connectors, sync = {}) {
  if (!Array.isArray(connectors)) return;
  const groups = connectors.reduce((result, connector) => {
    (result[connector.category || 'Other'] ||= []).push(connector);
    return result;
  }, {});
  const groupEntries = Object.entries(groups);
  const [leftGroups, rightGroups] = splitSourceHealthGroups(groupEntries);
  const healthy = connectors.filter(c => c.state === 'healthy').length;
  const needsKeys = connectors.filter(c => c.state === 'auth_required').length;
  const disabled = connectors.filter(c => c.state === 'disabled').length;
  const attention = connectors.filter(c => ['degraded', 'rate_limited'].includes(c.state)).length;
  const failed = connectors.filter(c => c.state === 'failed').length;
  const overallState = failed ? 'failed' : (healthy === connectors.length ? 'healthy' : 'attention');

  const card = document.getElementById('source-health-card');
  if (card) {
    card.dataset.health = overallState;
    card.classList.toggle('is-syncing', Boolean(sync.is_syncing));
  }
  renderSourceHealthColumn('left', leftGroups);
  renderSourceHealthColumn('right', rightGroups);

  const meta = document.getElementById('source-health-meta');
  if (meta) {
    meta.innerHTML = `
      <span class="health-count healthy" id="source-health-summary">${healthy}/${connectors.length} healthy</span>
      ${needsKeys ? `<span class="health-count attention">${needsKeys} need keys</span>` : ''}
      ${attention ? `<span class="health-count attention">${attention} attention</span>` : ''}
      ${failed ? `<span class="health-count failed">${failed} error</span>` : ''}
      ${disabled ? `<span class="health-count muted">${disabled} disabled</span>` : ''}
    `;
  }
  const syncState = document.getElementById('source-health-sync-state');
  if (syncState) {
    const schedulerState = sync.scheduler_running === false ? 'SCHEDULER STOPPED' : 'SCHEDULED INGESTION';
    syncState.innerHTML = `<i class="status-indicator-dot pulse-sync"></i>${sync.is_syncing ? 'SYNCING NOW' : schedulerState}`;
    syncState.classList.toggle('failed', sync.scheduler_running === false);
  }
  const coreStatus = document.getElementById('source-core-status');
  if (coreStatus) coreStatus.textContent = failed ? 'SOURCE ERROR' : (overallState === 'healthy' ? 'ALL SOURCES HEALTHY' : 'MONITORING ATTENTION');
  const coreCount = document.getElementById('source-core-count');
  if (coreCount) coreCount.textContent = `${connectors.length} CONNECTORS`;
  renderSourceHealthFlow('left', leftGroups);
  renderSourceHealthFlow('right', rightGroups);
}

async function pollStatus() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return false;
    const data = await res.json();

    // Keep the INFOCON state live inside the map HUD.
    if (data.stats && data.stats.infocon) {
      const status = (data.stats.infocon.status || 'unknown').toLowerCase();
      const val = document.getElementById('infocon-val');
      if (val) {
        val.className = `hud-val mono ${status === 'green' ? 'ok' : (['yellow', 'orange'].includes(status) ? 'warn' : (status === 'red' ? 'crit' : ''))}`.trim();
        val.textContent = status.toUpperCase();
      }
    }

    // Update Metrics Strip
    if (data.stats) {
      const s = data.stats;
      const elCves = document.getElementById('stat-total-cves');
      if (elCves) elCves.textContent = s.total_cves;

      const elKev = document.getElementById('stat-total-kev');
      if (elKev) elKev.textContent = s.total_kev;

      const elCrit = document.getElementById('stat-total-critical');
      if (elCrit) elCrit.textContent = s.total_critical_cves;

      const metricMap = {
        'stat-total-iocs': s.total_active_iocs,
        'stat-correlated-iocs': s.total_correlated_iocs,
        'stat-malicious-ips': s.total_malicious_ips,
        'stat-vendor-advisories': s.total_vendor_advisories,
        'stat-attack-objects': s.total_attack_objects,
      };
      Object.entries(metricMap).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) element.textContent = Number(value || 0).toLocaleString();
      });

      // Mirror the dashboard's public DShield Top Targeted Ports widget.
      renderMapTopTargetedPorts(s.top_ports);

    }

    // Update the animated dashboard source-health topology.
    if (data.connectors) {
      renderSourceHealth(data.connectors, data.sync || {});
    }

    const isSyncing = data.sync && data.sync.is_syncing;
    return !isSyncing;

  } catch (err) {
    console.warn('Poll status error:', err);
    return false;
  }
}

// Utility: escape HTML
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeHttpUrl(value) {
  if (!value) return '';
  try {
    const parsed = new URL(String(value), window.location.origin);
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : '';
  } catch (_err) {
    return '';
  }
}

function sha1Fallback(message) {
  const bytes = new TextEncoder().encode(message);
  const words = [];
  for (let i = 0; i < bytes.length; i++) words[i >> 2] = (words[i >> 2] || 0) | bytes[i] << (24 - (i % 4) * 8);
  words[bytes.length >> 2] = (words[bytes.length >> 2] || 0) | 0x80 << (24 - (bytes.length % 4) * 8);
  words[(((bytes.length + 8) >> 6) + 1) * 16 - 1] = bytes.length * 8;
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const rotate = (value, bits) => (value << bits) | (value >>> (32 - bits));
  for (let block = 0; block < words.length; block += 16) {
    const w = new Array(80);
    for (let i = 0; i < 16; i++) w[i] = words[block + i] || 0;
    for (let i = 16; i < 80; i++) w[i] = rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const temp = (rotate(a, 5) + f + e + k + w[i]) | 0;
      e = d; d = c; c = rotate(b, 30); b = a; a = temp;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }
  return [h0, h1, h2, h3, h4].map(value => (value >>> 0).toString(16).padStart(8, '0')).join('').toUpperCase();
}

async function sha1Hex(message) {
  if (window.crypto?.subtle) {
    const digest = await window.crypto.subtle.digest('SHA-1', new TextEncoder().encode(message));
    return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  return sha1Fallback(message);
}


// ==================== RANSOMWARE TRACKER (v1.2.0) ====================

async function loadRansomware() {
  const q = document.getElementById('ransomware-search')?.value.trim() || '';
  const country = document.getElementById('filter-ransomware-country') ? document.getElementById('filter-ransomware-country').value : 'all';

  const tbody = document.getElementById('ransomware-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="loading-row">Carregando telemetria de ransomware...</td></tr>';

  const offset = (ransomwareState.page - 1) * ransomwareState.limit;

  try {
    const params = new URLSearchParams({
      limit: ransomwareState.limit,
      offset: offset
    });
    if (q) params.set('q', q);
    if (country !== 'all') params.set('country', country);

    const res = await fetch(`/api/ransomware?${params.toString()}`);
    const data = await res.json();

    ransomwareState.total = data.total;
    updateRansomwarePagination();

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No public exposure incidents found for current filters.</td></tr>';
      return;
    }

    tbody.innerHTML = data.items.map(item => {
      const countryValue = String(item.country || '').trim();
      const normalizedCountry = countryValue.toUpperCase();
      const isBR = ['BR', 'BRA', 'BRAZIL', 'BRASIL'].includes(normalizedCountry);
      const countryCode = normalizedCountry.length === 2 ? normalizedCountry : (isBR ? 'BR' : '');
      const countryFlag = countryCode && /^[A-Z]{2}$/.test(countryCode)
        ? String.fromCodePoint(...countryCode.split('').map(character => 127397 + character.charCodeAt(0)))
        : '';
      const countryLabel = isBR ? 'BRASIL' : countryValue;
      const highlightedCountry = isBR || Boolean(item.country_watched);
      const countryBadge = countryValue
        ? `<span class="badge ${highlightedCountry ? 'badge-crit watchlist-country-badge' : 'badge-filetype'} mono${highlightedCountry ? ' font-bold' : ''}" title="${escapeHtml(countryLabel)}">${countryFlag ? `${countryFlag} ` : ''}${escapeHtml(countryLabel)}</span>`
        : '<span class="mono text-muted">-</span>';

      return `
      <tr class="clickable-row" data-artifact-type="ransomware" data-artifact-id="${escapeHtml(item.id)}">
        <td class="mono text-muted timestamp-cell" title="${escapeHtml(formatDateTime(item.discovered || item.attackdate || item.updated_at))}">${tableTimestampMarkup(item.discovered || item.attackdate || item.updated_at)}</td>
        <td><span class="badge ${item.incident_type === 'data_breach' ? 'badge-warn' : 'badge-ransomware'} mono font-bold">${escapeHtml(item.incident_type === 'data_breach' ? 'DATA BREACH' : (item.group_name || 'UNKNOWN'))}</span></td>
        <td class="font-bold wrap-cell" title="${escapeHtml(item.victim_name)}">${escapeHtml(item.victim_name)}</td>
        <td class="country-cell">${countryBadge}</td>
        <td class="mono wrap-cell" style="color: var(--accent-blue);" title="${escapeHtml(item.domain || item.activity || '-')}">${escapeHtml(item.domain || item.activity || '-')}</td>
        <td><span class="badge ${Number(item.source_count) > 1 ? 'badge-kev' : 'badge-filetype'} mono">${Number(item.confidence_score) || 55}%</span> <span class="mono text-muted">${Number(item.source_count) || 1} SRC</span></td>
      </tr>
      `;
    }).join('');

  } catch (err) {
    console.error('Failed to load ransomware data:', err);
    tbody.innerHTML = `<tr><td colspan="6" class="error-row">Error loading ransomware feed: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function updateRansomwarePagination() {
  const totalPages = Math.ceil(ransomwareState.total / ransomwareState.limit) || 1;
  const start = ransomwareState.total === 0 ? 0 : (ransomwareState.page - 1) * ransomwareState.limit + 1;
  const end = Math.min(ransomwareState.page * ransomwareState.limit, ransomwareState.total);

  const text = `Showing ${start} - ${end} of ${ransomwareState.total} incidents`;
  const infoTop = document.getElementById('ransomware-page-info');
  const infoBottom = document.getElementById('ransomware-page-info-bottom');
  if (infoTop) infoTop.textContent = text;
  if (infoBottom) infoBottom.textContent = text;

  const pageNum = document.getElementById('ransomware-page-num');
  if (pageNum) pageNum.textContent = `PAGE ${ransomwareState.page} / ${totalPages}`;

  const prevBtn = document.getElementById('ransomware-btn-prev');
  const prevBtnB = document.getElementById('ransomware-btn-prev-b');
  const nextBtn = document.getElementById('ransomware-btn-next');
  const nextBtnB = document.getElementById('ransomware-btn-next-b');

  if (prevBtn) prevBtn.disabled = (ransomwareState.page <= 1);
  if (prevBtnB) prevBtnB.disabled = (ransomwareState.page <= 1);
  if (nextBtn) nextBtn.disabled = (ransomwareState.page >= totalPages);
  if (nextBtnB) nextBtnB.disabled = (ransomwareState.page >= totalPages);
}

function ransomwarePrevPage() {
  if (ransomwareState.page > 1) {
    ransomwareState.page--;
    loadRansomware();
  }
}

function ransomwareNextPage() {
  const totalPages = Math.ceil(ransomwareState.total / ransomwareState.limit);
  if (ransomwareState.page < totalPages) {
    ransomwareState.page++;
    loadRansomware();
  }
}

function changeRansomwarePageSize(newSize) {
  ransomwareState.limit = parseInt(newSize, 10);
  ransomwareState.page = 1;
  loadRansomware();
}



// ==================== LIVE CYBERATTACK MAP ENGINE (v1.5.3 REAL ATLAS) ====================

let mapCanvas = null;
let mapCtx = null;
let attackMapInitialized = false;
let activeArcs = [];
let impactRipples = [];
let worldPolygons = null;

// Enforce strict 2:1 equirectangular projection centered inside canvas
function geoToCanvas(lon, lat, w, h) {
  const mapAspect = 2.0;
  let mapW, mapH, offsetX, offsetY;

  if (w / h > mapAspect) {
    mapH = h * 0.94;
    mapW = mapH * mapAspect;
    offsetX = (w - mapW) / 2;
    offsetY = (h - mapH) / 2;
  } else {
    mapW = w * 0.98;
    mapH = mapW / mapAspect;
    offsetX = (w - mapW) / 2;
    offsetY = (h - mapH) / 2;
  }

  const x = offsetX + (lon + 180) * (mapW / 360);
  const y = offsetY + ((-lat) + 90) * (mapH / 180);
  return { x, y };
}

async function loadWorldPolygons() {
  if (worldPolygons) return;
  try {
    const res = await fetch('/static/data/world_polygons.json');
    if (res.ok) {
      worldPolygons = await res.json();
    }
  } catch (e) {
    console.warn('Failed to load world polygons, using fallback:', e);
  }
}

function initAttackMap() {
  mapCanvas = document.getElementById('attack-map-canvas');
  if (!mapCanvas) return;
  mapCtx = mapCanvas.getContext('2d');

  function resizeCanvas() {
    if (!mapCanvas) return;
    const parent = mapCanvas.parentElement;
    if (parent && parent.clientWidth > 50) {
      mapCanvas.width = parent.clientWidth;
      mapCanvas.height = parent.clientHeight || 540;
    }
  }

  resizeCanvas();
  setTimeout(resizeCanvas, 80);
  setTimeout(resizeCanvas, 300);
  window.addEventListener('resize', resizeCanvas);

  loadWorldPolygons();

  if (!attackMapInitialized) {
    attackMapInitialized = true;
    startAttackSimulation();
    requestAnimationFrame(renderAttackMapFrame);
  }
}

function startAttackSimulation() {
  async function fetchLiveAttacks() {
    try {
      const res = await fetch('/api/attacks/live');
      if (!res.ok) return;
      const data = await res.json();
      if (data.attacks && data.attacks.length > 0) {
        data.attacks.forEach((atk, idx) => {
          setTimeout(() => {
            spawnAttackArc(atk);
            prependLiveStream(atk);
          }, idx * 360);
        });
      }
    } catch (e) {
      console.warn('Live attack stream poller error:', e);
    }
  }

  fetchLiveAttacks();
  setInterval(fetchLiveAttacks, 5000);
}

function spawnAttackArc(atk) {
  if (!mapCanvas) return;
  const w = mapCanvas.width;
  const h = mapCanvas.height;

  const start = geoToCanvas(atk.src_lon, atk.src_lat, w, h);
  const end = geoToCanvas(atk.dst_lon, atk.dst_lat, w, h);

  const midX = (start.x + end.x) / 2;
  const midY = Math.min(start.y, end.y) - Math.abs(start.x - end.x) * 0.22 - 30;

  activeArcs.push({
    start,
    end,
    ctrl: { x: midX, y: midY },
    progress: 0,
    speed: 0.012 + Math.random() * 0.008,
    color: atk.severity === 'CRITICAL' ? '#f85149' : (atk.port === 443 ? '#38bdf8' : '#eab308'),
    data: atk
  });
}

function prependLiveStream(atk) {
  const container = document.getElementById('map-live-stream');
  if (!container) return;

  const placeholder = container.querySelector('.stream-item-placeholder');
  if (placeholder) placeholder.remove();

  const item = document.createElement('div');
  item.className = 'stream-item';
  item.innerHTML = `
    <div class="stream-item-top">
      <div class="stream-trajectory">
        <span class="mono font-bold" style="color: var(--accent-red);">${escapeHtml(atk.src_country)}</span>
        <span class="text-muted">&rarr;</span>
        <span class="mono font-bold" style="color: var(--accent-green);">${escapeHtml(atk.dst_country)}</span>
      </div>
      <span class="badge ${atk.severity === 'CRITICAL' ? 'badge-crit' : 'badge-warn'} mono font-bold">${Number(atk.port) || 0} / ${escapeHtml(atk.service)}</span>
    </div>
    <div class="stream-meta">
      <span class="mono text-muted">${escapeHtml(atk.src_ip)}</span>
      <span class="mono text-muted">${escapeHtml(atk.time)}</span>
    </div>
  `;

  container.prepend(item);
  while (container.children.length > 25) {
    container.removeChild(container.lastChild);
  }
}

function renderAttackMapFrame() {
  if (!mapCanvas || !mapCtx) return;
  const ctx = mapCtx;
  const w = mapCanvas.width;
  const h = mapCanvas.height;

  // Background
  ctx.fillStyle = '#040711';
  ctx.fillRect(0, 0, w, h);

  // Subtle coordinate grid
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 45) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }
  for (let y = 0; y < h; y += 45) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  // Draw Real Cartographic World Map
  if (worldPolygons && worldPolygons.length > 0) {
    ctx.fillStyle = '#0f172a';
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1.0;

    for (let i = 0; i < worldPolygons.length; i++) {
      const ring = worldPolygons[i];
      if (ring.length < 3) continue;

      ctx.beginPath();
      const first = geoToCanvas(ring[0][0], ring[0][1], w, h);
      ctx.moveTo(first.x, first.y);

      for (let j = 1; j < ring.length; j++) {
        const pt = geoToCanvas(ring[j][0], ring[j][1], w, h);
        ctx.lineTo(pt.x, pt.y);
      }

      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
  }

  // Animate Ballistic Laser Arcs
  for (let i = activeArcs.length - 1; i >= 0; i--) {
    const arc = activeArcs[i];
    arc.progress += arc.speed;

    const t = Math.min(arc.progress, 1);
    const currX = (1 - t) * (1 - t) * arc.start.x + 2 * (1 - t) * t * arc.ctrl.x + t * t * arc.end.x;
    const currY = (1 - t) * (1 - t) * arc.start.y + 2 * (1 - t) * t * arc.ctrl.y + t * t * arc.end.y;

    // Glowing trajectory line
    ctx.strokeStyle = arc.color + '44';
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.moveTo(arc.start.x, arc.start.y);
    ctx.quadraticCurveTo(arc.ctrl.x, arc.ctrl.y, arc.end.x, arc.end.y);
    ctx.stroke();

    // Laser particle
    ctx.fillStyle = arc.color;
    ctx.shadowColor = arc.color;
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.arc(currX, currY, 3, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;

    // Origin node point
    ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
    ctx.beginPath();
    ctx.arc(arc.start.x, arc.start.y, 2, 0, Math.PI * 2);
    ctx.fill();

    if (arc.progress >= 1) {
      impactRipples.push({
        x: arc.end.x,
        y: arc.end.y,
        radius: 3,
        alpha: 1,
        color: arc.color
      });
      activeArcs.splice(i, 1);
    }
  }

  // Impact Ripples
  for (let i = impactRipples.length - 1; i >= 0; i--) {
    const rip = impactRipples[i];
    rip.radius += 0.7;
    rip.alpha -= 0.025;

    ctx.strokeStyle = rip.color;
    ctx.globalAlpha = Math.max(0, rip.alpha);
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.arc(rip.x, rip.y, rip.radius, 0, Math.PI * 2);
    ctx.stroke();
    ctx.globalAlpha = 1;

    if (rip.alpha <= 0) {
      impactRipples.splice(i, 1);
    }
  }

  requestAnimationFrame(renderAttackMapFrame);
}

// Auto-start on load
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  setTimeout(initAttackMap, 100);
} else {
  document.addEventListener('DOMContentLoaded', initAttackMap);
}


// ==================== LEAK CHECK MODULE (v1.6.0) ====================

function togglePasswordVisibility() {
  const input = document.getElementById('leak-password-input');
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
}

async function runEmailLeakCheck() {
  const input = document.getElementById('leak-email-input');
  const btn = document.getElementById('btn-check-email');
  const resultsBox = document.getElementById('leak-email-results');
  const consent = document.getElementById('leak-email-consent');
  if (!input || !btn || !resultsBox) return;

  const email = input.value.trim();
  if (!email || !email.includes('@')) {
    alert('Please enter a valid email address.');
    return;
  }
  if (!consent?.checked) {
    alert('Confirm the external lookup before sending this email address to XposedOrNot.');
    return;
  }

  btn.disabled = true;
  btn.innerText = 'QUERYING...';
  resultsBox.style.display = 'block';
  resultsBox.innerHTML = '<div class="loading-row">Querying XposedOrNot global breach database...</div>';

  try {
    const res = await fetch('/api/leak-check/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, consent: true })
    });
    const data = await res.json();

    if (data.exposed) {
      let breachPills = '';
      if (data.breaches && data.breaches.length > 0) {
        breachPills = data.breaches.map(b => `<span class="breach-pill">⚠️ ${escapeHtml(b)}</span>`).join('');
      }

      resultsBox.innerHTML = `
        <div class="leak-status-banner compromised">
          <div class="leak-status-title">⚠️ EMAIL COMPROMISED IN DATA BREACHES</div>
          <div class="leak-status-desc">Email <strong>${escapeHtml(data.email)}</strong> was identified in <strong>${Number(data.count) || 0} public data breach dump(s)</strong> on the Dark Web.</div>
        </div>
        <div style="font-size: 11px; font-weight: 700; color: var(--text-secondary); margin-bottom: 6px;">COMPROMISED SERVICES & BREACHES:</div>
        <div class="breaches-grid">${breachPills}</div>
      `;
    } else {
      resultsBox.innerHTML = `
        <div class="leak-status-banner clean">
          <div class="leak-status-title">✅ NO BREACHES DETECTED</div>
          <div class="leak-status-desc">Email <strong>${escapeHtml(data.email)}</strong> was not found in public databases monitored by XposedOrNot.</div>
        </div>
      `;
    }
  } catch (err) {
    resultsBox.innerHTML = `<div class="leak-status-banner compromised"><div class="leak-status-title">❌ QUERY ERROR</div><div class="leak-status-desc">${escapeHtml(err.message || 'Failed to communicate with server')}</div></div>`;
  } finally {
    btn.disabled = false;
    btn.innerText = 'VERIFY';
  }
}

async function runPasswordLeakCheck() {
  const input = document.getElementById('leak-password-input');
  const btn = document.getElementById('btn-check-password');
  const resultsBox = document.getElementById('leak-password-results');
  if (!input || !btn || !resultsBox) return;

  const password = input.value;
  if (!password) {
    alert('Please enter a password to verify.');
    return;
  }

  btn.disabled = true;
  btn.innerText = 'VERIFYING...';
  resultsBox.style.display = 'block';
  resultsBox.innerHTML = '<div class="loading-row">Calculating SHA-1 and querying K-Anonymity Range API...</div>';

  try {
    const sha1 = await sha1Hex(password);
    const suffix = sha1.slice(5);
    input.value = '';
    const res = await fetch('/api/leak-check/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sha1_prefix: sha1.slice(0, 5) })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const count = Number(data.suffixes?.[suffix]) || 0;
    const exposed = count > 0;

    if (exposed) {
      resultsBox.innerHTML = `
        <div class="leak-status-banner compromised">
          <div class="leak-status-title">☠️ PASSWORD COMPROMISED IN LEAKS!</div>
          <div class="leak-status-desc">
            This password appeared exactly <strong>${count.toLocaleString('en-US')} times</strong> in global data breach dumps (Have I Been Pwned).
            <div style="margin-top: 6px; color: #ff7b72; font-weight: bold;">
              ⛔ NEVER use this password in production or personal accounts.
            </div>
          </div>
        </div>
      `;
    } else {
      resultsBox.innerHTML = `
        <div class="leak-status-banner clean">
          <div class="leak-status-title">✅ NO LEAKS DETECTED</div>
          <div class="leak-status-desc">
            This password was not found in the global dataset of 850M+ compromised passwords (Have I Been Pwned).
          </div>
        </div>
      `;
    }
  } catch (err) {
    resultsBox.innerHTML = `<div class="leak-status-banner compromised"><div class="leak-status-title">❌ QUERY ERROR</div><div class="leak-status-desc">${escapeHtml(err.message || 'Failed to communicate with server')}</div></div>`;
  } finally {
    btn.disabled = false;
    btn.innerText = 'VERIFY';
  }
}


// ==================== SECURE CONNECTOR CREDENTIAL SETTINGS ====================

function integrationStateLabel(state) {
  if (state === 'failed') return 'ERROR';
  return String(state || 'never_run').replaceAll('_', ' ').toUpperCase();
}

function setIntegrationMessage(message, type = '') {
  const element = document.getElementById('integration-access-message');
  if (!element) return;
  element.textContent = message;
  element.className = `integration-message mono ${type}`.trim();
}

function updateTlsFileLabel(inputId, labelId) {
  const input = document.getElementById(inputId);
  const label = document.getElementById(labelId);
  if (!label) return;
  label.textContent = input?.files?.[0]?.name || 'NO FILE SELECTED';
}

function clearTlsFileInputs() {
  [
    ['settings-tls-certificate', 'settings-tls-certificate-name'],
    ['settings-tls-chain', 'settings-tls-chain-name'],
    ['settings-tls-key', 'settings-tls-key-name']
  ].forEach(([inputId, labelId]) => {
    const input = document.getElementById(inputId);
    if (input) input.value = '';
    updateTlsFileLabel(inputId, labelId);
  });
}

function openIntegrationSettings() {
  switchTab('panel-settings', document.getElementById('tab-settings'));
  document.getElementById('settings-integrations-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  setTimeout(() => document.getElementById('integration-admin-token')?.focus(), 350);
}

function closeIntegrationSettings() {
  integrationAdminToken = '';
  document.getElementById('settings-admin-access')?.classList.remove('is-unlocked');
  if (integrationSettingsPoll) {
    clearInterval(integrationSettingsPoll);
    integrationSettingsPoll = null;
  }
  ['threatfox', 'urlhaus', 'alienvault_otx', 'phishtank', 'abuseipdb', 'threatcluster', 'openphish'].forEach(provider => {
    const keyInput = document.getElementById(`integration-key-${provider}`);
    const saveButton = document.getElementById(`integration-save-${provider}`);
    const removeButton = document.getElementById(`integration-remove-${provider}`);
    if (keyInput) { keyInput.value = ''; keyInput.disabled = true; }
    if (saveButton) saveButton.disabled = true;
    if (removeButton) removeButton.disabled = true;
  });
  ['integration-enable-openphish', 'integration-terms-openphish'].forEach(id => {
    const checkbox = document.getElementById(id);
    if (checkbox) { checkbox.checked = false; checkbox.disabled = true; }
  });
  ['settings-timezone', 'settings-locale', 'settings-save-general'].forEach(id => {
    const control = document.getElementById(id);
    if (control) control.disabled = true;
  });
  document.querySelectorAll('.tls-control').forEach(control => { control.disabled = true; });
  clearTlsFileInputs();
  const tokenInput = document.getElementById('integration-admin-token');
  if (tokenInput) tokenInput.value = '';
  setIntegrationMessage(translateMessage('admin_required'));
}

async function parseIntegrationResponse(response) {
  let data = {};
  try { data = await response.json(); } catch (_) { /* no response body */ }
  if (!response.ok) {
    const detail = Array.isArray(data.detail) ? 'Invalid credential format.' : (data.error || data.detail || `HTTP ${response.status}`);
    throw new Error(detail);
  }
  return data;
}

async function verifyIntegrationAccess() {
  const tokenInput = document.getElementById('integration-admin-token');
  const token = tokenInput?.value.trim() || '';
  if (!token) {
    setIntegrationMessage(translateMessage('enter_admin'), 'error');
    return;
  }
  integrationAdminToken = token;
  setIntegrationMessage(translateMessage('verifying_admin'));
  try {
    const sessionResponse = await fetch('/api/admin/watchlist-session', {
      method: 'POST',
      headers: { 'X-Admin-Token': integrationAdminToken }
    });
    await parseIntegrationResponse(sessionResponse);
    await loadIntegrationSettings();
    await loadPublicSettings();
    await loadTlsSettings();
    ['settings-timezone', 'settings-locale', 'settings-save-general'].forEach(id => {
      const control = document.getElementById(id);
      if (control) control.disabled = false;
    });
    if (tokenInput) tokenInput.value = '';
    document.getElementById('settings-admin-access')?.classList.add('is-unlocked');
    setIntegrationMessage(translateMessage('admin_verified'), 'ok');
    if (integrationSettingsPoll) clearInterval(integrationSettingsPoll);
    integrationSettingsPoll = setInterval(() => {
      loadIntegrationSettings(true).catch(() => {});
      loadTlsSettings(true).catch(() => {});
    }, 5000);
  } catch (error) {
    integrationAdminToken = '';
    document.getElementById('settings-admin-access')?.classList.remove('is-unlocked');
    ['settings-timezone', 'settings-locale', 'settings-save-general'].forEach(id => {
      const control = document.getElementById(id);
      if (control) control.disabled = true;
    });
    setIntegrationMessage(error.message, 'error');
  }
}

function renderTlsSettings(data) {
  const stateBadge = document.getElementById('tls-manager-state');
  const meta = document.getElementById('settings-tls-meta');
  const readiness = document.getElementById('settings-tls-readiness-note');
  const ready = Boolean(data.manager_ready);
  const state = data.state || (ready ? 'not_configured' : 'disabled');
  const applicationPort = Number(data.application_port) || 9220;
  const httpPortHelp = document.getElementById('tls-http-port-help');
  if (httpPortHelp) {
    httpPortHelp.textContent = `Nginx public listener for HTTP access or redirect. Application upstream remains on port ${applicationPort}.`;
  }
  if (stateBadge) {
    stateBadge.className = `connector-state ${state === 'active' ? 'healthy' : (state === 'error' ? 'failed' : 'disabled')} mono`;
    stateBadge.textContent = !ready ? 'SETUP REQUIRED' : (state === 'active' ? 'HTTPS ACTIVE' : state.replaceAll('_', ' ').toUpperCase());
  }
  if (readiness) {
    readiness.textContent = ready
      ? 'The certificate and key are validated before an atomic Nginx reload. Failed activation automatically restores the previous listener.'
      : 'Host TLS manager is not installed. Run the documented installer once before configuring HTTPS.';
  }
  if (meta) {
    const address = data.configured
      ? `https://${data.fqdn}${Number(data.https_port) === 443 ? '' : `:${data.https_port}`}`
      : 'HTTPS is not configured';
    const issuer = data.issuer ? ` // Issuer: ${data.issuer}` : '';
    const expiry = data.expires_at ? ` // Expires: ${formatDateTime(data.expires_at)}` : '';
    meta.textContent = `${address}${issuer}${expiry}${data.message ? ` // ${data.message}` : ''}`;
  }
  if (data.fqdn) document.getElementById('settings-tls-fqdn').value = data.fqdn;
  if (data.http_port) document.getElementById('settings-tls-http-port').value = data.http_port;
  if (data.https_port) document.getElementById('settings-tls-https-port').value = data.https_port;
  if (typeof data.redirect_http === 'boolean') document.getElementById('settings-tls-redirect').checked = data.redirect_http;
  document.querySelectorAll('.tls-control').forEach(control => { control.disabled = !ready; });
}

async function loadTlsSettings(silent = false) {
  if (!integrationAdminToken) throw new Error(translateMessage('admin_required'));
  const response = await fetch('/api/admin/settings/tls', {
    cache: 'no-store',
    headers: { 'X-Admin-Token': integrationAdminToken }
  });
  const data = await parseIntegrationResponse(response);
  renderTlsSettings(data);
  if (!silent && !data.manager_ready) {
    setIntegrationMessage('Administrative access verified. HTTPS host manager requires one-time setup.', 'ok');
  }
  return data;
}

async function applyTlsSettings() {
  if (!integrationAdminToken) {
    setIntegrationMessage('Unlock administrative access first.', 'error');
    return;
  }
  const certificate = document.getElementById('settings-tls-certificate')?.files?.[0];
  const privateKey = document.getElementById('settings-tls-key')?.files?.[0];
  const chain = document.getElementById('settings-tls-chain')?.files?.[0];
  if (!certificate || !privateKey) {
    setIntegrationMessage('Select the server certificate and matching private key.', 'error');
    return;
  }
  const form = new FormData();
  form.append('fqdn', document.getElementById('settings-tls-fqdn')?.value.trim() || '');
  form.append('http_port', document.getElementById('settings-tls-http-port')?.value || '80');
  form.append('https_port', document.getElementById('settings-tls-https-port')?.value || '443');
  form.append('redirect_http', String(Boolean(document.getElementById('settings-tls-redirect')?.checked)));
  form.append('certificate', certificate);
  form.append('private_key', privateKey);
  if (chain) form.append('intermediate_chain', chain);
  const button = document.getElementById('settings-tls-apply');
  if (button) button.disabled = true;
  setIntegrationMessage('Validating certificate, key, hostname, and listener ports...');
  try {
    const response = await fetch('/api/admin/settings/tls', {
      method: 'POST',
      headers: { 'X-Admin-Token': integrationAdminToken },
      body: form
    });
    const data = await parseIntegrationResponse(response);
    renderTlsSettings(data);
    clearTlsFileInputs();
    setIntegrationMessage('TLS configuration queued. Existing access remains active during validation.', 'ok');
  } catch (error) {
    setIntegrationMessage(error.message, 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

async function saveGeneralSettings() {
  if (!integrationAdminToken) {
    setIntegrationMessage(translateMessage('unlock_first'), 'error');
    return;
  }
  const timezone = document.getElementById('settings-timezone')?.value || 'UTC';
  const locale = document.getElementById('settings-locale')?.value || 'en';
  const saveButton = document.getElementById('settings-save-general');
  if (saveButton) saveButton.disabled = true;
  setIntegrationMessage(translateMessage('saving_settings'));
  try {
    const response = await fetch('/api/admin/settings/general', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Token': integrationAdminToken
      },
      body: JSON.stringify({ timezone, locale })
    });
    const data = await parseIntegrationResponse(response);
    appSettings = { timezone: data.timezone, locale: data.locale };
    document.body.dataset.timezone = appSettings.timezone;
    document.body.dataset.locale = appSettings.locale;
    document.documentElement.lang = appSettings.locale;
    applyConfiguredDates();
    updateSettingsPreview();
    const zoneStatus = document.getElementById('settings-current-zone');
    if (zoneStatus) zoneStatus.textContent = translateMessage('display_timezone', { timezone: appSettings.timezone });
    setIntegrationMessage(translateMessage('settings_saved', { timezone: appSettings.timezone }), 'ok');
  } catch (error) {
    setIntegrationMessage(error.message, 'error');
  } finally {
    if (saveButton) saveButton.disabled = false;
  }
}

async function loadIntegrationSettings(silent = false) {
  if (!integrationAdminToken) throw new Error(translateMessage('admin_required'));
  const response = await fetch('/api/admin/integrations', {
    headers: { 'X-Admin-Token': integrationAdminToken }
  });
  const data = await parseIntegrationResponse(response);

  (data.items || []).forEach(item => {
    const state = item.state || 'never_run';
    const stateBadge = document.getElementById(`integration-state-${item.provider}`);
    const keyInput = document.getElementById(`integration-key-${item.provider}`);
    const saveButton = document.getElementById(`integration-save-${item.provider}`);
    const removeButton = document.getElementById(`integration-remove-${item.provider}`);
    const meta = document.getElementById(`integration-meta-${item.provider}`);
    if (stateBadge) {
      stateBadge.className = `connector-state ${state} mono`;
      stateBadge.textContent = integrationStateLabel(state);
    }
    if (keyInput) keyInput.disabled = false;
    if (saveButton) saveButton.disabled = false;
    if (removeButton) removeButton.disabled = !item.configured;
    if (item.provider === 'openphish') {
      const enableCheckbox = document.getElementById('integration-enable-openphish');
      const termsCheckbox = document.getElementById('integration-terms-openphish');
      if (enableCheckbox) {
        enableCheckbox.disabled = false;
        enableCheckbox.checked = Boolean(item.enabled);
      }
      if (termsCheckbox) {
        termsCheckbox.disabled = false;
        termsCheckbox.checked = Boolean(item.terms_accepted);
      }
    }
    if (meta) {
      const configuredText = item.provider === 'openphish'
        ? 'COMMUNITY FEED / NO AUTH REQUIRED'
        : (item.configured ? 'KEY CONFIGURED' : 'NO KEY CONFIGURED');
      const detail = state === 'healthy'
        ? `Last success: ${formatDateTime(item.last_success)}`
        : (item.last_error || 'Awaiting connector validation');
      meta.textContent = `${configuredText} // ${detail}`;
    }
  });

  if (!silent) return data;
  return data;
}

async function saveIntegrationKey(provider) {
  const keyInput = document.getElementById(`integration-key-${provider}`);
  const saveButton = document.getElementById(`integration-save-${provider}`);
  const key = keyInput?.value.trim() || '';
  if (!integrationAdminToken) {
    setIntegrationMessage('Unlock administrative access first.', 'error');
    return;
  }
  if (!key) {
    setIntegrationMessage(`Paste the ${provider.toUpperCase()} Auth-Key first.`, 'error');
    keyInput?.focus();
    return;
  }

  if (saveButton) saveButton.disabled = true;
  setIntegrationMessage(`Saving and validating ${provider.toUpperCase()}...`);
  try {
    const response = await fetch(`/api/admin/integrations/${provider}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Token': integrationAdminToken
      },
      body: JSON.stringify({ api_key: key })
    });
    await parseIntegrationResponse(response);
    if (keyInput) keyInput.value = '';
    setIntegrationMessage(`${provider.toUpperCase()} key saved. Connector validation is running.`, 'ok');
    await loadIntegrationSettings(true);
    pollStatus();
  } catch (error) {
    setIntegrationMessage(error.message, 'error');
  } finally {
    if (saveButton) saveButton.disabled = false;
  }
}

async function saveOpenPhishSettings() {
  const enableCheckbox = document.getElementById('integration-enable-openphish');
  const termsCheckbox = document.getElementById('integration-terms-openphish');
  const saveButton = document.getElementById('integration-save-openphish');
  const enabled = Boolean(enableCheckbox?.checked);
  const termsAccepted = Boolean(termsCheckbox?.checked);

  if (!integrationAdminToken) {
    setIntegrationMessage('Unlock administrative access first.', 'error');
    return;
  }
  if (enabled && !termsAccepted) {
    setIntegrationMessage('Review and confirm the OpenPhish provider terms before enabling.', 'error');
    termsCheckbox?.focus();
    return;
  }

  if (saveButton) saveButton.disabled = true;
  setIntegrationMessage(`${enabled ? 'Enabling' : 'Disabling'} OPENPHISH...`);
  try {
    const response = await fetch('/api/admin/integrations/openphish/settings', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Token': integrationAdminToken
      },
      body: JSON.stringify({
        enabled,
        terms_accepted: termsAccepted
      })
    });
    await parseIntegrationResponse(response);
    setIntegrationMessage(
      enabled
        ? 'OPENPHISH enabled. Feed validation is running.'
        : 'OPENPHISH disabled. Existing indicators remain available for historical analysis.',
      'ok'
    );
    await loadIntegrationSettings(true);
    pollStatus();
  } catch (error) {
    setIntegrationMessage(error.message, 'error');
  } finally {
    if (saveButton) saveButton.disabled = false;
  }
}

async function removeIntegrationKey(provider) {
  if (!integrationAdminToken) return;
  if (!confirm(`Remove the ${provider.toUpperCase()} Auth-Key from this server?`)) return;
  setIntegrationMessage(`Removing ${provider.toUpperCase()} key...`);
  try {
    const response = await fetch(`/api/admin/integrations/${provider}`, {
      method: 'DELETE',
      headers: { 'X-Admin-Token': integrationAdminToken }
    });
    await parseIntegrationResponse(response);
    setIntegrationMessage(`${provider.toUpperCase()} key removed. Status returned to AUTH REQUIRED.`, 'ok');
    await loadIntegrationSettings(true);
    pollStatus();
  } catch (error) {
    setIntegrationMessage(error.message, 'error');
  }
}
