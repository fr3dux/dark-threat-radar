// ThreatRadar - Cyber Threat Intelligence Platform Logic
let currentTab = 'panel-dashboard';
let searchDebounceTimeout = null;
let syncPollingInterval = null;
let headerResizeObserver = null;
let integrationAdminToken = '';
let integrationSettingsPoll = null;

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

// Initial bootstrap
document.addEventListener('DOMContentLoaded', () => {
  // Keep the navigation fixed immediately below the responsive app header.
  // ResizeObserver also covers header wrapping caused by viewport or font changes.
  updateStickyNavigationOffset();
  requestAnimationFrame(updateStickyNavigationOffset);
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
      closeIntegrationSettings();
      closeDrawer();
      const menu = document.getElementById('feeds-dropdown-menu');
      const button = document.getElementById('feed-summary-btn');
      if (menu) menu.style.display = 'none';
      if (button) button.setAttribute('aria-expanded', 'false');
    }
  });

  // Start periodic status check (every 15s)
  setInterval(pollStatus, 15000);
});

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
  const metricsStrip = document.querySelector('.metrics-strip');

  // The executive KPI strip belongs to the dashboard. Hiding it in explorer
  // views gives tables and filters the visual priority they need.
  if (metricsStrip) metricsStrip.style.display = panelId === 'panel-dashboard' ? 'grid' : 'none';

  if (panelId === 'panel-dashboard' || panelId === 'panel-leakcheck' || panelId === 'panel-watchlist') {
    toolbar.style.display = 'none';
  } else {
    toolbar.style.display = 'flex';
    cveFilters.style.display = (panelId === 'panel-cves') ? 'flex' : 'none';
    malwareFilters.style.display = (panelId === 'panel-malware') ? 'flex' : 'none';
    newsFilters.style.display = (panelId === 'panel-news') ? 'flex' : 'none';
    if (ransomwareFilters) ransomwareFilters.style.display = (panelId === 'panel-ransomware') ? 'flex' : 'none';
  }

  // Lazy load data on tab switch if not already populated
  if (panelId === 'panel-attackmap') {
    initAttackMap();
  } else if (panelId === 'panel-watchlist') {
    loadWatchlist();
  } else if (panelId === 'panel-ransomware') {
    loadRansomware();
  } else if (panelId === 'panel-cves') {
    loadCves();
  } else if (panelId === 'panel-malware') {
    loadMalware();
  } else if (panelId === 'panel-dshield') {
    loadDshield();
  } else if (panelId === 'panel-news') {
    loadNews();
  }
}

function goToTabWithFilter(panelId, filters) {
  // Reset search input
  const searchInput = document.getElementById('global-search');
  if (filters.query) {
    searchInput.value = filters.query;
  } else {
    searchInput.value = '';
  }

  // Apply filters
  if (panelId === 'panel-watchlist') {
    loadWatchlist();
  } else if (panelId === 'panel-ransomware') {
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
  } else if (panelId === 'panel-news') {
    if (filters.source) document.getElementById('filter-news-source').value = filters.source;
    else document.getElementById('filter-news-source').value = 'all';
    newsState.page = 1;
  }

  const targetBtn = document.querySelector(`.tab-btn[data-target="${panelId}"]`);
  switchTab(panelId, targetBtn);
}

function debounceSearch() {
  clearTimeout(searchDebounceTimeout);
  searchDebounceTimeout = setTimeout(() => {
    if (currentTab === 'panel-cves') {
      cveState.page = 1;
      loadCves();
    } else if (currentTab === 'panel-malware') {
      malwareState.page = 1;
      loadMalware();
    } else if (currentTab === 'panel-dshield') {
      loadDshield();
    } else if (currentTab === 'panel-news') {
      newsState.page = 1;
      loadNews();
    }
  }, 250);
}

// ==================== CVE EXPLORER ====================

async function loadCves() {
  const q = document.getElementById('global-search').value.trim();
  const source = document.getElementById('filter-cve-source').value;
  const ransomware = document.getElementById('filter-cve-ransomware').value;
  const severity = document.getElementById('filter-cve-severity').value;

  const tbody = document.getElementById('cve-tbody');
  tbody.innerHTML = '<tr><td colspan="7" class="loading-row">Querying CVE intelligence index...</td></tr>';

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
      tbody.innerHTML = '<tr><td colspan="7" class="empty-row">No CVE records match the current filter criteria.</td></tr>';
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

      const vendor = escapeHtml((item.vendor_project || '') + (item.product ? ` / ${item.product}` : '')) || 'n/a';
      const desc = escapeHtml(item.short_description || item.vulnerability_name || '');

      return `
        <tr onclick="openArtifact('cve', '${escapeHtml(item.cve_id)}')">
          <td class="mono font-bold" style="color: var(--accent-blue);">${escapeHtml(item.cve_id)}</td>
          <td>${srcBadge}</td>
          <td title="${vendor}">${vendor.length > 28 ? vendor.slice(0, 26) + '..' : vendor}</td>
          <td title="${desc}">${desc.length > 95 ? desc.slice(0, 92) + '...' : desc}</td>
          <td>${cvssBadge}</td>
          <td>${rwBadge}</td>
          <td class="mono text-muted">${escapeHtml(item.date_added || '')}</td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-row" style="color: var(--accent-red);">Error loading CVEs: ${err.message}</td></tr>`;
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

  // Also update header tab count
  const countBadge = document.getElementById('tab-count-cves');
  if (countBadge) countBadge.textContent = cveState.total;
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
  const q = document.getElementById('global-search').value.trim();
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
        <tr onclick="openArtifact('malware', '${escapeHtml(sha256)}')">
          <td class="mono text-muted">${escapeHtml(item.first_seen || '')}</td>
          <td class="mono" style="color: var(--accent-purple);" title="${escapeHtml(sha256)}">${sha256Short}</td>
          <td class="mono" title="${escapeHtml(item.file_name || '')}">${escapeHtml((item.file_name || 'unknown').slice(0, 26))}</td>
          <td><span class="badge badge-filetype">${escapeHtml((item.file_type || 'bin').toUpperCase())}</span></td>
          <td>${sig}</td>
          <td class="mono text-muted">${escapeHtml(item.reporter || 'abuse_ch')}</td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-row" style="color: var(--accent-red);">Error loading malware: ${err.message}</td></tr>`;
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

  const countBadge = document.getElementById('tab-count-malware');
  if (countBadge) countBadge.textContent = malwareState.total;
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
    <div class="port-item" onclick="openArtifact('port', '${Number(item.port)}')">
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

  try {
    const res = await fetch('/api/dshield');
    const data = await res.json();

    // Sources
    const sources = data.sources || [];
    document.getElementById('dshield-sources-count').textContent = `${sources.length} Top IPs`;
    if (sources.length === 0) {
      sourcesTbody.innerHTML = '<tr><td colspan="5" class="empty-row">No attacking source telemetry logged.</td></tr>';
    } else {
      sourcesTbody.innerHTML = sources.map(item => `
        <tr onclick="openArtifact('ip', '${escapeHtml(item.ip)}')">
          <td class="mono font-bold" style="color: var(--accent-cyan);">${escapeHtml(item.ip)}</td>
          <td class="mono crit font-bold">${item.attacks.toLocaleString()}</td>
          <td class="mono">${item.count.toLocaleString()}</td>
          <td title="${escapeHtml(item.as_name || '')}">${escapeHtml((item.as_name || 'N/A').slice(0, 26))}</td>
          <td class="mono text-muted">${escapeHtml(item.lastseen || item.updated_at || '')}</td>
        </tr>
      `).join('');
    }

    // Ports
    const ports = data.ports || [];
    renderMapTopTargetedPorts(ports);
    document.getElementById('dshield-ports-count').textContent = `${ports.length} Monitored`;
    if (ports.length === 0) {
      portsTbody.innerHTML = '<tr><td colspan="5" class="empty-row">No port telemetry recorded.</td></tr>';
    } else {
      portsTbody.innerHTML = ports.map(item => `
        <tr onclick="openArtifact('port', '${item.port}')">
          <td class="mono font-bold" style="color: var(--accent-orange);">${item.port}</td>
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
  const q = document.getElementById('global-search').value.trim();
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
      <div class="news-card" onclick="openArtifact('news', '${escapeHtml(item.id)}')">
        <div class="news-header">
          <div class="news-title font-bold">${escapeHtml(item.title)}</div>
          <span class="badge badge-nvd">${escapeHtml(item.source)}</span>
        </div>
        ${item.snippet ? `<div class="news-snippet">${escapeHtml(item.snippet)}</div>` : ''}
        <div class="news-meta">
          <span>PUBLISHED: ${escapeHtml(item.published_date || item.updated_at || 'Recent')}</span>
          <span class="text-muted">&bull;</span>
          <span class="mono" style="color: var(--accent-blue); text-decoration: underline;">INSPECT INTELLIGENCE &rarr;</span>
        </div>
      </div>
    `).join('');

  } catch (err) {
    container.innerHTML = `<div class="empty-row" style="color: var(--accent-red);">Error loading news: ${err.message}</div>`;
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

  const countBadge = document.getElementById('tab-count-news');
  if (countBadge) countBadge.textContent = newsState.total;
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
    const res = await fetch(`/api/artifact/${type}/${encodeURIComponent(identifier)}`);
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
            <span class="property-key">CVSS BASE SCORE</span><span class="property-value mono font-bold" style="color: var(--accent-red);">${d.cvss_score ? d.cvss_score + ' (' + (d.cvss_severity || '') + ')' : 'N/A'}</span>
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
            <span class="property-key">FIRST SEEN</span><span class="property-value mono text-muted">${escapeHtml(d.first_seen || '')}</span>
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
            <span class="property-key">ATTACKS COUNT</span><span class="property-value mono crit font-bold">${d.attacks}</span>
            <span class="property-key">PACKETS COUNT</span><span class="property-value mono">${d.count}</span>
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
            <span class="property-key">PORT NUMBER</span><span class="property-value mono font-bold" style="color: var(--accent-orange);">${d.port}</span>
            <span class="property-key">KNOWN SERVICE</span><span class="property-value mono font-bold">${escapeHtml(d.service || 'Unknown')}</span>
            <span class="property-key">ATTACK SOURCES</span><span class="property-value mono warn font-bold">${d.count}</span>
            <span class="property-key">PACKET RECORDS</span><span class="property-value mono">${d.records}</span>
            <span class="property-key">TARGET SYSTEMS</span><span class="property-value mono">${d.targets}</span>
          </div>
        </div>
      `;

      actionsHtml = `
        <a class="external-link" href="https://isc.sans.edu/port.html?port=${d.port}" target="_blank" rel="noopener">SANS DShield Port Report &rarr;</a>
        <a class="external-link" href="https://www.speedguide.net/port.php?port=${d.port}" target="_blank" rel="noopener">SpeedGuide Port DB &rarr;</a>
      `;

    } else if (type === 'ransomware') {
      const publicRecordUrl = safeHttpUrl(d.url);
      const claimUrl = safeHttpUrl(d.claim_url);
      const screenshotUrl = safeHttpUrl(d.screenshot);
      propsHtml = `
        <div class="drawer-section">
          <div class="drawer-section-title">RANSOMWARE EXTORTION DISCLOSURE</div>
          <div class="property-list">
            <span class="property-key">VICTIM</span><span class="property-value font-bold">${escapeHtml(d.victim_name || 'Unknown')}</span>
            <span class="property-key">THREAT ACTOR</span><span class="property-value"><span class="badge badge-ransomware mono font-bold">${escapeHtml((d.group_name || 'UNKNOWN').toUpperCase())}</span></span>
            <span class="property-key">COUNTRY</span><span class="property-value mono">${escapeHtml(d.country || 'N/A')}</span>
            <span class="property-key">DOMAIN / ACTIVITY</span><span class="property-value mono">${escapeHtml(d.domain || d.activity || 'N/A')}</span>
            <span class="property-key">DISCOVERED</span><span class="property-value mono text-muted">${escapeHtml(d.discovered || 'N/A')}</span>
            <span class="property-key">ATTACK DATE</span><span class="property-value mono text-muted">${escapeHtml(d.attackdate || 'N/A')}</span>
          </div>
        </div>
        ${d.description ? `
          <div class="drawer-section">
            <div class="drawer-section-title">DISCLOSURE DETAILS</div>
            <div style="font-size: 12px; line-height: 1.5; color: var(--text-secondary);">${escapeHtml(d.description)}</div>
          </div>
        ` : ''}
      `;

      actionsHtml = `
        ${publicRecordUrl ? `<a class="external-link" href="${escapeHtml(publicRecordUrl)}" target="_blank" rel="noopener">Ransomware.live Record &rarr;</a>` : ''}
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
            <span class="property-key">PUBLISHED</span><span class="property-value mono text-muted">${escapeHtml(d.published_date || 'N/A')}</span>
          </div>
        </div>
        ${d.snippet ? `
          <div class="drawer-section">
            <div class="drawer-section-title">SUMMARY / INTELLIGENCE SNIPPET</div>
            <div style="font-size: 12px; line-height: 1.5; color: var(--text-secondary);">${escapeHtml(d.snippet)}</div>
          </div>
        ` : ''}
      `;

      actionsHtml = `
        <a class="external-link" href="${escapeHtml(d.link)}" target="_blank" rel="noopener">Open Original Article &rarr;</a>
      `;
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
          <button class="btn" style="padding: 2px 6px; font-size: 10px;" onclick="copyRawJson()">COPY JSON</button>
        </div>
        <pre class="json-viewer" id="raw-json-pre">${escapeHtml(rawJsonStr)}</pre>
      </div>
    `;

  } catch (err) {
    content.innerHTML = `<div class="empty-row" style="color: var(--accent-red);">Failed retrieving artifact: ${err.message}</div>`;
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

  btn.disabled = true;
  spinner.style.display = 'inline-block';
  label.textContent = 'SYNCING...';

  try {
    const res = await fetch('/api/sync', { method: 'POST' });
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

async function pollStatus() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return false;
    const data = await res.json();

    // Update infocon badge
    if (data.stats && data.stats.infocon) {
      const status = (data.stats.infocon.status || 'unknown').toLowerCase();
      const badge = document.getElementById('infocon-badge');
      const val = document.getElementById('infocon-val');
      if (badge && val) {
        badge.className = `infocon-badge infocon-${status}`;
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

      const elRw = document.getElementById('stat-total-ransomware');
      if (elRw) elRw.textContent = s.total_ransomware;

      const elMal = document.getElementById('stat-total-malware');
      if (elMal) elMal.textContent = s.total_malware;

      const elIps = document.getElementById('stat-total-ips');
      if (elIps) elIps.textContent = s.total_dshield_ips;

      const elPorts = document.getElementById('stat-total-ports');
      if (elPorts) elPorts.textContent = s.total_dshield_ports;

      const elNews = document.getElementById('stat-total-news');
      if (elNews) elNews.textContent = s.total_news;

      // Mirror the dashboard's public DShield Top Targeted Ports widget.
      renderMapTopTargetedPorts(s.top_ports);

      // Update Nav tab badges
      const tcCves = document.getElementById('tab-count-cves');
      if (tcCves) tcCves.textContent = s.total_cves;

      const tcMal = document.getElementById('tab-count-malware');
      if (tcMal) tcMal.textContent = s.total_malware;

      const tcDsh = document.getElementById('tab-count-dshield');
      if (tcDsh) tcDsh.textContent = s.total_dshield_ips + s.total_dshield_ports;

      const tcNews = document.getElementById('tab-count-news');
      if (tcNews) tcNews.textContent = s.total_news;
    }

    // Update connector health without adding another dashboard widget.
    if (data.connectors) {
      const healthy = data.connectors.filter(c => c.state === 'healthy').length;
      const needsKeys = data.connectors.filter(c => c.state === 'auth_required').length;
      const disabled = data.connectors.filter(c => c.state === 'disabled').length;
      const failed = data.connectors.filter(c => ['failed', 'degraded', 'rate_limited'].includes(c.state)).length;
      const summary = document.getElementById('feed-summary-text');
      if (summary) summary.textContent = `${healthy}/${data.connectors.length} SOURCES HEALTHY`;
      const summaryButton = document.getElementById('feed-summary-btn');
      if (summaryButton) summaryButton.dataset.health = failed > 0 ? 'failed' : (healthy === data.connectors.length ? 'healthy' : 'attention');
      const meta = document.getElementById('connector-health-meta');
      if (meta) {
        meta.innerHTML = `
          <span class="health-count healthy">${healthy} healthy</span>
          ${needsKeys ? `<span class="health-count attention">${needsKeys} need keys</span>` : ''}
          ${failed ? `<span class="health-count failed">${failed} attention</span>` : ''}
          ${disabled ? `<span class="health-count muted">${disabled} disabled</span>` : ''}
        `;
      }
      const container = document.querySelector('.dropdown-feed-grid');
      if (container) {
        const groups = data.connectors.reduce((result, connector) => {
          (result[connector.category] ||= []).push(connector);
          return result;
        }, {});
        container.innerHTML = Object.entries(groups).map(([category, connectors]) => `
          <div class="connector-category mono">${escapeHtml(category.toUpperCase())}</div>
          ${connectors.map(c => `
            <div class="dropdown-feed-item" title="${escapeHtml(c.last_error || `Last success: ${c.last_success || 'never'}`)}">
              <span class="status-dot ${escapeHtml(c.state)}"></span>
              <span class="feed-name mono">${escapeHtml(c.source_name.replaceAll('_', ' ').toUpperCase())}</span>
              <span class="connector-state ${escapeHtml(c.state)} mono">${escapeHtml(c.state === 'failed' ? 'error' : c.state.replaceAll('_', ' '))}</span>
            </div>
          `).join('')}
        `).join('');
      }
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


// ==================== RANSOMWARE TRACKER (v1.2.0) ====================

async function loadRansomware() {
  const q = document.getElementById('global-search').value.trim();
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

    const countTab = document.getElementById('tab-count-ransomware');
    if (countTab) countTab.textContent = data.total;

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No ransomware victims found for current filters.</td></tr>';
      return;
    }

    tbody.innerHTML = data.items.map(item => {
      const isBR = (item.country && (item.country.toUpperCase() === 'BR' || item.country.toUpperCase() === 'BRAZIL'));
      const countryBadge = isBR 
        ? '<span class="badge badge-crit font-bold" style="background: rgba(248, 81, 73, 0.2);">🇧🇷 BRASIL</span>'
        : (item.country ? `<span class="badge badge-filetype mono">${escapeHtml(item.country)}</span>` : '<span class="mono text-muted">-</span>');

      return `
      <tr onclick="openArtifact('ransomware', '${item.id}')">
        <td class="mono text-muted">${escapeHtml((item.discovered || item.attackdate || '').substring(0, 16))}</td>
        <td><span class="badge badge-ransomware mono font-bold">${escapeHtml(item.group_name || 'UNKNOWN')}</span></td>
        <td class="font-bold">${escapeHtml(item.victim_name)}</td>
        <td>${countryBadge}</td>
        <td class="mono" style="color: var(--accent-blue);">${escapeHtml(item.domain || item.activity || '-')}</td>
        <td><button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); openArtifact('ransomware', '${item.id}')">DETALHES</button></td>
      </tr>
      `;
    }).join('');

  } catch (err) {
    console.error('Failed to load ransomware data:', err);
    tbody.innerHTML = `<tr><td colspan="6" class="error-row">Error loading ransomware feed: ${err.message}</td></tr>`;
  }
}

function updateRansomwarePagination() {
  const totalPages = Math.ceil(ransomwareState.total / ransomwareState.limit) || 1;
  const start = ransomwareState.total === 0 ? 0 : (ransomwareState.page - 1) * ransomwareState.limit + 1;
  const end = Math.min(ransomwareState.page * ransomwareState.limit, ransomwareState.total);

  const text = `Showing ${start} - ${end} of ${ransomwareState.total} victims`;
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
        <span class="mono font-bold" style="color: var(--accent-red);">${atk.src_country}</span>
        <span class="text-muted">&rarr;</span>
        <span class="mono font-bold" style="color: var(--accent-green);">${atk.dst_country}</span>
      </div>
      <span class="badge ${atk.severity === 'CRITICAL' ? 'badge-crit' : 'badge-warn'} mono font-bold">${atk.port} / ${atk.service}</span>
    </div>
    <div class="stream-meta">
      <span class="mono text-muted">${atk.src_ip}</span>
      <span class="mono text-muted">${atk.time}</span>
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
  if (!input || !btn || !resultsBox) return;

  const email = input.value.trim();
  if (!email || !email.includes('@')) {
    alert('Please enter a valid email address.');
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
      body: JSON.stringify({ email })
    });
    const data = await res.json();

    if (data.exposed) {
      let breachPills = '';
      if (data.breaches && data.breaches.length > 0) {
        breachPills = data.breaches.map(b => `<span class="breach-pill">⚠️ ${b}</span>`).join('');
      }

      resultsBox.innerHTML = `
        <div class="leak-status-banner compromised">
          <div class="leak-status-title">⚠️ EMAIL COMPROMISED IN DATA BREACHES</div>
          <div class="leak-status-desc">Email <strong>${data.email}</strong> was identified in <strong>${data.count} public data breach dump(s)</strong> on the Dark Web.</div>
        </div>
        <div style="font-size: 11px; font-weight: 700; color: var(--text-secondary); margin-bottom: 6px;">COMPROMISED SERVICES & BREACHES:</div>
        <div class="breaches-grid">${breachPills}</div>
      `;
    } else {
      resultsBox.innerHTML = `
        <div class="leak-status-banner clean">
          <div class="leak-status-title">✅ NO BREACHES DETECTED</div>
          <div class="leak-status-desc">Email <strong>${data.email}</strong> was not found in public databases monitored by XposedOrNot.</div>
        </div>
      `;
    }
  } catch (err) {
    resultsBox.innerHTML = `<div class="leak-status-banner compromised"><div class="leak-status-title">❌ QUERY ERROR</div><div class="leak-status-desc">${err.message || 'Failed to communicate with server'}</div></div>`;
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
    const res = await fetch('/api/leak-check/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await res.json();

    if (data.exposed) {
      resultsBox.innerHTML = `
        <div class="leak-status-banner compromised">
          <div class="leak-status-title">☠️ PASSWORD COMPROMISED IN LEAKS!</div>
          <div class="leak-status-desc">
            This password appeared exactly <strong>${data.count.toLocaleString('en-US')} times</strong> in global data breach dumps (Have I Been Pwned).
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
    resultsBox.innerHTML = `<div class="leak-status-banner compromised"><div class="leak-status-title">❌ QUERY ERROR</div><div class="leak-status-desc">${err.message || 'Failed to communicate with server'}</div></div>`;
  } finally {
    btn.disabled = false;
    btn.innerText = 'VERIFY';
  }
}


// ==================== WATCHLIST & REMEDIATION (v1.7.7) ====================

async function loadWatchlist() {
  const container = document.getElementById('wl-items-container');
  const tbody = document.getElementById('wl-alerts-tbody');
  const badgeCount = document.getElementById('wl-badge-count');
  const alertsBadge = document.getElementById('wl-alerts-badge');
  const tabCount = document.getElementById('tab-count-watchlist');
  if (!container || !tbody) return;

  try {
    const res = await fetch('/api/watchlist');
    const data = await res.json();

    if (badgeCount) badgeCount.textContent = (data.total_items || 0) + ' TARGETS';
    if (alertsBadge) alertsBadge.textContent = (data.total_alerts || 0) + ' MATCHES';
    if (tabCount) tabCount.textContent = data.total_alerts || 0;

    // Render Monitored Targets
    if (!data.watchlist || data.watchlist.length === 0) {
      container.innerHTML = '<div class="stream-item-placeholder">No monitored targets registered yet. Add vendors or products above.</div>';
    } else {
      container.innerHTML = data.watchlist.map(function(item) {
        return '<div class="wl-item-card">' +
          '<div class="wl-item-info">' +
            '<div class="wl-item-title">' +
              '<span class="badge badge-filetype mono" style="font-size: 9.5px; padding: 1px 4px;">' + item.item_type.toUpperCase() + '</span> ' +
              item.value +
            '</div>' +
            '<div class="wl-item-meta mono">' + (item.notes || 'No notes') + ' • Added: ' + (item.created_at || '').substring(0, 10) + '</div>' +
          '</div>' +
          '<button class="wl-delete-btn mono font-bold" onclick="deleteWatchlistItem(\'' + item.id + '\')" title="Delete Target">✕</button>' +
        '</div>';
      }).join('');
    }

    // Render Matched Alerts & Official Remediation
    if (!data.active_alerts || data.active_alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="loading-row">No active KEV or Critical vulnerabilities matching your watchlist.</td></tr>';
    } else {
      tbody.innerHTML = data.active_alerts.map(function(cve) {
        const cvssBadge = (cve.cvss_score >= 9.0)
          ? '<span class="badge badge-crit font-bold">' + cve.cvss_score + ' CRITICAL</span>'
          : '<span class="badge badge-warn font-bold">' + (cve.cvss_score || 'N/A') + ' HIGH</span>';
        const kevBadge = (cve.source === 'cisa_kev') ? '<span class="badge badge-kev font-bold" style="margin-left: 4px;">KEV</span>' : '';
        const notesHtml = cve.notes ? '<br><span class="text-muted">' + cve.notes + '</span>' : '';
        const dueBadge = cve.due_date ? '<span class="badge badge-warn">' + cve.due_date + '</span>' : '<span class="text-muted">N/A</span>';

        return '<tr class="clickable-row">' +
          '<td>' +
            '<div class="mono font-bold" style="color: var(--accent-blue);">' + cve.cve_id + '</div>' +
            '<div class="mono text-muted" style="font-size: 11px;">' + (cve.vendor_project || '') + ' ' + (cve.product || '') + '</div>' +
          '</td>' +
          '<td>' + cvssBadge + ' ' + kevBadge + '</td>' +
          '<td>' +
            '<div class="font-bold" style="color: var(--text-primary); font-size: 12px;">' + (cve.vulnerability_name || 'Vulnerability Impact') + '</div>' +
            '<div class="remediation-directive-box mono">' +
              '<strong>ACTION REQUIRED:</strong> ' + cve.required_action + notesHtml +
            '</div>' +
          '</td>' +
          '<td class="mono">' + dueBadge + '</td>' +
          '<td>' +
            '<button class="btn btn-sm" onclick="openArtifact(\'' + 'cve' + '\', \'' + cve.cve_id + '\')">INSPECT</button>' +
          '</td>' +
        '</tr>';
      }).join('');
    }
  } catch (err) {
    console.error('Error loading watchlist:', err);
  }
}

async function addWatchlistItem() {
  const typeSelect = document.getElementById('wl-type-select');
  const valInput = document.getElementById('wl-val-input');
  const notesInput = document.getElementById('wl-notes-input');
  if (!typeSelect || !valInput) return;

  const value = valInput.value.trim();
  const item_type = typeSelect.value;
  const notes = notesInput ? notesInput.value.trim() : '';

  if (!value) {
    alert('Please enter a vendor, product, or CVE to monitor.');
    return;
  }

  try {
    const res = await fetch('/api/watchlist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ item_type: item_type, value: value, notes: notes })
    });
    if (res.ok) {
      valInput.value = '';
      if (notesInput) notesInput.value = '';
      loadWatchlist();
    } else {
      const err = await res.json();
      alert('Failed to add target: ' + (err.detail || 'Unknown error'));
    }
  } catch (e) {
    alert('Error adding watchlist target: ' + e);
  }
}

async function deleteWatchlistItem(itemId) {
  if (!confirm('Remove this target from your watchlist?')) return;
  try {
    const res = await fetch('/api/watchlist/' + itemId, { method: 'DELETE' });
    if (res.ok) {
      loadWatchlist();
    }
  } catch (e) {
    alert('Error removing target: ' + e);
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

function openIntegrationSettings() {
  const overlay = document.getElementById('integration-modal-overlay');
  const menu = document.getElementById('feeds-dropdown-menu');
  const summaryButton = document.getElementById('feed-summary-btn');
  if (menu) menu.style.display = 'none';
  if (summaryButton) summaryButton.setAttribute('aria-expanded', 'false');
  if (!overlay) return;
  overlay.classList.add('open');
  overlay.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  setTimeout(() => document.getElementById('integration-admin-token')?.focus(), 0);
}

function closeIntegrationSettings() {
  const overlay = document.getElementById('integration-modal-overlay');
  if (!overlay || !overlay.classList.contains('open')) return;
  overlay.classList.remove('open');
  overlay.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
  integrationAdminToken = '';
  if (integrationSettingsPoll) {
    clearInterval(integrationSettingsPoll);
    integrationSettingsPoll = null;
  }
  ['threatfox', 'urlhaus'].forEach(provider => {
    const keyInput = document.getElementById(`integration-key-${provider}`);
    const saveButton = document.getElementById(`integration-save-${provider}`);
    const removeButton = document.getElementById(`integration-remove-${provider}`);
    if (keyInput) { keyInput.value = ''; keyInput.disabled = true; }
    if (saveButton) saveButton.disabled = true;
    if (removeButton) removeButton.disabled = true;
  });
  const tokenInput = document.getElementById('integration-admin-token');
  if (tokenInput) tokenInput.value = '';
  setIntegrationMessage('Administrative authentication is required.');
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
    setIntegrationMessage('Enter the administrative access code.', 'error');
    return;
  }
  integrationAdminToken = token;
  setIntegrationMessage('Verifying administrative access...');
  try {
    await loadIntegrationSettings();
    if (tokenInput) tokenInput.value = '';
    setIntegrationMessage('Administrative access verified. Keys remain server-side only.', 'ok');
    if (integrationSettingsPoll) clearInterval(integrationSettingsPoll);
    integrationSettingsPoll = setInterval(() => loadIntegrationSettings(true), 5000);
  } catch (error) {
    integrationAdminToken = '';
    setIntegrationMessage(error.message, 'error');
  }
}

async function loadIntegrationSettings(silent = false) {
  if (!integrationAdminToken) throw new Error('Administrative authentication is required.');
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
    if (meta) {
      const configuredText = item.configured ? 'KEY CONFIGURED' : 'NO KEY CONFIGURED';
      const detail = state === 'healthy'
        ? `Last success: ${item.last_success || 'just now'}`
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

function toggleFeedDropdown() {
  const menu = document.getElementById('feeds-dropdown-menu');
  const button = document.getElementById('feed-summary-btn');
  if (!menu) return;
  const willOpen = menu.style.display === 'none';
  menu.style.display = willOpen ? 'block' : 'none';
  if (button) button.setAttribute('aria-expanded', String(willOpen));
}

document.addEventListener('click', (e) => {
  const wrapper = document.querySelector('.feeds-dropdown-wrapper');
  const menu = document.getElementById('feeds-dropdown-menu');
  if (wrapper && menu && !wrapper.contains(e.target)) {
    menu.style.display = 'none';
    const button = document.getElementById('feed-summary-btn');
    if (button) button.setAttribute('aria-expanded', 'false');
  }
});
