// ThreatRadar - Cyber Threat Intelligence Platform Logic
let currentTab = 'panel-dashboard';
let searchDebounceTimeout = null;
let syncPollingInterval = null;

// Pagination states
const cveState = { page: 1, limit: 50, total: 0 };
const ransomwareState = { page: 1, limit: 50, total: 0 };
const malwareState = { page: 1, limit: 50, total: 0 };
const newsState = { page: 1, limit: 20, total: 0 };

// Initial bootstrap
document.addEventListener('DOMContentLoaded', () => {
  // Initial background load of telemetry
  loadDshield();

  // Close drawer on ESC
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDrawer();
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

  if (panelId === 'panel-dashboard' || panelId === 'panel-attackmap') {
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
  if (panelId === 'panel-attackmap') {
    initAttackMap();
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

    const rawJsonStr = d.raw_json ? JSON.stringify(d.parsed_raw || JSON.parse(d.raw_json), null, 2) : JSON.stringify(d, null, 2);

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

    // Update Feed Chips
    if (data.feeds) {
      const container = document.getElementById('feeds-status-container');
      if (container) {
        container.innerHTML = data.feeds.map(f => `
          <div class="feed-chip" title="${escapeHtml(f.message || '')}">
            <span class="status-dot ${f.status}"></span>
            <span>${escapeHtml(f.feed_name.toUpperCase())}</span>
            <span class="mono" style="color: var(--text-muted);">(${f.items_count})</span>
          </div>
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
      tbody.innerHTML = '<tr><td colspan="6" class="empty-row">Nenhuma vítima de ransomware encontrada para os filtros atuais.</td></tr>';
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
    tbody.innerHTML = `<tr><td colspan="6" class="error-row">Erro ao carregar feed de ransomware: ${err.message}</td></tr>`;
  }
}

function updateRansomwarePagination() {
  const totalPages = Math.ceil(ransomwareState.total / ransomwareState.limit) || 1;
  const start = ransomwareState.total === 0 ? 0 : (ransomwareState.page - 1) * ransomwareState.limit + 1;
  const end = Math.min(ransomwareState.page * ransomwareState.limit, ransomwareState.total);

  const text = `Exibindo ${start} - ${end} de ${ransomwareState.total} vítimas`;
  const infoTop = document.getElementById('ransomware-page-info');
  const infoBottom = document.getElementById('ransomware-page-info-bottom');
  if (infoTop) infoTop.textContent = text;
  if (infoBottom) infoBottom.textContent = text;

  const pageNum = document.getElementById('ransomware-page-num');
  if (pageNum) pageNum.textContent = `PÁGINA ${ransomwareState.page} / ${totalPages}`;

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
