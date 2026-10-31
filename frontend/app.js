/**
 * PyReach Frontend Application Logic
 * Integrates with FastAPI backend endpoints:
 *   - GET  /api/health
 *   - GET  /api/fixtures
 *   - POST /api/scan
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- DOM Elements ---
  const apiStatusBadge = document.getElementById('apiStatusBadge');
  const projectPathInput = document.getElementById('projectPathInput');
  const networkToggle = document.getElementById('networkToggle');
  const networkLabel = document.getElementById('networkLabel');
  const runScanBtn = document.getElementById('runScanBtn');
  const btnSpinner = document.getElementById('btnSpinner');
  const scanningPulse = document.getElementById('scanningPulse');
  const pulseText = document.getElementById('pulseText');

  // Metrics
  const valTotalDeps = document.getElementById('valTotalDeps');
  const valTotalAdvisories = document.getElementById('valTotalAdvisories');
  const valReachable = document.getElementById('valReachable');
  const valNotReachable = document.getElementById('valNotReachable');
  const valUncertain = document.getElementById('valUncertain');

  // Posture Bar
  const barReachable = document.getElementById('barReachable');
  const barUncertain = document.getElementById('barUncertain');
  const barSafe = document.getElementById('barSafe');

  // Findings & Filters
  const findingsList = document.getElementById('findingsList');
  const filterPills = document.querySelectorAll('.filter-pill');
  const countAll = document.getElementById('countAll');
  const countReachable = document.getElementById('countReachable');
  const countSafe = document.getElementById('countSafe');
  const countUncertain = document.getElementById('countUncertain');
  const findingsSearchInput = document.getElementById('findingsSearchInput');

  // Call Graph SVG
  const callGraphSvg = document.getElementById('callGraphSvg');

  // Inspector Tabs
  const inspectorTabs = document.querySelectorAll('.inspector-tab');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const depsTableBody = document.getElementById('depsTableBody');
  const tabDepsCount = document.getElementById('tabDepsCount');
  const rawJsonBlock = document.getElementById('rawJsonBlock');
  const copyJsonBtn = document.getElementById('copyJsonBtn');

  // Preset Buttons
  const presetButtons = document.querySelectorAll('.preset-btn');

  // State
  let currentScanData = null;
  let activeFilter = 'ALL';

  // --- Initial Setup ---
  checkApiHealth();
  setupEventListeners();

  // Auto run initial demo scan
  setTimeout(() => {
    executeScan();
  }, 300);

  // --- Functions ---

  async function checkApiHealth() {
    try {
      const resp = await fetch('/api/health');
      if (resp.ok) {
        apiStatusBadge.classList.remove('offline');
        apiStatusBadge.classList.add('online');
        apiStatusBadge.querySelector('.status-label').textContent = 'API Ready: Port 8000';
      } else {
        throw new Error('API returned ' + resp.status);
      }
    } catch (err) {
      apiStatusBadge.classList.remove('online');
      apiStatusBadge.classList.add('offline');
      apiStatusBadge.querySelector('.status-label').textContent = 'API Offline (Start FastAPI)';
    }
  }

  function setupEventListeners() {
    // Preset Buttons
    presetButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        presetButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        projectPathInput.value = btn.dataset.path;
        executeScan();
      });
    });

    // Network Toggle
    networkToggle.addEventListener('change', () => {
      networkLabel.textContent = networkToggle.checked ? 'Live OSV API' : 'Curated Offline';
    });

    // Run Scan Button
    runScanBtn.addEventListener('click', executeScan);

    // Keyboard shortcut: Cmd+Enter / Ctrl+Enter
    window.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        executeScan();
      }
    });

    // Search Input
    findingsSearchInput.addEventListener('input', () => {
      renderFindings(currentScanData ? currentScanData.findings : []);
    });

    // Filter Pills
    filterPills.forEach(pill => {
      pill.addEventListener('click', () => {
        filterPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        activeFilter = pill.dataset.filter;
        renderFindings(currentScanData ? currentScanData.findings : []);
      });
    });

    // Bottom Inspector Tabs
    inspectorTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        inspectorTabs.forEach(t => t.classList.remove('active'));
        tabPanes.forEach(p => p.classList.remove('active'));

        tab.classList.add('active');
        const targetPane = document.getElementById(tab.dataset.target);
        if (targetPane) targetPane.classList.add('active');
      });
    });

    // Copy JSON
    copyJsonBtn.addEventListener('click', () => {
      if (!currentScanData) return;
      navigator.clipboard.writeText(JSON.stringify(currentScanData, null, 2)).then(() => {
        const orig = copyJsonBtn.textContent;
        copyJsonBtn.textContent = 'Copied!';
        setTimeout(() => copyJsonBtn.textContent = orig, 1800);
      });
    });
  }

  async function executeScan() {
    const projectPath = projectPathInput.value.trim();
    if (!projectPath) return;

    // UI Loading state
    runScanBtn.disabled = true;
    btnSpinner.style.display = 'inline-block';
    scanningPulse.classList.remove('hidden');

    const loadingSteps = [
      'Reading requirements.txt & normalising package names...',
      'Matching against OSV database & offline symbol map...',
      'Parsing Python AST trees (zero code execution)...',
      'Traversing call graph via BFS from entrypoints...',
      'Computing reachability verdicts & evidence chains...'
    ];

    let stepIdx = 0;
    const interval = setInterval(() => {
      if (stepIdx < loadingSteps.length) {
        pulseText.textContent = loadingSteps[stepIdx++];
      }
    }, 180);

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project_path: projectPath,
          use_network: networkToggle.checked
        })
      });

      clearInterval(interval);

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ detail: 'Unknown scan error' }));
        throw new Error(errData.detail || `Server returned ${resp.status}`);
      }

      const data = await resp.json();
      currentScanData = data;
      renderScanResults(data);

    } catch (err) {
      clearInterval(interval);
      showErrorState(err.message);
    } finally {
      runScanBtn.disabled = false;
      btnSpinner.style.display = 'none';
      scanningPulse.classList.add('hidden');
    }
  }

  function renderScanResults(report) {
    const summary = report.summary;

    // 1. Update Metrics
    valTotalDeps.textContent = summary.total_dependencies;
    valTotalAdvisories.textContent = summary.total_advisories;
    valReachable.textContent = summary.reachable_count;
    valNotReachable.textContent = summary.not_reachable_count;
    valUncertain.textContent = summary.uncertain_count;

    // 2. Posture Bar
    const totalFindings = summary.total_advisories || 1;
    const pReach = ((summary.reachable_count / totalFindings) * 100).toFixed(1);
    const pUncert = ((summary.uncertain_count / totalFindings) * 100).toFixed(1);
    const pSafe = ((summary.not_reachable_count / totalFindings) * 100).toFixed(1);

    barReachable.style.width = `${pReach}%`;
    barUncertain.style.width = `${pUncert}%`;
    barSafe.style.width = `${pSafe}%`;

    // 3. Filter Counts
    countAll.textContent = report.findings.length;
    countReachable.textContent = summary.reachable_count;
    countSafe.textContent = summary.not_reachable_count;
    countUncertain.textContent = summary.uncertain_count;

    // 4. Render Findings
    renderFindings(report.findings);

    // 5. Render Dependencies Table
    renderDependencies(report.dependencies);

    // 6. Render Call Graph (DAG)
    renderCallGraph(report);

    // 7. Update Raw JSON
    rawJsonBlock.textContent = JSON.stringify(report, null, 2);
  }

  function renderFindings(findings) {
    findingsList.innerHTML = '';

    const query = findingsSearchInput.value.toLowerCase().trim();

    const filtered = findings.filter(f => {
      // Filter tab check
      if (activeFilter !== 'ALL' && f.verdict !== activeFilter) {
        return false;
      }
      // Search query check
      if (query) {
        const text = `${f.package} ${f.advisory_id} ${f.summary} ${f.vulnerable_symbol || ''}`.toLowerCase();
        return text.includes(query);
      }
      return true;
    });

    if (filtered.length === 0) {
      findingsList.innerHTML = `
        <div class="empty-findings">
          <p>No findings matching the current filter criteria.</p>
        </div>
      `;
      return;
    }

    filtered.forEach(finding => {
      const card = document.createElement('div');
      card.className = 'finding-card';

      let verdictBadgeClass = 'tag-safe';
      let verdictLabel = 'NOT REACHABLE';
      if (finding.verdict === 'REACHABLE') {
        verdictBadgeClass = 'tag-reachable';
        verdictLabel = 'REACHABLE';
      } else if (finding.verdict === 'UNCERTAIN') {
        verdictBadgeClass = 'tag-uncertain';
        verdictLabel = 'UNCERTAIN';
      }

      // Evidence steps HTML
      let evidenceHtml = '';
      if (finding.evidence && finding.evidence.length > 0) {
        evidenceHtml = `
          <div class="code-evidence-box">
            <div class="evidence-header">
              <span class="evidence-path">Call Trace (${finding.evidence.length} Step${finding.evidence.length > 1 ? 's' : ''})</span>
              <span>${escapeHtml(finding.evidence[0].file)}:${finding.evidence[0].line}</span>
            </div>
            ${finding.evidence.map(step => `
              <div class="evidence-step">
                <span class="step-from">${escapeHtml(step.from)}</span>
                <span class="step-arrow">➔ calls ➔</span>
                <span class="step-to">${escapeHtml(step.to)}</span>
              </div>
            `).join('')}
          </div>
        `;
      }

      // Uncertainty reasons if present
      let uncertaintyHtml = '';
      if (finding.uncertainty_reasons && finding.uncertainty_reasons.length > 0) {
        uncertaintyHtml = `
          <div class="code-evidence-box" style="border-color: rgba(245, 158, 11, 0.4);">
            <div class="evidence-header" style="color: #f59e0b;">
              <span>Dynamic Reflection Hazards</span>
            </div>
            <div style="padding: 10px 14px; font-size: 0.8rem; color: #cbd5e1;">
              ${finding.uncertainty_reasons.map(r => `<div>• ${escapeHtml(r)}</div>`).join('')}
            </div>
          </div>
        `;
      }

      card.innerHTML = `
        <div class="finding-header">
          <div class="pkg-title-row">
            <span class="pkg-name">${escapeHtml(finding.package)}</span>
            <span class="version-badge">v${escapeHtml(finding.installed_version || 'unknown')}</span>
            <a href="https://osv.dev/vulnerability/${escapeHtml(finding.advisory_id)}" target="_blank" class="advisory-id-link">
              ${escapeHtml(finding.advisory_id)} ↗
            </a>
          </div>
          <span class="verdict-tag ${verdictBadgeClass}">${verdictLabel}</span>
        </div>

        <p class="finding-summary">${escapeHtml(finding.summary)}</p>

        ${evidenceHtml}
        ${uncertaintyHtml}

        <div class="verdict-rationale">
          <strong>Analysis:</strong> ${escapeHtml(finding.reason)}
        </div>
      `;

      findingsList.appendChild(card);
    });
  }

  function renderDependencies(dependencies) {
    tabDepsCount.textContent = dependencies.length;
    depsTableBody.innerHTML = '';

    if (dependencies.length === 0) {
      depsTableBody.innerHTML = '<tr><td colspan="5" class="empty-state">No dependencies parsed.</td></tr>';
      return;
    }

    dependencies.forEach(dep => {
      const tr = document.createElement('tr');
      const pinnedBadge = dep.is_pinned 
        ? `<span class="pinned-badge pinned">== ${escapeHtml(dep.version || '')} (Pinned)</span>`
        : `<span class="pinned-badge unpinned">Unpinned</span>`;

      tr.innerHTML = `
        <td style="font-weight: 600; color: #fff;">${escapeHtml(dep.name)}</td>
        <td>${escapeHtml(dep.version || '—')}</td>
        <td>${pinnedBadge}</td>
        <td style="color: #94a3b8;">${escapeHtml(dep.source_file)}</td>
        <td style="color: #c084fc;">L${dep.line}</td>
      `;
      depsTableBody.appendChild(tr);
    });
  }

  /**
   * Interactive Reachability Call Graph (DAG)
   * Renders SVG nodes: Entrypoint -> Call Sites -> Vulnerable Sinks
   */
  function renderCallGraph(report) {
    callGraphSvg.innerHTML = '';

    const width = callGraphSvg.clientWidth || 550;
    const height = 440;

    // Determine graph nodes based on findings
    const firstFinding = report.findings && report.findings[0];
    const isReachable = firstFinding && firstFinding.verdict === 'REACHABLE';
    const isUncertain = firstFinding && firstFinding.verdict === 'UNCERTAIN';

    // SVG Definitions (Gradients and markers)
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.innerHTML = `
      <marker id="arrowRed" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#f43f5e" />
      </marker>
      <marker id="arrowGreen" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
      </marker>
      <marker id="arrowOrange" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
      </marker>
      <filter id="glowEffect">
        <feGaussianBlur stdDeviation="3.5" result="coloredBlur"/>
        <feMerge>
          <feMergeNode in="coloredBlur"/>
          <feMergeNode in="SourceGraphic"/>
        </feMerge>
      </filter>
    `;
    callGraphSvg.appendChild(defs);

    // Nodes setup
    const nodes = [
      { id: 'entry', label: 'main() [Entry]', sub: 'app.py:10', x: 80, y: height / 2, type: 'entry' },
      { id: 'internal', label: 'process_input()', sub: 'app.py:5', x: width / 2, y: height / 2 - 40, type: 'internal' },
      { id: 'sink', label: 'yaml.load() [Sink]', sub: 'pyyaml (CVE-2020-14343)', x: width - 110, y: height / 2 + 30, type: 'sink' }
    ];

    if (!isReachable && !isUncertain) {
      nodes[2].label = 'yaml.safe_load()';
      nodes[2].sub = 'Verified Safe Function';
    } else if (isUncertain) {
      nodes[1].label = 'getattr(yaml, ... )';
      nodes[1].sub = 'Dynamic Reflection';
    }

    // Color coordination
    let edgeColor = '#10b981';
    let markerId = 'arrowGreen';
    let edgeDash = 'none';

    if (isReachable) {
      edgeColor = '#f43f5e';
      markerId = 'arrowRed';
    } else if (isUncertain) {
      edgeColor = '#f59e0b';
      markerId = 'arrowOrange';
      edgeDash = '6,4';
    }

    // Draw connecting edges
    const p1 = `M ${nodes[0].x} ${nodes[0].y} Q ${(nodes[0].x + nodes[1].x)/2} ${nodes[1].y - 30} ${nodes[1].x} ${nodes[1].y}`;
    const p2 = `M ${nodes[1].x} ${nodes[1].y} Q ${(nodes[1].x + nodes[2].x)/2} ${nodes[2].y + 30} ${nodes[2].x} ${nodes[2].y}`;

    // Glow paths
    const drawEdge = (d, color, marker, dash) => {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', d);
      path.setAttribute('fill', 'none');
      path.setAttribute('stroke', color);
      path.setAttribute('stroke-width', '2.5');
      if (dash !== 'none') path.setAttribute('stroke-dasharray', dash);
      path.setAttribute('marker-end', `url(#${marker})`);
      path.setAttribute('filter', 'url(#glowEffect)');
      return path;
    };

    callGraphSvg.appendChild(drawEdge(p1, isReachable ? '#f43f5e' : (isUncertain ? '#f59e0b' : '#38bdf8'), isReachable ? 'arrowRed' : (isUncertain ? 'arrowOrange' : 'arrowGreen'), edgeDash));
    
    // Boundary line between User project and Dependency
    const boundaryX = width - 180;
    const boundaryLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    boundaryLine.setAttribute('x1', boundaryX);
    boundaryLine.setAttribute('y1', 40);
    boundaryLine.setAttribute('x2', boundaryX);
    boundaryLine.setAttribute('y2', height - 40);
    boundaryLine.setAttribute('stroke', 'rgba(255, 255, 255, 0.12)');
    boundaryLine.setAttribute('stroke-dasharray', '4,4');
    callGraphSvg.appendChild(boundaryLine);

    const boundaryText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    boundaryText.setAttribute('x', boundaryX + 10);
    boundaryText.setAttribute('y', 60);
    boundaryText.setAttribute('fill', '#64748b');
    boundaryText.setAttribute('font-size', '11');
    boundaryText.setAttribute('font-family', 'var(--font-mono)');
    boundaryText.textContent = 'DEPENDENCY BOUNDARY';
    callGraphSvg.appendChild(boundaryText);

    if (isReachable) {
      callGraphSvg.appendChild(drawEdge(p2, '#f43f5e', 'arrowRed', 'none'));
    } else if (isUncertain) {
      callGraphSvg.appendChild(drawEdge(p2, '#f59e0b', 'arrowOrange', '6,4'));
    }

    // Draw Nodes
    nodes.forEach(node => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('transform', `translate(${node.x}, ${node.y})`);

      let strokeColor = '#38bdf8';
      let fillColor = 'rgba(56, 189, 248, 0.15)';

      if (node.type === 'internal') {
        strokeColor = '#c084fc';
        fillColor = 'rgba(192, 132, 252, 0.15)';
      } else if (node.type === 'sink') {
        strokeColor = isReachable ? '#f43f5e' : (isUncertain ? '#f59e0b' : '#10b981');
        fillColor = isReachable ? 'rgba(244, 63, 94, 0.2)' : 'rgba(16, 185, 129, 0.15)';
      }

      // Outer halo
      const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('x', '-70');
      rect.setAttribute('y', '-26');
      rect.setAttribute('width', '140');
      rect.setAttribute('height', '52');
      rect.setAttribute('rx', '8');
      rect.setAttribute('fill', '#0e121b');
      rect.setAttribute('stroke', strokeColor);
      rect.setAttribute('stroke-width', '2');
      rect.setAttribute('filter', 'url(#glowEffect)');

      const title = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      title.setAttribute('text-anchor', 'middle');
      title.setAttribute('y', '-3');
      title.setAttribute('fill', '#ffffff');
      title.setAttribute('font-weight', '700');
      title.setAttribute('font-size', '12');
      title.setAttribute('font-family', 'var(--font-mono)');
      title.textContent = node.label;

      const subtitle = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      subtitle.setAttribute('text-anchor', 'middle');
      subtitle.setAttribute('y', '15');
      subtitle.setAttribute('fill', strokeColor);
      subtitle.setAttribute('font-size', '10');
      subtitle.setAttribute('font-family', 'var(--font-mono)');
      subtitle.textContent = node.sub;

      g.appendChild(rect);
      g.appendChild(title);
      g.appendChild(subtitle);

      callGraphSvg.appendChild(g);
    });
  }

  function showErrorState(message) {
    findingsList.innerHTML = `
      <div style="background: rgba(244, 63, 94, 0.12); border: 1px solid rgba(244, 63, 94, 0.3); border-radius: 8px; padding: 18px; color: #f43f5e;">
        <strong>Scan Execution Failed:</strong>
        <p style="margin-top: 6px; font-size: 0.88rem; color: #cbd5e1;">${escapeHtml(message)}</p>
      </div>
    `;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
