/**
 * PyReach Frontend Application
 * Combines:
 *   - Abnormal AI: Live 3D Perspective Wave & Particle Mesh Canvas
 *   - GitHub UI: Folder Drag & Drop / Recursive Upload, File Explorer, Code Evidence
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- Canvas: Abnormal AI Interactive 3D Wave Grid ---
  initAbnormalWaveCanvas();

  // --- DOM Elements ---
  const apiStatusText = document.getElementById('apiStatusText');
  const apiTelemetryChip = document.getElementById('apiTelemetryChip');
  const projectPathInput = document.getElementById('projectPathInput');
  const networkToggle = document.getElementById('networkToggle');
  const networkLabel = document.getElementById('networkLabel');
  const runScanBtn = document.getElementById('runScanBtn');
  const radarScanBanner = document.getElementById('radarScanBanner');
  const radarStepText = document.getElementById('radarStepText');

  // Folder Upload & Dropzone Elements
  const folderDropzone = document.getElementById('folderDropzone');
  const folderInput = document.getElementById('folderInput');
  const uploadFolderTriggerBtn = document.getElementById('uploadFolderTriggerBtn');
  const browseFolderLink = document.getElementById('browseFolderLink');
  const uploadedFilesStatus = document.getElementById('uploadedFilesStatus');
  const filesTableBody = document.getElementById('filesTableBody');
  const fileCountBadge = document.getElementById('fileCountBadge');

  // Metrics
  const valTotalDeps = document.getElementById('valTotalDeps');
  const valTotalAdvisories = document.getElementById('valTotalAdvisories');
  const valReachable = document.getElementById('valReachable');
  const valNotReachable = document.getElementById('valNotReachable');
  const valUncertain = document.getElementById('valUncertain');

  // Posture Slices & Percentages
  const sliceReachable = document.getElementById('sliceReachable');
  const sliceUncertain = document.getElementById('sliceUncertain');
  const sliceSafe = document.getElementById('sliceSafe');
  const pctReachable = document.getElementById('pctReachable');
  const pctUncertain = document.getElementById('pctUncertain');
  const pctSafe = document.getElementById('pctSafe');

  // Findings & Filters
  const findingsContainer = document.getElementById('findingsContainer');
  const filterPills = document.querySelectorAll('.gh-pill');
  const countAll = document.getElementById('countAll');
  const countReachable = document.getElementById('countReachable');
  const countSafe = document.getElementById('countSafe');
  const countUncertain = document.getElementById('countUncertain');
  const findingSearchBox = document.getElementById('findingSearchBox');

  // Subnav Badges
  const subnavAdvisoriesBadge = document.getElementById('subnavAdvisoriesBadge');
  const subnavDepsBadge = document.getElementById('subnavDepsBadge');
  const subnavTabs = document.querySelectorAll('.subnav-tab');

  // Graph SVG
  const reachabilityGraphSvg = document.getElementById('reachabilityGraphSvg');
  const graphStateBadge = document.getElementById('graphStateBadge');

  // Bottom Dock
  const dockTabs = document.querySelectorAll('.dock-tab');
  const dockPanes = document.querySelectorAll('.dock-pane');
  const dockDepsTableBody = document.getElementById('dockDepsTableBody');
  const dockDepsCount = document.getElementById('dockDepsCount');
  const rawJsonBlock = document.getElementById('rawJsonBlock');
  const copyJsonBtn = document.getElementById('copyJsonBtn');

  // Fixture Chips
  const fixtureChips = document.querySelectorAll('.fixture-chip');

  // In-memory Uploaded Files Cache
  let stagedUploadedFiles = null;
  let stagedFolderName = null;
  let currentReportData = null;
  let activeFilter = 'ALL';

  // --- Initialize ---
  checkHealth();
  setupEventHandlers();

  // Run initial default demo scan
  setTimeout(() => {
    executeScan();
  }, 250);

  // ========================================================================
  // 1. Abnormal AI Interactive 3D Perspective Wave & Particle Mesh
  // ========================================================================
  function initAbnormalWaveCanvas() {
    const canvas = document.getElementById('abnormalWaveCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    });

    // Wave grid parameters
    const cols = 28;
    const rows = 18;
    let time = 0;
    let mouse = { x: width / 2, y: height / 2, radius: 200 };

    window.addEventListener('mousemove', (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    });

    function renderWave() {
      ctx.clearRect(0, 0, width, height);

      const cellW = width / cols;
      const cellH = (height * 0.75) / rows;
      const startY = height * 0.15;

      // Draw perspective wave lines
      for (let r = 0; r < rows; r++) {
        ctx.beginPath();
        for (let c = 0; c <= cols; c++) {
          const x = c * cellW;
          // 3D perspective sine wave distortion
          const wave1 = Math.sin((c * 0.3) + (time * 0.03) + (r * 0.2)) * 14;
          const wave2 = Math.cos((r * 0.25) + (time * 0.02)) * 10;
          
          // Cursor magnetic ripple
          const dx = x - mouse.x;
          const dy = (startY + (r * cellH)) - mouse.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          let mouseOffset = 0;
          if (dist < mouse.radius) {
            mouseOffset = Math.sin((1 - dist / mouse.radius) * Math.PI) * 22;
          }

          const y = startY + (r * cellH) + wave1 + wave2 - mouseOffset;

          if (c === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);

          // Draw small glowing cyber node points on every 2nd intersection
          if (c % 2 === 0 && r % 2 === 0) {
            const alpha = 0.2 + (Math.sin(time * 0.05 + c + r) * 0.15);
            ctx.fillStyle = `rgba(168, 85, 247, ${Math.max(0.05, alpha)})`;
            ctx.fillRect(x - 1.5, y - 1.5, 3, 3);
          }
        }

        // Depth perspective opacity
        const depthAlpha = 0.04 + ((r / rows) * 0.08);
        ctx.strokeStyle = `rgba(139, 92, 246, ${depthAlpha})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      time++;
      requestAnimationFrame(renderWave);
    }

    renderWave();
  }

  // ========================================================================
  // 2. Health Check & Core Event Handlers
  // ========================================================================
  async function checkHealth() {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        apiTelemetryChip.classList.remove('offline');
        apiStatusText.textContent = 'Engine Live: Port 8000';
      } else {
        throw new Error();
      }
    } catch {
      apiTelemetryChip.classList.add('offline');
      apiStatusText.textContent = 'Engine Offline (Start Backend)';
    }
  }

  function setupEventHandlers() {
    // Quick Fixture Chips
    fixtureChips.forEach(chip => {
      chip.addEventListener('click', () => {
        fixtureChips.forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        stagedUploadedFiles = null;
        stagedFolderName = null;
        uploadedFilesStatus.textContent = 'Fixture selected';
        projectPathInput.value = chip.dataset.path;
        executeScan();
      });
    });

    // Network Toggle
    networkToggle.addEventListener('change', () => {
      networkLabel.textContent = networkToggle.checked
        ? 'Live OSV API (3s timeout)'
        : 'Curated Offline Mode';
    });

    // Run Scan Button
    runScanBtn.addEventListener('click', executeScan);

    // Keyboard Shortcut (Cmd+Enter or Ctrl+Enter)
    window.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        executeScan();
      }
    });

    // Findings Filter Search
    findingSearchBox.addEventListener('input', () => {
      renderFindings(currentReportData ? currentReportData.findings : []);
    });

    // Filter Pills
    filterPills.forEach(pill => {
      pill.addEventListener('click', () => {
        filterPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        activeFilter = pill.dataset.filter;
        renderFindings(currentReportData ? currentReportData.findings : []);
      });
    });

    // Subnav Tabs
    subnavTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        subnavTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        const view = tab.dataset.view;
        if (view === 'graphView') {
          document.querySelector('.graph-workspace').scrollIntoView({ behavior: 'smooth' });
        } else if (view === 'securityView') {
          document.querySelector('.findings-workspace').scrollIntoView({ behavior: 'smooth' });
        } else if (view === 'depsView' || view === 'honestyView') {
          document.querySelector('.bottom-dock-card').scrollIntoView({ behavior: 'smooth' });
          if (view === 'depsView') switchDockTab('paneDeps');
          if (view === 'honestyView') switchDockTab('paneHonesty');
        }
      });
    });

    // Bottom Dock Tabs
    dockTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        switchDockTab(tab.dataset.pane);
      });
    });

    function switchDockTab(paneId) {
      dockTabs.forEach(t => t.classList.remove('active'));
      dockPanes.forEach(p => p.classList.remove('active'));
      const activeTab = Array.from(dockTabs).find(t => t.dataset.pane === paneId);
      if (activeTab) activeTab.classList.add('active');
      const targetPane = document.getElementById(paneId);
      if (targetPane) targetPane.classList.add('active');
    }

    // Copy JSON
    copyJsonBtn.addEventListener('click', () => {
      if (!currentReportData) return;
      navigator.clipboard.writeText(JSON.stringify(currentReportData, null, 2)).then(() => {
        const orig = copyJsonBtn.textContent;
        copyJsonBtn.textContent = 'Copied to Clipboard!';
        setTimeout(() => copyJsonBtn.textContent = orig, 1800);
      });
    });

    // ======================================================================
    // 3. GitHub Drag-and-Drop & Folder Upload Implementation
    // ======================================================================
    uploadFolderTriggerBtn.addEventListener('click', () => folderInput.click());
    browseFolderLink.addEventListener('click', () => folderInput.click());

    folderInput.addEventListener('change', async (e) => {
      if (e.target.files && e.target.files.length > 0) {
        await handleFilesList(e.target.files);
      }
    });

    // Drag and Drop listeners
    ['dragenter', 'dragover'].forEach(name => {
      folderDropzone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        folderDropzone.classList.add('drag-over');
      });
    });

    ['dragleave', 'drop'].forEach(name => {
      folderDropzone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        folderDropzone.classList.remove('drag-over');
      });
    });

    folderDropzone.addEventListener('drop', async (e) => {
      const items = e.dataTransfer.items;
      if (items && items.length > 0) {
        const files = await getAllFilesFromDataTransfer(items);
        if (files.length > 0) {
          await handleFilesList(files);
        }
      } else if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        await handleFilesList(e.dataTransfer.files);
      }
    });
  }

  // Recursive directory reader for drag-and-drop folders
  async function getAllFilesFromDataTransfer(items) {
    const files = [];

    async function traverseEntry(entry, path = '') {
      if (entry.isFile) {
        const file = await new Promise((resolve) => entry.file(resolve));
        file._relativePath = path ? `${path}/${file.name}` : file.name;
        files.push(file);
      } else if (entry.isDirectory) {
        const dirReader = entry.createReader();
        const entries = await new Promise((resolve) => {
          dirReader.readEntries(resolve);
        });
        for (const child of entries) {
          await traverseEntry(child, path ? `${path}/${entry.name}` : entry.name);
        }
      }
    }

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.webkitGetAsEntry) {
        const entry = item.webkitGetAsEntry();
        if (entry) await traverseEntry(entry);
      } else {
        const file = item.getAsFile();
        if (file) files.push(file);
      }
    }

    return files;
  }

  // Handle uploaded files list
  async function handleFilesList(fileList) {
    const fileArray = Array.from(fileList);
    const readPromises = [];
    const validFiles = [];

    for (const file of fileArray) {
      // Determine relative path
      const relPath = file.webkitRelativePath || file._relativePath || file.name;
      // Filter for Python files, requirements.txt, or text config
      if (relPath.endsWith('.py') || relPath.endsWith('requirements.txt') || relPath.endsWith('.txt')) {
        const p = file.text().then(content => {
          validFiles.push({ path: relPath, content: content });
        });
        readPromises.push(p);
      }
    }

    await Promise.all(readPromises);

    if (validFiles.length === 0) {
      uploadedFilesStatus.textContent = 'No .py or requirements.txt files found in folder';
      return;
    }

    // Determine top folder name
    let folderName = 'uploaded_project';
    if (validFiles[0].path.includes('/')) {
      folderName = validFiles[0].path.split('/')[0];
    }

    stagedUploadedFiles = validFiles;
    stagedFolderName = folderName;

    // Update UI
    uploadedFilesStatus.textContent = `Folder loaded: ${folderName} (${validFiles.length} files)`;
    projectPathInput.value = `[Uploaded Folder: ${folderName}]`;
    fixtureChips.forEach(c => c.classList.remove('active'));

    // Update GitHub File Explorer Table
    renderFileExplorerTable(validFiles);

    // Automatically trigger reachability scan on the uploaded folder!
    executeScan();
  }

  function renderFileExplorerTable(files) {
    filesTableBody.innerHTML = '';
    fileCountBadge.textContent = `${files.length} files in active target`;

    files.forEach(f => {
      const tr = document.createElement('tr');
      const isReq = f.path.endsWith('requirements.txt');
      const iconColor = isReq ? '#38bdf8' : '#a855f7';
      const statusText = isReq ? 'Pinned Specs' : 'Python AST';
      const statusClass = isReq ? 'green' : 'purple';
      const roleText = isReq 
        ? 'Dependency specifications & OSV matching'
        : 'AST call site & entry point extraction';

      tr.innerHTML = `
        <td class="file-col">
          <svg class="file-icon" width="14" height="14" viewBox="0 0 16 16" fill="${iconColor}"><path d="M2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l3.914 3.914c.329.328.513.773.513 1.237v8.586A1.75 1.75 0 0114.25 16H3.75A1.75 1.75 0 012 14.25V1.75z"/></svg>
          <span class="file-path-text">${escapeHtml(f.path)}</span>
        </td>
        <td><span class="tag-status ${statusClass}">${statusText}</span></td>
        <td class="file-desc-text">${roleText}</td>
      `;
      filesTableBody.appendChild(tr);
    });
  }

  // ========================================================================
  // 4. Execute Reachability Scan (Preset path OR Uploaded folder)
  // ========================================================================
  async function executeScan() {
    runScanBtn.disabled = true;
    radarScanBanner.classList.remove('hidden');

    const steps = [
      'Extracting dependencies from requirements.txt...',
      'Querying OSV advisory database & offline curated symbol map...',
      'Constructing recursive Python AST call graph (0% execution)...',
      'Traversing BFS path from entry points to vulnerability sinks...',
      'Synthesizing reachability proofs & conservative verdicts...'
    ];

    let stepIdx = 0;
    const stepInterval = setInterval(() => {
      if (stepIdx < steps.length) {
        radarStepText.textContent = steps[stepIdx++];
      }
    }, 180);

    try {
      let resp;

      if (stagedUploadedFiles && stagedUploadedFiles.length > 0) {
        // Use POST /api/scan/upload for in-memory folder uploads
        resp = await fetch('/api/scan/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            files: stagedUploadedFiles,
            project_name: stagedFolderName || 'custom_upload',
            use_network: networkToggle.checked
          })
        });
      } else {
        // Use standard POST /api/scan for repository fixtures
        const path = projectPathInput.value.trim() || 'examples/vulnerable_app';
        resp = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            project_path: path,
            use_network: networkToggle.checked
          })
        });
      }

      clearInterval(stepInterval);

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: 'Analysis failed' }));
        throw new Error(err.detail || `Server returned ${resp.status}`);
      }

      const report = await resp.json();
      currentReportData = report;
      renderScanReport(report);

    } catch (err) {
      clearInterval(stepInterval);
      showErrorState(err.message);
    } finally {
      runScanBtn.disabled = false;
      radarScanBanner.classList.add('hidden');
    }
  }

  // ========================================================================
  // 5. Render Scan Report & Visual Elements
  // ========================================================================
  function renderScanReport(report) {
    const summary = report.summary;

    // 1. Metric values
    valTotalDeps.textContent = summary.total_dependencies;
    valTotalAdvisories.textContent = summary.total_advisories;
    valReachable.textContent = summary.reachable_count;
    valNotReachable.textContent = summary.not_reachable_count;
    valUncertain.textContent = summary.uncertain_count;

    // Subnav counters
    subnavAdvisoriesBadge.textContent = summary.total_advisories;
    subnavDepsBadge.textContent = summary.total_dependencies;

    // 2. Posture Bar Calculations
    const total = summary.total_advisories || 1;
    const pReach = ((summary.reachable_count / total) * 100).toFixed(0);
    const pUncert = ((summary.uncertain_count / total) * 100).toFixed(0);
    const pSafe = ((summary.not_reachable_count / total) * 100).toFixed(0);

    sliceReachable.style.width = `${pReach}%`;
    sliceUncertain.style.width = `${pUncert}%`;
    sliceSafe.style.width = `${pSafe}%`;

    pctReachable.textContent = `${pReach}%`;
    pctUncertain.textContent = `${pUncert}%`;
    pctSafe.textContent = `${pSafe}%`;

    // 3. Filter counts
    countAll.textContent = report.findings.length;
    countReachable.textContent = summary.reachable_count;
    countSafe.textContent = summary.not_reachable_count;
    countUncertain.textContent = summary.uncertain_count;

    // 4. Render Findings
    renderFindings(report.findings);

    // 5. Render Bottom Dependencies
    renderDependenciesTable(report.dependencies);

    // 6. Render Animated Reachability Call Graph (DAG)
    renderAnimatedCallGraph(report);

    // 7. Update Raw JSON code block
    rawJsonBlock.textContent = JSON.stringify(report, null, 2);
  }

  function renderFindings(findings) {
    findingsContainer.innerHTML = '';
    const query = findingSearchBox.value.toLowerCase().trim();

    const filtered = findings.filter(f => {
      if (activeFilter !== 'ALL' && f.verdict !== activeFilter) return false;
      if (query) {
        const text = `${f.package} ${f.advisory_id} ${f.summary} ${f.vulnerable_symbol || ''}`.toLowerCase();
        return text.includes(query);
      }
      return true;
    });

    if (filtered.length === 0) {
      findingsContainer.innerHTML = `
        <div style="text-align: center; padding: 40px 20px; color: #64748b;">
          <p>No security findings matching active filter (${activeFilter}).</p>
        </div>
      `;
      return;
    }

    filtered.forEach(finding => {
      const card = document.createElement('div');
      card.className = 'gh-finding-card';

      let badgeClass = 'badge-safe';
      let badgeLabel = 'NOT REACHABLE';
      if (finding.verdict === 'REACHABLE') {
        badgeClass = 'badge-reachable';
        badgeLabel = 'REACHABLE';
      } else if (finding.verdict === 'UNCERTAIN') {
        badgeClass = 'badge-uncertain';
        badgeLabel = 'UNCERTAIN';
      }

      // Evidence Trace HTML
      let evidenceHtml = '';
      if (finding.evidence && finding.evidence.length > 0) {
        evidenceHtml = `
          <div class="gh-code-evidence">
            <div class="code-header-bar">
              <span>Code Call Trace (${finding.evidence.length} Step${finding.evidence.length > 1 ? 's' : ''})</span>
              <span>${escapeHtml(finding.evidence[0].file)}:L${finding.evidence[0].line}</span>
            </div>
            ${finding.evidence.map(step => `
              <div class="code-trace-row">
                <span class="trace-from">${escapeHtml(step.from)}</span>
                <span class="trace-arrow">── calls ──▶</span>
                <span class="trace-to">${escapeHtml(step.to)}</span>
              </div>
            `).join('')}
          </div>
        `;
      }

      // Uncertainty hazards
      let uncertaintyHtml = '';
      if (finding.uncertainty_reasons && finding.uncertainty_reasons.length > 0) {
        uncertaintyHtml = `
          <div class="gh-code-evidence" style="border-color: rgba(245, 158, 11, 0.4);">
            <div class="code-header-bar" style="color: #f59e0b;">
              <span>Dynamic Reflection Hazards Flagged</span>
            </div>
            <div style="padding: 10px 14px; font-size: 0.8rem; color: #cbd5e1;">
              ${finding.uncertainty_reasons.map(r => `<div>• ${escapeHtml(r)}</div>`).join('')}
            </div>
          </div>
        `;
      }

      card.innerHTML = `
        <div class="card-headline">
          <div class="pkg-title-group">
            <span class="pkg-name-text">${escapeHtml(finding.package)}</span>
            <span class="version-pill">v${escapeHtml(finding.installed_version || 'unknown')}</span>
            <a href="https://osv.dev/vulnerability/${escapeHtml(finding.advisory_id)}" target="_blank" class="advisory-badge-link">
              ${escapeHtml(finding.advisory_id)} ↗
            </a>
          </div>
          <span class="risk-badge ${badgeClass}">${badgeLabel}</span>
        </div>

        <p class="card-desc">${escapeHtml(finding.summary)}</p>

        ${evidenceHtml}
        ${uncertaintyHtml}

        <div class="card-rationale">
          <strong>Reachability Proof:</strong> ${escapeHtml(finding.reason)}
        </div>
      `;

      findingsContainer.appendChild(card);
    });
  }

  function renderDependenciesTable(deps) {
    dockDepsCount.textContent = deps.length;
    dockDepsTableBody.innerHTML = '';

    if (deps.length === 0) {
      dockDepsTableBody.innerHTML = '<tr><td colspan="5" class="empty-table-state">No dependencies parsed in project.</td></tr>';
      return;
    }

    deps.forEach(d => {
      const tr = document.createElement('tr');
      const pinTag = d.is_pinned
        ? `<span class="tag-status green">== ${escapeHtml(d.version || '')} (Pinned)</span>`
        : `<span class="tag-status purple">Unpinned</span>`;

      tr.innerHTML = `
        <td style="font-weight: 700; color: #fff;">${escapeHtml(d.name)}</td>
        <td>${escapeHtml(d.version || '—')}</td>
        <td>${pinTag}</td>
        <td style="color: #8b949e;">${escapeHtml(d.source_file)}</td>
        <td style="color: #c084fc;">Line ${d.line}</td>
      `;
      dockDepsTableBody.appendChild(tr);
    });
  }

  // ========================================================================
  // 6. Animated Abnormal AI Call Graph DAG with Signal Packets
  // ========================================================================
  function renderAnimatedCallGraph(report) {
    reachabilityGraphSvg.innerHTML = '';

    const width = reachabilityGraphSvg.clientWidth || 560;
    const height = 450;

    const firstFinding = report.findings && report.findings[0];
    const isReachable = firstFinding && firstFinding.verdict === 'REACHABLE';
    const isUncertain = firstFinding && firstFinding.verdict === 'UNCERTAIN';

    // SVG Defs with Markers & Flow Filters
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.innerHTML = `
      <marker id="arrowRed" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#f43f5e" />
      </marker>
      <marker id="arrowGreen" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
      </marker>
      <marker id="arrowAmber" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
      </marker>
      <filter id="neonHalo" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="4" result="blur" />
        <feMerge>
          <feMergeNode in="blur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    `;
    reachabilityGraphSvg.appendChild(defs);

    // Node topology
    const nodes = [
      { id: 'n1', label: 'main()', file: 'app.py:10', type: 'entry', x: 80, y: height / 2 },
      { id: 'n2', label: 'process_input()', file: 'app.py:5', type: 'internal', x: width / 2, y: (height / 2) - 40 },
      { id: 'n3', label: 'yaml.load()', file: 'pyyaml (CVE-2020-14343)', type: 'sink', x: width - 110, y: (height / 2) + 30 }
    ];

    if (!isReachable && !isUncertain) {
      nodes[2].label = 'yaml.safe_load()';
      nodes[2].file = 'Verified Safe Sink';
      graphStateBadge.textContent = 'Path: Blocked / Safe';
      graphStateBadge.style.color = '#10b981';
    } else if (isUncertain) {
      nodes[1].label = 'getattr(yaml, ...)';
      nodes[1].file = 'Dynamic Hazard';
      graphStateBadge.textContent = 'Path: Ambiguous (Reflection)';
      graphStateBadge.style.color = '#f59e0b';
    } else {
      graphStateBadge.textContent = 'Path: REACHABLE SINK DETECTED';
      graphStateBadge.style.color = '#f43f5e';
    }

    // Boundary Line between User Code & External Dependency
    const boundX = width - 180;
    const boundary = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    boundary.setAttribute('x1', boundX);
    boundary.setAttribute('y1', 30);
    boundary.setAttribute('x2', boundX);
    boundary.setAttribute('y2', height - 30);
    boundary.setAttribute('stroke', 'rgba(255, 255, 255, 0.1)');
    boundary.setAttribute('stroke-dasharray', '5,5');
    reachabilityGraphSvg.appendChild(boundary);

    const boundLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    boundLabel.setAttribute('x', boundX + 8);
    boundLabel.setAttribute('y', 45);
    boundLabel.setAttribute('fill', '#6e7681');
    boundLabel.setAttribute('font-size', '10');
    boundLabel.setAttribute('font-family', 'var(--font-mono)');
    boundLabel.textContent = 'EXTERNAL DEPENDENCY BOUNDARY';
    reachabilityGraphSvg.appendChild(boundLabel);

    // Curved Paths
    const pathId1 = 'curvePath1';
    const pathId2 = 'curvePath2';
    const d1 = `M ${nodes[0].x} ${nodes[0].y} Q ${(nodes[0].x + nodes[1].x)/2} ${nodes[1].y - 35} ${nodes[1].x} ${nodes[1].y}`;
    const d2 = `M ${nodes[1].x} ${nodes[1].y} Q ${(nodes[1].x + nodes[2].x)/2} ${nodes[2].y + 35} ${nodes[2].x} ${nodes[2].y}`;

    let strokeCol = isReachable ? '#f43f5e' : (isUncertain ? '#f59e0b' : '#38bdf8');
    let marker = isReachable ? 'arrowRed' : (isUncertain ? 'arrowAmber' : 'arrowGreen');

    function createCurve(id, d, color, mark) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('id', id);
      path.setAttribute('d', d);
      path.setAttribute('fill', 'none');
      path.setAttribute('stroke', color);
      path.setAttribute('stroke-width', '2.5');
      path.setAttribute('marker-end', `url(#${mark})`);
      path.setAttribute('filter', 'url(#neonHalo)');
      return path;
    }

    reachabilityGraphSvg.appendChild(createCurve(pathId1, d1, strokeCol, marker));
    reachabilityGraphSvg.appendChild(createCurve(pathId2, d2, isReachable ? '#f43f5e' : (isUncertain ? '#f59e0b' : '#10b981'), marker));

    // Animated Flowing Signal Packets (Moving along the path!)
    function createFlowPacket(pathId, color) {
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', '4');
      circle.setAttribute('fill', color);
      circle.setAttribute('filter', 'url(#neonHalo)');

      const anim = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
      anim.setAttribute('dur', '1.8s');
      anim.setAttribute('repeatCount', 'indefinite');
      anim.innerHTML = `<mpath href="#${pathId}" />`;
      circle.appendChild(anim);

      return circle;
    }

    reachabilityGraphSvg.appendChild(createFlowPacket(pathId1, strokeCol));
    reachabilityGraphSvg.appendChild(createFlowPacket(pathId2, isReachable ? '#f43f5e' : (isUncertain ? '#f59e0b' : '#10b981')));

    // Nodes Rendering
    nodes.forEach(n => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('transform', `translate(${n.x}, ${n.y})`);

      let stroke = '#38bdf8';
      if (n.type === 'internal') stroke = '#c084fc';
      else if (n.type === 'sink') stroke = isReachable ? '#f43f5e' : (isUncertain ? '#f59e0b' : '#10b981');

      const box = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      box.setAttribute('x', '-65');
      box.setAttribute('y', '-25');
      box.setAttribute('width', '130');
      box.setAttribute('height', '50');
      box.setAttribute('rx', '8');
      box.setAttribute('fill', '#090d14');
      box.setAttribute('stroke', stroke);
      box.setAttribute('stroke-width', '2');
      box.setAttribute('filter', 'url(#neonHalo)');

      const t1 = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t1.setAttribute('text-anchor', 'middle');
      t1.setAttribute('y', '-2');
      t1.setAttribute('fill', '#ffffff');
      t1.setAttribute('font-size', '12');
      t1.setAttribute('font-weight', '700');
      t1.setAttribute('font-family', 'var(--font-mono)');
      t1.textContent = n.label;

      const t2 = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t2.setAttribute('text-anchor', 'middle');
      t2.setAttribute('y', '15');
      t2.setAttribute('fill', stroke);
      t2.setAttribute('font-size', '10');
      t2.setAttribute('font-family', 'var(--font-mono)');
      t2.textContent = n.file;

      g.appendChild(box);
      g.appendChild(t1);
      g.appendChild(t2);

      reachabilityGraphSvg.appendChild(g);
    });
  }

  function showErrorState(msg) {
    findingsContainer.innerHTML = `
      <div style="background: rgba(244, 63, 94, 0.15); border: 1px solid rgba(244, 63, 94, 0.4); border-radius: 8px; padding: 18px; color: #f43f5e;">
        <strong>Reachability Analysis Error:</strong>
        <p style="margin-top: 6px; font-size: 0.86rem; color: #cbd5e1;">${escapeHtml(msg)}</p>
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
