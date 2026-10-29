/**
 * FileGuard - Suspicious File Analysis Platform
 * Frontend JavaScript Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    // Current application state
    let activeReportData = null;
    let scanHistoryCache = [];
    let activeFilter = 'all';

    // UI Elements
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.app-section');
    const dropzone = document.getElementById('file-dropzone');
    const fileInput = document.getElementById('file-input');
    const btnBrowse = document.getElementById('btn-browse');
    const progressBox = document.getElementById('scan-progress-box');
    const progressBarFill = document.getElementById('progress-bar-fill');
    const progressPhaseLabel = document.getElementById('progress-phase-label');
    const progressPercentLabel = document.getElementById('progress-percent-label');
    const scannerResultBox = document.getElementById('scanner-result-box');
    const historyTbody = document.getElementById('history-tbody');
    const historySearchInput = document.getElementById('history-search-input');
    const historyFilterPills = document.querySelectorAll('.filter-pill');
    const btnRefreshHistory = document.getElementById('btn-refresh-history');
    const btnClearHistory = document.getElementById('btn-clear-history');
    const sampleButtons = document.querySelectorAll('.sample-btn');

    // =========================================================================
    // 1. Tab & Hash Navigation Routing
    // =========================================================================
    function switchTab(tabId, pushHash = true) {
        // Normalize tab id
        const targetSection = document.getElementById(`section-${tabId}`);
        if (!targetSection) tabId = 'dashboard';

        // Update Nav items
        navItems.forEach(item => {
            if (item.getAttribute('data-tab') === tabId) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        // Update Sections
        sections.forEach(sec => {
            if (sec.id === `section-${tabId}`) {
                sec.classList.add('active');
            } else {
                sec.classList.remove('active');
            }
        });

        if (pushHash) {
            window.location.hash = tabId;
        }

        // Trigger tab-specific refreshes
        if (tabId === 'history') {
            loadScanHistory();
        } else if (tabId === 'dashboard') {
            refreshDashboardStats();
        }

        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    // Handle initial hash on page load
    function handleInitialHash() {
        const hash = window.location.hash.replace('#', '').trim();
        if (hash) {
            if (hash.startsWith('report?id=')) {
                const scanId = hash.split('=')[1];
                switchTab('report');
                loadScanDetail(scanId);
            } else {
                switchTab(hash);
            }
        } else {
            switchTab('dashboard');
        }
    }

    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.replace('#', '').trim();
        if (hash && !hash.startsWith('report?id=')) {
            switchTab(hash, false);
        }
    });

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = item.getAttribute('data-tab');
            switchTab(tab);
        });
    });

    // Brand link
    const brandLink = document.getElementById('brand-link');
    if (brandLink) {
        brandLink.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('dashboard');
        });
    }

    // =========================================================================
    // 2. Toast Notifications & Helpers
    // =========================================================================
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        let iconSvg = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#00ff88" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
        if (type === 'error') {
            iconSvg = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
        }

        toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
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

    function copyToClipboard(text, label = 'Copied to clipboard!') {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
                showToast(label, 'success');
            }).catch(() => {
                fallbackCopyText(text, label);
            });
        } else {
            fallbackCopyText(text, label);
        }
    }

    function fallbackCopyText(text, label) {
        const temp = document.createElement('textarea');
        temp.value = text;
        document.body.appendChild(temp);
        temp.select();
        try {
            document.execCommand('copy');
            showToast(label, 'success');
        } catch (err) {
            showToast('Unable to copy text.', 'error');
        }
        document.body.removeChild(temp);
    }

    // =========================================================================
    // 3. File Drag & Drop + Upload Pipeline
    // =========================================================================
    if (dropzone && fileInput) {
        // Browse button
        if (btnBrowse) {
            btnBrowse.addEventListener('click', (e) => {
                e.stopPropagation();
                fileInput.click();
            });
        }

        dropzone.addEventListener('click', () => {
            fileInput.click();
        });

        // Drag events
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('dragover');
            });
        });

        dropzone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files && files.length > 0) {
                handleFileUpload(files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (fileInput.files && fileInput.files.length > 0) {
                handleFileUpload(fileInput.files[0]);
            }
        });
    }

    function handleFileUpload(file) {
        // Max 16 MB limit check
        const MAX_BYTES = 16 * 1024 * 1024;
        if (file.size > MAX_BYTES) {
            showToast(`File exceeds 16 MB upload limit (${(file.size / (1024 * 1024)).toFixed(2)} MB).`, 'error');
            return;
        }

        if (file.size === 0) {
            showToast('Selected file is empty (0 bytes).', 'error');
            return;
        }

        startScanPipeline(file);
    }

    function startScanPipeline(file) {
        // Reset and display progress animation
        progressBox.style.display = 'block';
        scannerResultBox.style.display = 'none';

        const steps = [
            document.getElementById('step-upload'),
            document.getElementById('step-hash'),
            document.getElementById('step-entropy'),
            document.getElementById('step-heuristics')
        ];

        steps.forEach(s => s.classList.remove('active'));
        steps[0].classList.add('active');

        progressBarFill.style.width = '20%';
        progressPercentLabel.innerText = '20%';
        progressPhaseLabel.innerText = `Ingesting ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`;

        // Create form data
        const formData = new FormData();
        formData.append('file', file);

        // Simulated progress steps for great UX
        setTimeout(() => {
            steps[1].classList.add('active');
            progressBarFill.style.width = '50%';
            progressPercentLabel.innerText = '50%';
            progressPhaseLabel.innerText = 'Computing SHA-256 and cryptographic digests...';
        }, 250);

        setTimeout(() => {
            steps[2].classList.add('active');
            progressBarFill.style.width = '75%';
            progressPercentLabel.innerText = '75%';
            progressPhaseLabel.innerText = 'Analyzing Shannon entropy and byte distribution...';
        }, 500);

        // Perform actual fetch request
        fetch('/api/scan', {
            method: 'POST',
            body: formData
        })
        .then(res => {
            if (!res.ok) {
                return res.json().then(errData => { throw new Error(errData.message || 'Scan request failed'); });
            }
            return res.json();
        })
        .then(data => {
            if (data.status === 'success' && data.report) {
                steps[3].classList.add('active');
                progressBarFill.style.width = '100%';
                progressPercentLabel.innerText = '100%';
                progressPhaseLabel.innerText = 'Static heuristics evaluated. Complete!';

                setTimeout(() => {
                    progressBox.style.display = 'none';
                    renderScannerResult(data.report);
                    refreshDashboardStats();
                    showToast(`Scan complete for ${file.name}`, 'success');
                }, 400);
            } else {
                throw new Error(data.message || 'Unknown analysis error.');
            }
        })
        .catch(err => {
            progressBox.style.display = 'none';
            showToast(err.message, 'error');
        })
        .finally(() => {
            if (fileInput) fileInput.value = '';
        });
    }

    // =========================================================================
    // 4. Render Scanner Immediate Result Card
    // =========================================================================
    function renderScannerResult(report) {
        activeReportData = report;
        const meta = report.file_metadata;
        const hashes = report.hashes;
        const analysis = report.analysis;
        const entropy = report.entropy;

        let verdictClass = 'clean';
        let borderClass = 'score-border-clean';
        if (analysis.risk_score >= 50) {
            verdictClass = 'danger';
            borderClass = 'score-border-danger';
        } else if (analysis.risk_score > 20) {
            verdictClass = 'warning';
            borderClass = 'score-border-warning';
        }

        let findingsHtml = '';
        if (analysis.findings && analysis.findings.length > 0) {
            findingsHtml = analysis.findings.map(f => {
                const sevLower = f.severity.toLowerCase();
                const evidenceHtml = f.evidence && f.evidence.length > 0 
                    ? `<div class="finding-evidence-snippet">Evidence: ${escapeHtml(f.evidence.join(' | '))}</div>` 
                    : '';
                return `
                    <div class="finding-item sev-${sevLower}">
                        <div class="finding-top-row">
                            <div class="finding-tag-group">
                                <span class="badge-sev badge-sev-${sevLower}">${f.severity}</span>
                                <span class="finding-rule-id">[${f.rule_id}]</span>
                                <span class="finding-title-text">${escapeHtml(f.title)}</span>
                            </div>
                            <span class="text-xs text-muted font-mono">${f.category}</span>
                        </div>
                        <p class="finding-body-text">${escapeHtml(f.explanation)}</p>
                        ${evidenceHtml}
                    </div>
                `;
            }).join('');
        } else {
            findingsHtml = `
                <div class="glass-card text-center py-6">
                    <p class="highlight-green font-semibold">✓ No anomalous heuristics detected. Standard file characteristics.</p>
                </div>
            `;
        }

        scannerResultBox.innerHTML = `
            <div class="scan-result-card">
                <!-- Verdict Header -->
                <div class="result-verdict-header verdict-box-${verdictClass}">
                    <div class="verdict-left">
                        <span class="verdict-label">STATIC HEURISTIC EVALUATION</span>
                        <h2 class="verdict-title text-${analysis.verdict_badge}">${analysis.verdict}</h2>
                        <p class="verdict-desc">${escapeHtml(analysis.summary)}</p>
                    </div>
                    <div class="verdict-right">
                        <div class="threat-score-gauge ${borderClass}">
                            <span class="gauge-val">${analysis.risk_score}</span>
                            <span class="gauge-max">/ 100</span>
                            <span class="gauge-tag">THREAT SCORE</span>
                        </div>
                    </div>
                </div>

                <!-- File Summary Grid -->
                <div class="summary-meta-grid">
                    <div class="meta-box">
                        <div class="meta-box-label">File Name & Size</div>
                        <div class="meta-box-val font-mono">${escapeHtml(meta.filename)}</div>
                        <div class="text-xs text-muted mt-1">${meta.filesize_formatted} (${meta.filesize} bytes)</div>
                    </div>
                    <div class="meta-box">
                        <div class="meta-box-label">Detected Type</div>
                        <div class="meta-box-val highlight-green">${escapeHtml(meta.detected_type)}</div>
                        <div class="text-xs text-muted font-mono mt-1">Claimed: ${escapeHtml(meta.extension)}</div>
                    </div>
                    <div class="meta-box">
                        <div class="meta-box-label">Shannon Entropy</div>
                        <div class="meta-box-val highlight-amber font-mono">${entropy.score} / 8.00</div>
                        <div class="text-xs text-muted mt-1">${entropy.level}</div>
                    </div>
                </div>

                <!-- SHA-256 Hash Display -->
                <div class="hash-preview-card">
                    <div class="hash-label-group">
                        <span class="hash-title-label">SHA-256 CRYPTOGRAPHIC DIGEST</span>
                        <span class="hash-display-text" id="result-sha256">${hashes.sha256}</span>
                    </div>
                    <button class="btn-copy" id="btn-copy-sha256">Copy Hash</button>
                </div>

                <!-- Findings Section -->
                <div class="findings-container">
                    <h3 class="card-title-sub mb-3">Triggered Heuristics (${analysis.findings_count})</h3>
                    ${findingsHtml}
                </div>

                <!-- Action Toolbar -->
                <div class="result-actions-toolbar">
                    <button class="btn btn-primary" id="btn-open-full-report">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                        <span>View Forensic Report</span>
                    </button>
                    <div class="flex-center gap-2">
                        <a href="/api/scans/${report.scan_id}/export?format=json" class="btn btn-outline btn-sm">Export JSON</a>
                        <a href="/api/scans/${report.scan_id}/export?format=txt" class="btn btn-outline btn-sm">Export TXT</a>
                        <button class="btn btn-secondary btn-sm" id="btn-scan-another">Scan Another File</button>
                    </div>
                </div>
            </div>
        `;

        scannerResultBox.style.display = 'block';

        // Bind inner buttons
        document.getElementById('btn-copy-sha256').addEventListener('click', () => {
            copyToClipboard(hashes.sha256, 'SHA-256 copied to clipboard!');
        });

        document.getElementById('btn-open-full-report').addEventListener('click', () => {
            switchTab('report');
            renderFullReport(report);
        });

        document.getElementById('btn-scan-another').addEventListener('click', () => {
            scannerResultBox.style.display = 'none';
            window.scrollTo({ top: dropzone.offsetTop - 80, behavior: 'smooth' });
        });
    }

    // =========================================================================
    // 5. Educational Preset Samples
    // =========================================================================
    sampleButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const sampleType = btn.getAttribute('data-sample');
            triggerSampleScan(sampleType);
        });
    });

    function triggerSampleScan(sampleType) {
        switchTab('scanner');
        progressBox.style.display = 'block';
        scannerResultBox.style.display = 'none';

        progressBarFill.style.width = '40%';
        progressPercentLabel.innerText = '40%';
        progressPhaseLabel.innerText = `Generating test sample: ${sampleType}...`;

        setTimeout(() => {
            progressBarFill.style.width = '75%';
            progressPercentLabel.innerText = '75%';
            progressPhaseLabel.innerText = 'Evaluating static heuristics and signatures...';
        }, 300);

        fetch(`/api/sample/${sampleType}`, { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' && data.report) {
                progressBarFill.style.width = '100%';
                progressPercentLabel.innerText = '100%';
                setTimeout(() => {
                    progressBox.style.display = 'none';
                    renderScannerResult(data.report);
                    refreshDashboardStats();
                    showToast(data.message, 'success');
                }, 300);
            } else {
                throw new Error(data.message || 'Sample test failed.');
            }
        })
        .catch(err => {
            progressBox.style.display = 'none';
            showToast(err.message, 'error');
        });
    }

    // =========================================================================
    // 6. Scan History & Filtering
    // =========================================================================
    function loadScanHistory() {
        if (!historyTbody) return;

        historyTbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-6 text-muted">
                    <span class="spinner-inline"></span> Fetching local scan records...
                </td>
            </tr>
        `;

        fetch('/api/scans')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                scanHistoryCache = data.scans || [];
                renderHistoryRows(filterScans(scanHistoryCache));
                updateNavCount(scanHistoryCache.length);
            }
        })
        .catch(err => {
            historyTbody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center py-6 text-red-400">Failed to load history: ${escapeHtml(err.message)}</td>
                </tr>
            `;
        });
    }

    function filterScans(scans) {
        const query = historySearchInput ? historySearchInput.value.toLowerCase().trim() : '';
        return scans.filter(scan => {
            // Text search
            const matchQuery = !query || 
                scan.filename.toLowerCase().includes(query) ||
                scan.sha256.toLowerCase().includes(query) ||
                scan.verdict.toLowerCase().includes(query) ||
                (scan.detected_type && scan.detected_type.toLowerCase().includes(query));

            // Pill filter
            let matchPill = true;
            if (activeFilter === 'high risk') {
                matchPill = scan.verdict.toLowerCase() === 'high risk';
            } else if (activeFilter === 'suspicious') {
                matchPill = scan.verdict.toLowerCase() === 'suspicious';
            } else if (activeFilter === 'clean') {
                matchPill = scan.verdict.toLowerCase() === 'clean' || scan.verdict.toLowerCase() === 'low risk';
            }

            return matchQuery && matchPill;
        });
    }

    function renderHistoryRows(scans) {
        if (!historyTbody) return;

        if (scans.length === 0) {
            historyTbody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center py-8 text-muted">
                        No scan records match your criteria.
                    </td>
                </tr>
            `;
            return;
        }

        historyTbody.innerHTML = scans.map(s => {
            const truncatedHash = `${s.sha256.substring(0, 10)}...${s.sha256.substring(s.sha256.length - 8)}`;
            const sizeFormatted = formatBytes(s.filesize);
            const verdictLower = s.verdict.toLowerCase().replace(/\s+/g, '-');
            const scoreClass = s.risk_score >= 50 ? 'danger' : (s.risk_score > 20 ? 'warning' : 'clean');
            const timeStr = s.created_at ? s.created_at.substring(0, 19).replace('T', ' ') : 'N/A';

            return `
                <tr>
                    <td class="font-semibold text-white">${escapeHtml(s.filename)}</td>
                    <td class="text-xs font-mono">${sizeFormatted}</td>
                    <td><span class="badge-tag">${escapeHtml(s.detected_type || 'Unknown')}</span></td>
                    <td class="font-mono text-xs">
                        <span class="cursor-pointer" title="Click to copy hash" onclick="window.copyHash('${s.sha256}')">
                            ${truncatedHash}
                        </span>
                    </td>
                    <td class="font-mono text-xs">${s.entropy}</td>
                    <td>
                        <div class="score-pill score-${scoreClass}">${s.risk_score}/100</div>
                    </td>
                    <td>
                        <span class="badge-verdict verdict-${verdictLower}">${s.verdict}</span>
                    </td>
                    <td class="text-xs text-muted">${timeStr}</td>
                    <td>
                        <div class="flex-center gap-2">
                            <button class="btn-table-action" onclick="window.viewScanDetail('${s.scan_id}')">Report</button>
                            <button class="btn-table-delete" title="Delete record" onclick="window.deleteScanRecord('${s.scan_id}')">
                                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }

    // Search input listener
    if (historySearchInput) {
        historySearchInput.addEventListener('input', () => {
            renderHistoryRows(filterScans(scanHistoryCache));
        });
    }

    // Filter pills
    historyFilterPills.forEach(pill => {
        pill.addEventListener('click', () => {
            historyFilterPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            activeFilter = pill.getAttribute('data-filter');
            renderHistoryRows(filterScans(scanHistoryCache));
        });
    });

    if (btnRefreshHistory) {
        btnRefreshHistory.addEventListener('click', () => {
            loadScanHistory();
            showToast('Scan history refreshed.');
        });
    }

    if (btnClearHistory) {
        btnClearHistory.addEventListener('click', () => {
            if (confirm('Are you sure you want to delete all historical scan records from local database?')) {
                fetch('/api/scans', { method: 'DELETE' })
                .then(res => res.json())
                .then(data => {
                    showToast(data.message);
                    loadScanHistory();
                    refreshDashboardStats();
                });
            }
        });
    }

    // Global helper bindings
    window.copyHash = (hash) => {
        copyToClipboard(hash, 'SHA-256 copied to clipboard!');
    };

    window.viewScanDetail = (scanId) => {
        switchTab('report');
        loadScanDetail(scanId);
    };

    window.deleteScanRecord = (scanId) => {
        if (confirm('Delete this scan record?')) {
            fetch(`/api/scans/${scanId}`, { method: 'DELETE' })
            .then(res => res.json())
            .then(data => {
                showToast(data.message);
                loadScanHistory();
                refreshDashboardStats();
            });
        }
    };

    // =========================================================================
    // 7. Full Analysis Report View
    // =========================================================================
    function loadScanDetail(scanId) {
        const placeholder = document.getElementById('report-empty-placeholder');
        const activeContainer = document.getElementById('report-active-content');
        const controls = document.getElementById('report-controls');

        placeholder.style.display = 'block';
        activeContainer.style.display = 'none';
        controls.style.display = 'none';

        fetch(`/api/scans/${scanId}`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' && data.report) {
                renderFullReport(data.report);
            } else {
                showToast('Report not found.', 'error');
            }
        })
        .catch(err => {
            showToast(err.message, 'error');
        });
    }

    function renderFullReport(report) {
        activeReportData = report;
        const placeholder = document.getElementById('report-empty-placeholder');
        const activeContainer = document.getElementById('report-active-content');
        const controls = document.getElementById('report-controls');
        const meta = report.file_metadata;
        const hashes = report.hashes;
        const analysis = report.analysis;
        const entropy = report.entropy;

        placeholder.style.display = 'none';
        controls.style.display = 'flex';
        activeContainer.style.display = 'block';

        // Update export buttons
        const btnTxt = document.getElementById('btn-export-txt');
        const btnJson = document.getElementById('btn-export-json');
        if (btnTxt) btnTxt.onclick = () => window.location.href = `/api/scans/${report.scan_id}/export?format=txt`;
        if (btnJson) btnJson.onclick = () => window.location.href = `/api/scans/${report.scan_id}/export?format=json`;

        // Verdict class
        let verdictClass = 'clean';
        let borderClass = 'score-border-clean';
        if (analysis.risk_score >= 50) {
            verdictClass = 'danger';
            borderClass = 'score-border-danger';
        } else if (analysis.risk_score > 20) {
            verdictClass = 'warning';
            borderClass = 'score-border-warning';
        }

        // Findings
        let findingsHtml = '';
        if (analysis.findings && analysis.findings.length > 0) {
            findingsHtml = analysis.findings.map(f => {
                const sevLower = f.severity.toLowerCase();
                const evidenceHtml = f.evidence && f.evidence.length > 0
                    ? `<div class="finding-evidence-box mt-2">
                        <span class="evidence-tag">Matched Pattern / String:</span>
                        <div class="evidence-items font-mono text-xs mt-1">
                            ${f.evidence.map(e => `<code class="bg-black p-1 rounded inline-block text-green-400 mr-2">${escapeHtml(e)}</code>`).join('')}
                        </div>
                       </div>`
                    : '';
                return `
                    <div class="finding-item sev-${sevLower}">
                        <div class="finding-top-row">
                            <div class="finding-tag-group">
                                <span class="badge-sev badge-sev-${sevLower}">${f.severity}</span>
                                <span class="finding-rule-id font-mono">[${f.rule_id}]</span>
                                <span class="finding-title-text font-bold">${escapeHtml(f.title)}</span>
                            </div>
                            <span class="text-xs text-muted font-mono">${f.category}</span>
                        </div>
                        <p class="finding-body-text mt-2">${escapeHtml(f.explanation)}</p>
                        ${evidenceHtml}
                    </div>
                `;
            }).join('');
        } else {
            findingsHtml = `
                <div class="clean-findings-box text-center py-6">
                    <p class="highlight-green font-semibold">✓ No suspicious characteristics or anomalous heuristics detected.</p>
                </div>
            `;
        }

        // Hex dump
        let hexDumpRows = '';
        if (report.hex_dump && report.hex_dump.length > 0) {
            hexDumpRows = report.hex_dump.map(r => 
                `<span class="hex-offset">${r.offset}:</span> <span class="hex-bytes">${r.hex}</span>  <span class="hex-ascii">|${escapeHtml(r.ascii)}|</span>\n`
            ).join('');
        }

        // Entropy chunks chart
        let chunkChartHtml = '';
        if (entropy.chunks && entropy.chunks.length > 0) {
            chunkChartHtml = `
                <div class="mt-4">
                    <span class="text-xs font-semibold uppercase text-muted">Entropy Distribution (16 Segments across file):</span>
                    <div class="chunk-chart-grid mt-2">
                        ${entropy.chunks.map(ch => {
                            const pctHeight = Math.min(100, Math.max(8, (ch.entropy / 8.0) * 100));
                            const barClass = ch.entropy >= 7.2 ? 'bar-critical' : (ch.entropy >= 6.0 ? 'bar-warning' : 'bar-normal');
                            return `
                                <div class="chunk-col" title="Slice ${ch.chunk} (${ch.start_pct}%-${ch.end_pct}%): ${ch.entropy} entropy">
                                    <div class="chunk-bar ${barClass}" style="height: ${pctHeight}%;"></div>
                                    <span class="chunk-lbl">${ch.chunk}</span>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            `;
        }

        activeContainer.innerHTML = `
            <!-- Verdict Hero -->
            <div class="glass-card mb-6">
                <div class="result-verdict-header verdict-box-${verdictClass}">
                    <div class="verdict-left">
                        <span class="verdict-label">STATIC HEURISTIC VERDICT</span>
                        <h2 class="verdict-title text-${analysis.verdict_badge}">${analysis.verdict}</h2>
                        <p class="verdict-desc">${escapeHtml(analysis.summary)}</p>
                        <div class="text-xs text-muted mt-2 font-mono">
                            Scan ID: ${report.scan_id} • Analyzed: ${report.created_at.substring(0, 19).replace('T', ' ')} UTC
                        </div>
                    </div>
                    <div class="verdict-right">
                        <div class="threat-score-gauge ${borderClass}">
                            <span class="gauge-val">${analysis.risk_score}</span>
                            <span class="gauge-max">/ 100</span>
                            <span class="gauge-tag">THREAT SCORE</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Metadata & Hashes Grid -->
            <div class="dashboard-grid-2col mb-6">
                <!-- Identification -->
                <div class="glass-card">
                    <h3 class="card-title-sub">File Identification</h3>
                    <div class="meta-data-table">
                        <div class="meta-row">
                            <span class="meta-label">File Name:</span>
                            <span class="meta-val font-mono font-bold">${escapeHtml(meta.filename)}</span>
                        </div>
                        <div class="meta-row">
                            <span class="meta-label">File Size:</span>
                            <span class="meta-val">${meta.filesize_formatted} (${meta.filesize} bytes)</span>
                        </div>
                        <div class="meta-row">
                            <span class="meta-label">Claimed Extension:</span>
                            <span class="meta-val font-mono">${escapeHtml(meta.extension)}</span>
                        </div>
                        <div class="meta-row">
                            <span class="meta-label">True Detected Type:</span>
                            <span class="meta-val highlight-green font-semibold">${escapeHtml(meta.detected_type)}</span>
                        </div>
                        <div class="meta-row">
                            <span class="meta-label">MIME Type:</span>
                            <span class="meta-val font-mono text-xs">${escapeHtml(meta.mime_type)}</span>
                        </div>
                        <div class="meta-row">
                            <span class="meta-label">Direct Executable:</span>
                            <span class="meta-val">${meta.is_executable ? 'Yes (Executable / Shell Script)' : 'No (Passive / Data)'}</span>
                        </div>
                    </div>
                </div>

                <!-- Hashes -->
                <div class="glass-card">
                    <h3 class="card-title-sub">Cryptographic Hashes</h3>
                    <div class="hash-list">
                        <div class="hash-item-box">
                            <div class="hash-header">
                                <span class="hash-algo">SHA-256 (Primary Identifier)</span>
                                <button class="btn-copy-hash" onclick="window.copyHash('${hashes.sha256}')">Copy</button>
                            </div>
                            <div class="hash-string font-mono">${hashes.sha256}</div>
                        </div>

                        <div class="hash-item-box">
                            <div class="hash-header">
                                <span class="hash-algo">SHA-1</span>
                                <button class="btn-copy-hash" onclick="window.copyHash('${hashes.sha1}')">Copy</button>
                            </div>
                            <div class="hash-string font-mono">${hashes.sha1}</div>
                        </div>

                        <div class="hash-item-box">
                            <div class="hash-header">
                                <span class="hash-algo">MD5</span>
                                <button class="btn-copy-hash" onclick="window.copyHash('${hashes.md5}')">Copy</button>
                            </div>
                            <div class="hash-string font-mono">${hashes.md5}</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Shannon Entropy -->
            <div class="glass-card mb-6">
                <div class="card-header-flex">
                    <div>
                        <h3 class="card-title-sub mb-1">Shannon Entropy Randomness Analysis</h3>
                        <p class="text-xs text-muted">Values above 7.2 indicate encrypted payloads, compressed droppers, or UPX binary packers.</p>
                    </div>
                    <div class="entropy-val-badge">
                        Entropy: <strong class="highlight-amber">${entropy.score}</strong> / 8.00 (${entropy.level})
                    </div>
                </div>

                <div class="entropy-bar-track mt-3">
                    <div class="entropy-bar-fill" style="width: ${(entropy.score / 8.0) * 100}%;"></div>
                    <div class="entropy-threshold-mark" style="left: 90%;" title="7.2 Suspicious / Packed Threshold"></div>
                </div>
                <div class="entropy-legend mt-2">
                    <span>0.0 (Uniform)</span>
                    <span>4.0 (Normal Text)</span>
                    <span>6.0 (Compiled Code)</span>
                    <span class="highlight-red">7.2+ (Suspicious/Encrypted)</span>
                    <span>8.0 (Random/Max)</span>
                </div>

                <p class="text-sm text-secondary mt-3">
                    <strong>Assessment:</strong> ${escapeHtml(entropy.description)}
                </p>

                ${chunkChartHtml}
            </div>

            <!-- Heuristic Findings List -->
            <div class="glass-card mb-6">
                <h3 class="card-title-sub mb-3">Heuristic Threat Indicators (${analysis.findings_count})</h3>
                <div class="findings-list-wrapper">
                    ${findingsHtml}
                </div>
            </div>

            <!-- Hex Dump Preview -->
            <div class="glass-card mb-6">
                <h3 class="card-title-sub mb-2">Initial Byte Stream & Hex Dump (First 128 Bytes)</h3>
                <p class="text-xs text-muted mb-3">Static inspection of the initial file header bytes showing offset, hexadecimal bytes, and printable ASCII representation.</p>
                <div class="hex-dump-container">
                    <pre class="hex-pre"><code>${hexDumpRows}</code></pre>
                </div>
            </div>

            <!-- Disclaimer Box -->
            <div class="disclaimer-alert-box">
                <strong>Static Inspection Notice:</strong> ${escapeHtml(report.disclaimer.notice)} ${escapeHtml(report.disclaimer.limitation)}
            </div>
        `;

        window.location.hash = `report?id=${report.scan_id}`;
    }

    // =========================================================================
    // 8. Dashboard Telemetry Updates
    // =========================================================================
    function refreshDashboardStats() {
        fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const s = data.data;
                const totalEl = document.getElementById('kpi-total-scans');
                const threatEl = document.getElementById('kpi-threat-scans');
                const cleanEl = document.getElementById('kpi-clean-scans');
                const avgEntEl = document.getElementById('kpi-avg-entropy');
                
                if (totalEl) totalEl.innerText = s.total_scans;
                if (threatEl) threatEl.innerText = s.suspicious_scans + s.high_risk_scans;
                if (cleanEl) cleanEl.innerText = s.clean_scans;
                if (avgEntEl) avgEntEl.innerHTML = `${s.avg_entropy} <span class="unit">/ 8.0</span>`;

                updateNavCount(s.total_scans);
                renderRecentTable(s.recent_scans);
            }
        })
        .catch(() => {});
    }

    function updateNavCount(count) {
        const navCount = document.getElementById('nav-history-count');
        if (navCount) navCount.innerText = count;
    }

    function renderRecentTable(recent) {
        const tbody = document.getElementById('dashboard-recent-tbody');
        if (!tbody) return;

        if (!recent || recent.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center py-6 text-muted">No files analyzed yet. Upload a file or launch a test sample above!</td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = recent.map(item => {
            const truncatedHash = `${item.sha256.substring(0, 10)}...${item.sha256.substring(item.sha256.length - 8)}`;
            const scoreClass = item.risk_score >= 50 ? 'danger' : (item.risk_score > 20 ? 'warning' : 'clean');
            const verdictLower = item.verdict.toLowerCase().replace(/\s+/g, '-');
            const timeStr = item.created_at ? item.created_at.substring(0, 19).replace('T', ' ') : '';

            return `
                <tr>
                    <td class="font-semibold text-white">${escapeHtml(item.filename)}</td>
                    <td><span class="badge-tag">${escapeHtml(item.detected_type || 'Unknown')}</span></td>
                    <td class="font-mono text-xs cursor-pointer" onclick="window.copyHash('${item.sha256}')" title="Click to copy">${truncatedHash}</td>
                    <td>
                        <div class="score-pill score-${scoreClass}">${item.risk_score}/100</div>
                    </td>
                    <td>
                        <span class="badge-verdict verdict-${verdictLower}">${item.verdict}</span>
                    </td>
                    <td class="text-xs text-muted">${timeStr}</td>
                    <td>
                        <button class="btn-table-action" onclick="window.viewScanDetail('${item.scan_id}')">Report</button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    // Initialize application
    handleInitialHash();
});
