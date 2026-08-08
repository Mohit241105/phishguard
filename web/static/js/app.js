/**
 * Main Web Application Logic for PhishGuard AI Cyber SOC Dashboard
 * 100% English Language Edition
 */
document.addEventListener('DOMContentLoaded', () => {

    let selectedFile = null;

    // Elements
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const dropLabel = document.getElementById('drop-label');
    const btnExecuteScan = document.getElementById('btn-execute-scan');
    const scanBtnText = document.getElementById('scan-btn-text');

    const btnSamplePhish = document.getElementById('btn-sample-phish');
    const btnSampleSafe = document.getElementById('btn-sample-safe');

    const resultsDrawer = document.getElementById('results-drawer');
    const closeDrawer = document.getElementById('close-drawer');

    const btnHistory = document.getElementById('btn-history');
    const historyModal = document.getElementById('history-modal');
    const closeHistory = document.getElementById('close-history');
    const historySearch = document.getElementById('history-search');
    const btnClearDb = document.getElementById('btn-clear-db');

    const btnExport = document.getElementById('btn-export');

    // -------------------------------------------------------------
    // FILE DRAG AND DROP HANDLER
    // -------------------------------------------------------------
    if (dropZone && fileInput) {
        dropZone.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                selectedFile = e.target.files[0];
                dropLabel.innerText = `📄 File Selected: ${selectedFile.name}`;
            }
        });

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#3182ce';
            dropZone.style.background = '#ebf8ff';
        });

        dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#cbd5e0';
            dropZone.style.background = '#f7fafc';
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#cbd5e0';
            dropZone.style.background = '#f7fafc';

            if (e.dataTransfer.files.length > 0) {
                selectedFile = e.dataTransfer.files[0];
                dropLabel.innerText = `📄 File Selected: ${selectedFile.name}`;
            }
        });
    }

    // -------------------------------------------------------------
    // SAMPLE ACTIONS
    // -------------------------------------------------------------
    if (btnSamplePhish) {
        btnSamplePhish.addEventListener('click', () => runAnalysis({ sample_type: 'phishing' }));
    }

    if (btnSampleSafe) {
        btnSampleSafe.addEventListener('click', () => runAnalysis({ sample_type: 'safe' }));
    }

    if (btnExecuteScan) {
        btnExecuteScan.addEventListener('click', () => {
            if (selectedFile) {
                const formData = new FormData();
                formData.append('file', selectedFile);
                runAnalysis(formData, true);
            } else {
                alert('Please select or drop an .eml email file first, or click one of the test sample buttons!');
            }
        });
    }

    // -------------------------------------------------------------
    // API ANALYSIS RUNNER
    // -------------------------------------------------------------
    async function runAnalysis(bodyData, isFormData = false) {
        setLoadingState(true);

        try {
            let options = { method: 'POST' };
            if (isFormData) {
                options.body = bodyData;
            } else {
                const form = new FormData();
                for (let k in bodyData) {
                    form.append(k, bodyData[k]);
                }
                options.body = form;
            }

            const response = await fetch('/api/analyze', options);
            const data = await response.json();

            setLoadingState(false);

            if (data.success && data.report) {
                updateDashboardWithReport(data.report);
                openResultsDrawer(data.report);
            } else {
                alert('Analysis Error: ' + (data.error || 'Unknown error'));
            }
        } catch (err) {
            setLoadingState(false);
            alert('Failed to connect to backend server: ' + err.message);
        }
    }

    function setLoadingState(loading) {
        if (loading) {
            scanBtnText.innerText = 'Analyzing Email & Security Headers...';
            btnExecuteScan.disabled = true;
            btnExecuteScan.style.opacity = '0.7';
        } else {
            scanBtnText.innerText = 'Run Security Scan / Analyze Email';
            btnExecuteScan.disabled = false;
            btnExecuteScan.style.opacity = '1';
        }
    }

    // -------------------------------------------------------------
    // UPDATE DASHBOARD & DUAL-COLUMN PILL TAG GRID
    // -------------------------------------------------------------
    function updateDashboardWithReport(report) {
        // Update Chart.js background graphs & drawer bar chart
        if (typeof updateChartsWithReport === 'function') {
            updateChartsWithReport(report);
        }

        const h = report.header_details || {};
        const u = report.url_details || {};
        const a = report.attachment_details || {};
        const n = report.nlp_details || {};
        const m = report.ml_details || {};

        // Update Dual Column L / R Pill Tags inside Central Manual Scan Card
        setPill('pill-spf', h.spf_status === 'PASS' ? 'SPF PASS' : 'SPF FAIL', h.spf_status === 'PASS' ? 'blue' : 'red');
        setPill('pill-dkim', h.dkim_status === 'PASS' ? 'DKIM PASS' : 'DKIM FAIL', h.dkim_status === 'PASS' ? 'blue' : 'red');
        setPill('pill-dmarc', h.dmarc_status === 'PASS' ? 'DMARC PASS' : 'DMARC FAIL', h.dmarc_status === 'PASS' ? 'blue' : 'red');
        setPill('pill-reply', h.reply_mismatch ? 'REPLY MISMATCH' : 'REPLY OK', h.reply_mismatch ? 'red' : 'blue');

        setPill('pill-return', h.return_mismatch ? 'RETURN MISMATCH' : 'RETURN OK', h.return_mismatch ? 'red' : 'blue');
        setPill('pill-spoof', h.brand_spoofing ? 'SPOOF DETECTED' : 'NO SPOOFING', h.brand_spoofing ? 'red' : 'blue');
        setPill('pill-ip-route', h.originating_ip ? `IP: ${h.originating_ip}` : 'VALID IP', 'blue');
        setPill('pill-msg-id', report.subject ? 'SUBJECT CHECKED' : 'HEADER OK', 'blue');

        setPill('pill-url', u.url_risk_score > 30 ? `URL RISK ${u.url_risk_score}` : 'URL CLEAN', u.url_risk_score > 30 ? 'red' : 'green');
        setPill('pill-ip', u.anchor_mismatches && u.anchor_mismatches.length > 0 ? 'DECEPTIVE LINK' : 'IP HOST CLEAN', u.anchor_mismatches && u.anchor_mismatches.length > 0 ? 'red' : 'green');
        setPill('pill-puny', u.findings && u.findings.some(f => f.includes('Punycode')) ? 'PUNYCODE DETECTED' : 'NO PUNYCODE', u.findings && u.findings.some(f => f.includes('Punycode')) ? 'red' : 'green');
        setPill('pill-short', u.findings && u.findings.some(f => f.includes('shortening')) ? 'URL SHORTENER' : 'NO SHORTENER', u.findings && u.findings.some(f => f.includes('shortening')) ? 'red' : 'green');

        setPill('pill-att', a.total_attachments > 0 ? `${a.total_attachments} ATTACHMENT(S)` : 'NO ATTACHMENTS', a.attachment_risk_score > 30 ? 'red' : 'green');
        setPill('pill-macro', a.findings && a.findings.some(f => f.includes('Macro') || f.includes('Executable')) ? 'HIGH RISK EXT' : 'NO MACROS', a.findings && a.findings.some(f => f.includes('Macro') || f.includes('Executable')) ? 'red' : 'green');

        setPill('pill-double-ext', a.findings && a.findings.some(f => f.includes('Double extension')) ? 'DOUBLE EXT' : 'CLEAN EXT', a.findings && a.findings.some(f => f.includes('Double extension')) ? 'red' : 'green');
        setPill('pill-archive', 'UNLOCKED', 'green');

        setPill('pill-anchor', u.anchor_mismatches && u.anchor_mismatches.length > 0 ? 'MISMATCHED' : 'MATCHED', u.anchor_mismatches && u.anchor_mismatches.length > 0 ? 'red' : 'gray');
        setPill('pill-protocol', u.urls && u.urls.some(url => url.url.startsWith('http://')) ? 'HTTP UNENCRYPTED' : 'HTTPS SECURE', u.urls && u.urls.some(url => url.url.startsWith('http://')) ? 'red' : 'gray');

        setPill('pill-greeting', n.findings && n.findings.some(f => f.includes('Generic Greeting')) ? 'GENERIC GREETING' : 'PERSONALIZED', n.findings && n.findings.some(f => f.includes('Generic Greeting')) ? 'red' : 'gray');
        setPill('pill-tld', u.findings && u.findings.some(f => f.includes('TLD')) ? 'SUSPICIOUS TLD' : 'STANDARD TLD', u.findings && u.findings.some(f => f.includes('TLD')) ? 'red' : 'gray');

        setPill('pill-nlp', n.total_tactic_hits > 0 ? `${n.total_tactic_hits} SOCIAL ENG TACTICS` : 'NLP NORMAL', n.total_tactic_hits > 0 ? 'red' : 'green');
        setPill('pill-urgency', n.detected_categories && n.detected_categories['Urgency & Pressure'] ? 'URGENCY DETECTED' : 'NO URGENCY', n.detected_categories && n.detected_categories['Urgency & Pressure'] ? 'red' : 'green');

        setPill('pill-ml', `AI CONF: ${m.confidence || 0}%`, report.verdict === 'PHISHING' ? 'red' : 'green');
        setPill('pill-verdict', `VERDICT: ${report.verdict}`, report.verdict === 'PHISHING' ? 'red' : (report.verdict === 'SUSPICIOUS' ? 'red' : 'blue'));
    }

    function setPill(id, text, colorClass) {
        const el = document.getElementById(id);
        if (el) {
            el.innerHTML = `${text} <span class="arr">▼</span>`;
            el.className = `pill-item ${colorClass}`;
        }
    }

    // -------------------------------------------------------------
    // RESULTS DRAWER & TABS
    // -------------------------------------------------------------
    function openResultsDrawer(report) {
        const resVerdict = document.getElementById('res-verdict');
        const resScore = document.getElementById('res-score');
        const resBanner = document.getElementById('res-banner');

        if (resVerdict && resScore && resBanner) {
            resVerdict.innerText = report.verdict;
            resScore.innerText = `Final Risk Score: ${report.final_risk_score}/100 (${report.risk_level})`;
            resBanner.style.borderColor = report.badge_color || '#00f2fe';
            resVerdict.style.color = report.badge_color || '#00f2fe';
        }

        // Explanations List
        const listExp = document.getElementById('list-explanations');
        if (listExp) {
            listExp.innerHTML = (report.explanations || []).map(e => `<li>${escapeHtml(e)}</li>`).join('');
        }

        // Recommendations List
        const listRec = document.getElementById('list-recommendations');
        if (listRec) {
            listRec.innerHTML = (report.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');
        }

        // URLs Table
        const tblUrls = document.getElementById('tbl-urls-body');
        if (tblUrls) {
            const urls = (report.url_details && report.url_details.urls) ? report.url_details.urls : [];
            tblUrls.innerHTML = urls.map(u => `
                <tr>
                    <td style="word-break:break-all;">${escapeHtml(u.url)}</td>
                    <td>${escapeHtml(u.domain)}</td>
                    <td><span style="color:${u.risk_level === 'DANGEROUS' ? '#ff5252' : '#00e676'}">${u.risk_level}</span></td>
                    <td>${u.score}/100</td>
                </tr>
            `).join('') || '<tr><td colspan="4">No URLs detected.</td></tr>';
        }

        // Attachments Table
        const tblAtts = document.getElementById('tbl-atts-body');
        if (tblAtts) {
            const atts = (report.attachment_details && report.attachment_details.analyzed_attachments) ? report.attachment_details.analyzed_attachments : [];
            tblAtts.innerHTML = atts.map(a => `
                <tr>
                    <td>${escapeHtml(a.filename)}</td>
                    <td>${escapeHtml(a.extension)}</td>
                    <td>${a.size} bytes</td>
                    <td><span style="color:${a.risk_level === 'MALICIOUS' ? '#ff5252' : '#00e676'}">${a.risk_level}</span></td>
                </tr>
            `).join('') || '<tr><td colspan="4">No attachments detected.</td></tr>';
        }

        // Headers Text Box
        const codeAuth = document.getElementById('code-auth');
        if (codeAuth) {
            const h = report.header_details || {};
            codeAuth.innerText = `Subject: ${report.subject}\nSender: ${report.sender}\nRecipient: ${report.recipient}\nDate: ${report.date}\n\nSPF Status: ${h.spf_status}\nDKIM Status: ${h.dkim_status}\nDMARC Status: ${h.dmarc_status}\nOriginating IP: ${h.originating_ip}\nReply-To Mismatch: ${h.reply_mismatch}\nReturn-Path Mismatch: ${h.return_mismatch}\nBrand Spoofing: ${h.brand_spoofing}\n\n--- FINDINGS ---\n${(h.findings || []).join('\n')}`;
        }

        // Raw Text Box
        const codeRaw = document.getElementById('code-raw');
        if (codeRaw) {
            codeRaw.innerText = report.parsed_email ? report.parsed_email.combined_body : '';
        }

        if (resultsDrawer) resultsDrawer.classList.add('open');
    }

    if (closeDrawer && resultsDrawer) {
        closeDrawer.addEventListener('click', () => resultsDrawer.classList.remove('open'));
    }

    // Result Tab Switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-tab');
            const pane = document.getElementById(targetId);
            if (pane) pane.classList.add('active');
        });
    });

    // -------------------------------------------------------------
    // HISTORY MODAL & SEARCH
    // -------------------------------------------------------------
    if (btnHistory && historyModal) {
        btnHistory.addEventListener('click', () => {
            historyModal.classList.add('open');
            fetchHistory();
        });
    }

    if (closeHistory && historyModal) {
        closeHistory.addEventListener('click', () => historyModal.classList.remove('open'));
    }

    if (historySearch) {
        historySearch.addEventListener('input', (e) => fetchHistory(e.target.value));
    }

    async function fetchHistory(query = '') {
        try {
            const res = await fetch(`/api/history?q=${encodeURIComponent(query)}`);
            const data = await res.json();
            const tblHistory = document.getElementById('tbl-history-body');

            if (tblHistory && data.scans) {
                tblHistory.innerHTML = data.scans.map(s => `
                    <tr style="cursor:pointer;" onclick='viewScanHistoryReport(${JSON.stringify(s.report_json)})'>
                        <td>${s.id}</td>
                        <td>${s.scan_date}</td>
                        <td>${escapeHtml(s.filename)}</td>
                        <td>${escapeHtml(s.sender)}</td>
                        <td>${escapeHtml(s.subject)}</td>
                        <td><strong style="color:${s.verdict === 'PHISHING' ? '#ff5252' : '#00e676'}">${s.verdict} (${s.risk_score})</strong></td>
                    </tr>
                `).join('') || '<tr><td colspan="6">No scan history found.</td></tr>';
            }
        } catch (e) {
            console.error(e);
        }
    }

    window.viewScanHistoryReport = function(jsonStr) {
        try {
            const report = typeof jsonStr === 'string' ? JSON.parse(jsonStr) : jsonStr;
            if (historyModal) historyModal.classList.remove('open');
            updateDashboardWithReport(report);
            openResultsDrawer(report);
        } catch (e) {
            alert('Failed to parse scan report history.');
        }
    };

    if (btnClearDb) {
        btnClearDb.addEventListener('click', async () => {
            if (confirm('Clear all scan history from local database?')) {
                await fetch('/api/history/clear', { method: 'POST' });
                fetchHistory();
            }
        });
    }

    // -------------------------------------------------------------
    // EXPORT REPORT HANDLER
    // -------------------------------------------------------------
    if (btnExport) {
        btnExport.addEventListener('click', () => {
            const fmt = prompt('Choose export format: html, json, or txt', 'html');
            if (fmt && ['html', 'json', 'txt'].includes(fmt.toLowerCase())) {
                window.open(`/api/export/${fmt.toLowerCase()}`, '_blank');
            }
        });
    }

    function escapeHtml(text) {
        if (!text) return '';
        return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

});
