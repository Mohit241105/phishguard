/**
 * PhishGuard AI — Enterprise SOC Dashboard & Application Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  // Initialize Three.js 3D Cyber Visualizer
  if (window.CyberVisualizer) {
    window.CyberVisualizer.init("cyber-canvas");
  }

  // Navigation Controller
  const navBtns = document.querySelectorAll(".nav-item button");
  const pages = document.querySelectorAll(".page-view");
  const topbarTitle = document.getElementById("topbar-title");

  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const pageTarget = btn.getAttribute("data-page");
      
      // Active states
      document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));
      btn.parentElement.classList.add("active");

      pages.forEach(page => {
        page.classList.remove("active");
        if (page.id === `page-${pageTarget}`) {
          page.classList.add("active");
        }
      });

      if (topbarTitle) {
        const titleMap = {
          dashboard: "SOC Threat Overview",
          analyze: "Email Security Analysis",
          history: "Forensic Scan Archives",
          "threat-intel": "Threat Intelligence & MITRE ATT&CK",
          reports: "Export Security Reports",
          settings: "SOC Engine Settings",
          profile: "Analyst Profile"
        };
        topbarTitle.textContent = titleMap[pageTarget] || "PhishGuard AI";
      }

      if (pageTarget === "dashboard") {
        fetchStats();
        fetchRecentScans();
      } else if (pageTarget === "history") {
        fetchFullHistory();
      }
    });
  });

  // Fetch initial SOC stats
  fetchStats();
  fetchRecentScans();

  // Drag & Drop Handling
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("eml-file-input");

  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("drag-over");
    });

    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("drag-over");
    });

    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag-over");
      if (e.dataTransfer.files.length > 0) {
        uploadAndAnalyze(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files.length > 0) {
        uploadAndAnalyze(fileInput.files[0]);
      }
    });
  }

  // Sample Load Buttons
  const btnSamplePhishing = document.getElementById("btn-sample-phishing");
  const btnSampleSafe = document.getElementById("btn-sample-safe");

  if (btnSamplePhishing) {
    btnSamplePhishing.addEventListener("click", () => analyzeSample("phishing"));
  }
  if (btnSampleSafe) {
    btnSampleSafe.addEventListener("click", () => analyzeSample("safe"));
  }

  // Forensic Result Sub-Tabs
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const tabTarget = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const pane = document.getElementById(`tab-${tabTarget}`);
      if (pane) pane.classList.add("active");
    });
  });

  // Threat Intel Lookup Search Button
  const btnLookup = document.getElementById("btn-intel-lookup");
  if (btnLookup) {
    btnLookup.addEventListener("click", performThreatIntelLookup);
  }
});

// API Helper Functions

async function fetchStats() {
  try {
    const res = await fetch("/api/v1/stats");
    const data = await res.json();

    document.getElementById("stat-analyzed").textContent = data.total_analyzed || 0;
    document.getElementById("stat-threats").textContent = data.threats_detected || 0;
    document.getElementById("stat-high-risk").textContent = data.high_risk_count || 0;
    document.getElementById("stat-ratio").textContent = data.high_risk_ratio || "0%";
  } catch (err) {
    console.error("Failed to fetch SOC stats:", err);
  }
}

async function uploadAndAnalyze(file) {
  const formData = new FormData();
  formData.append("file", file);

  startPipelineAnimation();

  try {
    const res = await fetch("/api/v1/analyze/upload", {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      completePipelineAnimation(data.report);
    } else {
      alert("Analysis failed: " + (data.error || "Unknown error"));
      stopPipelineAnimation();
    }
  } catch (err) {
    console.error("Upload error:", err);
    alert("Server error during email analysis.");
    stopPipelineAnimation();
  }
}

async function analyzeSample(sampleType) {
  startPipelineAnimation();

  try {
    const res = await fetch(`/api/v1/analyze/sample/${sampleType}`, {
      method: "POST"
    });
    const data = await res.json();
    if (data.success) {
      completePipelineAnimation(data.report);
    } else {
      alert("Sample analysis failed: " + (data.error || "Unknown error"));
      stopPipelineAnimation();
    }
  } catch (err) {
    console.error("Sample analysis error:", err);
    alert("Server error during sample analysis.");
    stopPipelineAnimation();
  }
}

// Interactive Pipeline Step Animation

function startPipelineAnimation() {
  if (window.CyberVisualizer) {
    window.CyberVisualizer.triggerScan(true);
  }

  const steps = ["step-ingest", "step-parser", "step-header", "step-url", "step-attachment", "step-nlp", "step-ml", "step-hybrid", "step-verdict"];
  steps.forEach(s => {
    const el = document.getElementById(s);
    if (el) {
      el.classList.remove("completed", "active");
    }
  });

  let index = 0;
  const interval = setInterval(() => {
    if (index < steps.length - 1) {
      if (index > 0) {
        document.getElementById(steps[index - 1]).classList.remove("active");
        document.getElementById(steps[index - 1]).classList.add("completed");
      }
      document.getElementById(steps[index]).classList.add("active");
      index++;
    } else {
      clearInterval(interval);
    }
  }, 200);
}

function stopPipelineAnimation() {
  if (window.CyberVisualizer) {
    window.CyberVisualizer.triggerScan(false);
  }
}

function completePipelineAnimation(report) {
  stopPipelineAnimation();

  const steps = ["step-ingest", "step-parser", "step-header", "step-url", "step-attachment", "step-nlp", "step-ml", "step-hybrid", "step-verdict"];
  steps.forEach(s => {
    const el = document.getElementById(s);
    if (el) {
      el.classList.remove("active");
      el.classList.add("completed");
    }
  });

  setTimeout(() => {
    renderReportResults(report);
  }, 400);
}

// Render Results Dashboard

function renderReportResults(report) {
  const resultsContainer = document.getElementById("results-container");
  if (!resultsContainer) return;

  resultsContainer.style.display = "block";
  resultsContainer.scrollIntoView({ behavior: "smooth" });

  // 1. Gauge & Verdict
  const score = report.final_risk_score || 0;
  const verdict = report.verdict || "SAFE";
  
  document.getElementById("res-score-num").textContent = score;

  const circleVal = document.getElementById("circle-val-path");
  if (circleVal) {
    // 377 is circumference
    const offset = 377 - (377 * score / 100);
    circleVal.style.strokeDashoffset = offset;

    if (verdict === "PHISHING") {
      circleVal.style.stroke = "#ef4444";
    } else if (verdict === "SUSPICIOUS") {
      circleVal.style.stroke = "#f59e0b";
    } else {
      circleVal.style.stroke = "#22c55e";
    }
  }

  const badgeEl = document.getElementById("res-verdict-badge");
  if (badgeEl) {
    badgeEl.textContent = verdict;
    badgeEl.className = "verdict-badge " + (
      verdict === "PHISHING" ? "badge-phishing" :
      verdict === "SUSPICIOUS" ? "badge-suspicious" : "badge-safe"
    );
  }

  // 2. Explainable AI Reasons
  const xaiList = document.getElementById("res-xai-list");
  if (xaiList) {
    xaiList.innerHTML = "";
    (report.explanations || []).forEach(exp => {
      const li = document.createElement("li");
      li.className = "xai-item";
      li.innerHTML = `<span style="color: var(--accent-cyan);">🛡️</span> <span>${exp}</span>`;
      xaiList.appendChild(li);
    });
  }

  // 3. Header Analysis Pane
  const h = report.header_details || {};
  document.getElementById("val-spf").innerHTML = getBadgeHTML(h.spf_status);
  document.getElementById("val-dkim").innerHTML = getBadgeHTML(h.dkim_status);
  document.getElementById("val-dmarc").innerHTML = getBadgeHTML(h.dmarc_status);
  document.getElementById("val-sender").textContent = report.sender || "-";
  document.getElementById("val-origin-ip").textContent = h.originating_ip || "Unknown";

  // 4. URL Security Matrix
  const urlTable = document.getElementById("tbl-urls-body");
  if (urlTable) {
    urlTable.innerHTML = "";
    const urls = (report.url_details || {}).urls || [];
    if (urls.length === 0) {
      urlTable.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-dim);">No external URLs detected in body.</td></tr>`;
    } else {
      urls.forEach(u => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td class="mono">${u.url}</td>
          <td><span class="mono">${u.domain}</span></td>
          <td><span class="badge ${u.risk_level === 'DANGEROUS' ? 'badge-fail' : u.risk_level === 'SUSPICIOUS' ? 'badge-warn' : 'badge-pass'}">${u.risk_level}</span></td>
          <td>${(u.flags || []).join("; ") || "Clean"}</td>
        `;
        urlTable.appendChild(row);
      });
    }
  }

  // 5. Attachment Sandbox Pane
  const attTable = document.getElementById("tbl-att-body");
  if (attTable) {
    attTable.innerHTML = "";
    const atts = (report.attachment_details || {}).analyzed_attachments || [];
    if (atts.length === 0) {
      attTable.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-dim);">No file attachments present.</td></tr>`;
    } else {
      atts.forEach(a => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td><strong>${a.filename}</strong></td>
          <td class="mono">${a.sha256 ? a.sha256.substring(0, 16) + '...' : '-'}</td>
          <td><span class="badge ${a.risk_level === 'MALICIOUS' ? 'badge-fail' : a.risk_level === 'SUSPICIOUS' ? 'badge-warn' : 'badge-pass'}">${a.risk_level}</span></td>
          <td>${(a.flags || []).join("; ") || "No warnings"}</td>
        `;
        attTable.appendChild(row);
      });
    }
  }

  // 6. NLP Tactic Keywords Pane
  const nlpBox = document.getElementById("nlp-findings-box");
  if (nlpBox) {
    const findings = (report.nlp_details || {}).findings || [];
    if (findings.length === 0) {
      nlpBox.innerHTML = `<p style="color: var(--status-safe);">✔ No social engineering or high-pressure keyword patterns detected.</p>`;
    } else {
      nlpBox.innerHTML = findings.map(f => `<p style="margin-bottom: 0.5rem;"><span class="nlp-tag">⚠️ Tactic</span> ${f}</p>`).join("");
    }
  }

  // 7. ML Classifier Pane
  const ml = report.ml_details || {};
  document.getElementById("ml-classification").textContent = ml.classification || "SAFE";
  document.getElementById("ml-confidence").textContent = `${ml.confidence || 0}%`;
  document.getElementById("ml-phishing-prob").textContent = `${ml.phishing_probability || 0}%`;

  // 8. MITRE ATT&CK & IOC Matrix Pane
  const mitreList = document.getElementById("mitre-techniques-list");
  if (mitreList) {
    mitreList.innerHTML = "";
    const techniques = (report.threat_intel || {}).mitre_techniques || [];
    if (techniques.length === 0) {
      mitreList.innerHTML = `<p style="color: var(--text-dim);">No MITRE ATT&CK techniques associated with this message.</p>`;
    } else {
      techniques.forEach(t => {
        const card = document.createElement("div");
        card.style.cssText = "background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 0.85rem; margin-bottom: 0.75rem;";
        card.innerHTML = `
          <div style="display: flex; align-items: center; justify-content: space-between;">
            <strong style="color: var(--accent-cyan);">${t.name}</strong>
            <span class="badge badge-warn">${t.tactics.join(", ")}</span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.3rem;">${t.description}</p>
        `;
        mitreList.appendChild(card);
      });
    }
  }
}

function getBadgeHTML(status) {
  if (status === "PASS") return `<span class="badge badge-pass">PASS</span>`;
  if (status === "FAIL") return `<span class="badge badge-fail">FAIL</span>`;
  return `<span class="badge badge-warn">${status || "UNKNOWN"}</span>`;
}

// Fetch History Functions

async function fetchRecentScans() {
  try {
    const res = await fetch("/api/v1/history");
    const data = await res.json();
    const scans = data.scans || [];

    const tableBody = document.getElementById("tbl-recent-scans-body");
    if (!tableBody) return;

    tableBody.innerHTML = "";

    if (scans.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim);">No email scans logged yet.</td></tr>`;
      return;
    }

    scans.slice(0, 5).forEach(s => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="mono">${s.timestamp || s.scan_timestamp || '-'}</td>
        <td><strong>${s.subject || 'Untitled'}</strong></td>
        <td>${s.sender || '-'}</td>
        <td><span class="badge ${s.verdict === 'PHISHING' ? 'badge-fail' : s.verdict === 'SUSPICIOUS' ? 'badge-warn' : 'badge-pass'}">${s.verdict}</span></td>
        <td><strong>${s.risk_score || s.final_risk_score || 0}</strong> / 100</td>
      `;
      tableBody.appendChild(row);
    });
  } catch (err) {
    console.error("Failed to fetch scan history:", err);
  }
}

async function fetchFullHistory() {
  try {
    const res = await fetch("/api/v1/history");
    const data = await res.json();
    const scans = data.scans || [];

    const tableBody = document.getElementById("tbl-full-history-body");
    if (!tableBody) return;

    tableBody.innerHTML = "";

    if (scans.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No historical scans recorded.</td></tr>`;
      return;
    }

    scans.forEach(s => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="mono">${s.id || '-'}</td>
        <td class="mono">${s.timestamp || s.scan_timestamp || '-'}</td>
        <td><strong>${s.subject || 'Untitled'}</strong></td>
        <td>${s.sender || '-'}</td>
        <td><span class="badge ${s.verdict === 'PHISHING' ? 'badge-fail' : s.verdict === 'SUSPICIOUS' ? 'badge-warn' : 'badge-pass'}">${s.verdict}</span></td>
        <td><strong>${s.risk_score || s.final_risk_score || 0}</strong></td>
      `;
      tableBody.appendChild(row);
    });
  } catch (err) {
    console.error("Failed to fetch full history:", err);
  }
}

async function performThreatIntelLookup() {
  const indicator = document.getElementById("intel-input").value.trim();
  const iocType = document.getElementById("intel-type-select").value;

  if (!indicator) return alert("Please enter an IP, domain, URL, or hash indicator.");

  try {
    const res = await fetch("/api/v1/threat-intel/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ indicator: indicator, ioc_type: iocType })
    });
    const data = await res.json();

    const outputBox = document.getElementById("intel-results-box");
    if (outputBox) {
      outputBox.innerHTML = `
        <pre class="mono" style="background: rgba(0,0,0,0.5); padding: 1rem; border-radius: 8px; border: 1px solid var(--border-color); color: var(--accent-cyan);">${JSON.stringify(data.data, null, 2)}</pre>
      `;
    }
  } catch (err) {
    console.error("Threat intel lookup error:", err);
  }
}
