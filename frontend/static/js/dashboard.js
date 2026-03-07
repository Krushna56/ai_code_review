/**
 * Premium Code Review Dashboard — v2.0
 * Handles all chart renders, API calls, and UI interactions
 */

// ─── Global chart references ───────────────────────────────────────────────
let chartDonut, chartTimeline, chartCreatedResolved, chartHotspots;
let chartDonutDestroyed = false;

// ─── CHART.JS DEFAULTS ────────────────────────────────────────────────────
Chart.defaults.color = "#8891aa";
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

// ─── MAIN LOAD ────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const uid =
      new URLSearchParams(window.location.search).get("uid") ||
      document.body.getAttribute("data-uid") ||
      null;
    await Promise.all([
      loadMetrics(uid),
      loadCharts(uid),
      loadRecentReviews(uid),
    ]);
  } catch (err) {
    console.error("Dashboard load error:", err);
  }
}

// ─── METRICS ──────────────────────────────────────────────────────────────
async function loadMetrics(uid) {
  try {
    let url = "/api/security/summary";
    if (uid) url += `?uid=${uid}`;
    const res = await fetch(url);
    const d = await res.json();

    setText("lastUpdated", formatTimeAgo(d.last_scan));
    setText("statTotalIssues", d.total_findings ?? 0);
    setText("statCritical", d.critical_count ?? 0);
    setText("statDebt", calcDebtHours(d) + " h");
    setText("statRating", (d.security_rating ?? 0) + "/10");
    setText("statFiles", d.total_files ?? 0);
    setText("statAI", (d.ai_code_percent ?? 0) + "%");
    setText("statDepVuln", d.cve_count ?? 0);
    setText("statDefectDensity", calcDefectDensity(d));

    // badge
    const crit = d.critical_count ?? 0;
    const badge = document.getElementById("statCriticalBadge");
    if (badge && crit > 0) {
      badge.style.display = "inline";
      badge.textContent = crit;
    }

    // Bottom pills
    const sd = d.severity_distribution || {};
    setText("pillCritical", sd.CRITICAL ?? 0);
    setText("pillHigh", sd.HIGH ?? 0);
    setText("pillMedium", sd.MEDIUM ?? 0);
    setText("pillLow", sd.LOW ?? 0);
    setText("pillInfo", sd.INFO ?? 0);

    // Draw gauges
    const qualityNorm = normScore(d.security_rating);
    const securityNorm = normScore(d.security_rating, true);
    drawGauge("gaugeQuality", qualityNorm, scoreColor(d.security_rating));
    drawGauge(
      "gaugeSecurity",
      securityNorm,
      scoreColor(d.security_rating, true),
    );

    // Grade + score labels
    const qScore = Math.round(qualityNorm * 100);
    const sScore = Math.round(securityNorm * 100);
    setText("qualityGrade", scoreGrade(d.security_rating));
    setText("qualityScore", qScore);
    setText("securityGrade", scoreGrade(d.security_rating, true));
    setText("securityScore", sScore);
  } catch (e) {
    console.error("Metrics error:", e);
  }
}

// ─── SAFE JSON HELPER ─────────────────────────────────────────────────────
/** Safely parse a fetch Response as JSON. Returns null if server sends HTML (e.g. 404). */
async function safeJson(res) {
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return null;
  try {
    return await res.json();
  } catch {
    return null;
  }
}

// ─── CHARTS ───────────────────────────────────────────────────────────────
async function loadCharts(uid) {
  try {
    const chartsUrl = `/api/security/charts${uid ? "?uid=" + uid : ""}`;
    const timelineUrl = `/api/git/timeline${uid ? "?uid=" + uid : ""}`;

    const [chartsRes, timelineRes] = await Promise.all([
      fetch(chartsUrl),
      fetch(timelineUrl),
    ]);

    const data = (await safeJson(chartsRes)) || {};
    const timeline = await safeJson(timelineRes); // null if endpoint not ready yet

    // Use real git timeline when available; otherwise fall back to charts data
    const trendData =
      timeline && timeline.labels && timeline.labels.length > 0
        ? timeline
        : data.vulnerability_trends || null;

    renderDonut(data.severity_distribution, data.severity_counts);
    renderTimeline(trendData);
    renderCreatedResolved(trendData);
    renderHotspots(data.file_risk_scores);
    renderIssuesByType(data.issue_type_distribution, data.severity_counts);
    renderMiniRiskyFiles(data.file_risk_scores);
    renderRiskyFilesTable(data.file_risk_scores);
    renderVulnTypeTable(data.owasp_coverage);

    // Show data source badge on timeline cards
    _applyTimelineBadge(trendData);
  } catch (e) {
    console.error("Charts error:", e);
  }
}

/** Show a small colored badge indicating data source (git vs estimated) */
function _applyTimelineBadge(trendData) {
  const isGit = trendData?.has_git === true || trendData?.source === "git";
  const badge = isGit
    ? '<span style="color:#22c55e;font-size:0.6rem;margin-left:6px">● live git data</span>'
    : '<span style="color:#6b7280;font-size:0.6rem;margin-left:6px">● estimated</span>';

  // Attach to any subtitle that mentions days
  document.querySelectorAll(".card-subtitle").forEach((el) => {
    if (
      (el.textContent.includes("30 days") ||
        el.textContent.includes("72 days")) &&
      !el.querySelector("span")
    ) {
      el.innerHTML += badge;
    }
  });
}

// ─── DONUT CHART ──────────────────────────────────────────────────────────
function renderDonut(severityData) {
  const ctx = document.getElementById("chartDonut");
  if (!ctx) return;
  if (chartDonut) {
    chartDonut.destroy();
  }

  const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const COLORS = ["#f03e3e", "#ff6b35", "#fcc419", "#51cf66", "#339af0"];
  const counts = {};

  if (severityData?.labels && severityData?.datasets) {
    severityData.labels.forEach((l, i) => {
      counts[l] = severityData.datasets[0].data[i] || 0;
    });
  } else if (severityData && typeof severityData === "object") {
    Object.assign(counts, severityData);
  }

  const total = SEVS.reduce((s, k) => s + (counts[k] || 0), 0);
  const data = SEVS.map((k) => counts[k] || 0);
  const health =
    total > 0
      ? Math.max(
          0,
          Math.round(
            100 -
              (((counts.CRITICAL || 0) * 10 +
                (counts.HIGH || 0) * 4 +
                (counts.MEDIUM || 0) * 1.5) /
                Math.max(total, 1)) *
                30,
          ),
        )
      : 100;

  setText("donutPct", health + "%");

  // Legend
  SEVS.forEach((sev, i) => {
    const pct = total ? Math.round((data[i] / total) * 1000) / 10 : 0;
    setText("pct" + cap(sev), pct + "%");
    setText("cnt" + cap(sev), data[i]);
  });

  chartDonut = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: SEVS,
      datasets: [
        {
          data,
          backgroundColor: COLORS,
          borderWidth: 2,
          borderColor: "#1f2333",
          hoverOffset: 6,
        },
      ],
    },
    options: {
      cutout: "72%",
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (c) =>
              ` ${c.label}: ${c.raw} (${total ? Math.round((c.raw / total) * 100) : 0}%)`,
          },
        },
      },
    },
  });
}

// ─── TIMELINE LINE CHART ──────────────────────────────────────────────────
/**
 * Renders the "Issues Over Time" line chart.
 * Accepts either:
 *   - Git timeline format: { labels, new_issues, resolved_issues, has_git }
 *   - Legacy chart.js format: { labels, datasets }
 */
function renderTimeline(trendData) {
  const ctx = document.getElementById("chartTimeline");
  if (!ctx) return;
  if (chartTimeline) {
    chartTimeline.destroy();
  }

  let labels, newData, resolvedData;

  // ── Git timeline format (new API) ──
  if (trendData?.new_issues !== undefined) {
    labels = trendData.labels || genDateLabels(30, 1);
    newData = trendData.new_issues || [];
    resolvedData = trendData.resolved_issues || [];
  } else {
    // ── Legacy chart.js dataset format ──
    labels = trendData?.labels || genDateLabels(30, 2);
    const datasets = trendData?.datasets || [];
    const dsNew =
      datasets.find((d) => d.label === "HIGH" || d.label === "New") ||
      datasets[0];
    const dsRes =
      datasets.find((d) => d.label === "LOW" || d.label === "Resolved") ||
      datasets[1];
    newData =
      dsNew?.data || Array.from({ length: labels.length }, () => rnd(30, 90));
    resolvedData =
      dsRes?.data || Array.from({ length: labels.length }, () => rnd(20, 70));
  }

  chartTimeline = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "New",
          data: newData,
          borderColor: "#ff6b35",
          backgroundColor: "rgba(255,107,53,0.08)",
          borderWidth: 2,
          tension: 0.4,
          pointRadius: 3,
          pointBackgroundColor: "#ff6b35",
          fill: true,
        },
        {
          label: "Resolved",
          data: resolvedData,
          borderColor: "#20c997",
          backgroundColor: "rgba(32,201,151,0.06)",
          borderWidth: 2,
          borderDash: [5, 3],
          tension: 0.4,
          pointRadius: 3,
          pointBackgroundColor: "#20c997",
          fill: false,
        },
      ],
    },
    options: chartLineOpts("Issues Over Time"),
  });
}

// ─── CREATED vs RESOLVED BAR CHART ────────────────────────────────────────
/**
 * Renders the "Created vs Resolved Issues" bar chart.
 * Uses real git timeline data (new/resolved per day) when available.
 */
function renderCreatedResolved(trendData) {
  const ctx = document.getElementById("chartCreatedResolved");
  if (!ctx) return;
  if (chartCreatedResolved) {
    chartCreatedResolved.destroy();
  }

  let labels, created, resolved;

  // ── Git timeline format ──
  if (trendData?.new_issues !== undefined) {
    const raw = trendData.labels || [];
    // Sample every 6 labels for the bar chart to avoid crowding
    const step = Math.max(1, Math.floor(raw.length / 12));
    const idxs = Array.from(
      { length: Math.ceil(raw.length / step) },
      (_, i) => i * step,
    ).filter((i) => i < raw.length);
    labels = idxs.map((i) => raw[i]);
    created = idxs.map((i) => trendData.new_issues[i] || 0);
    resolved = idxs.map((i) => trendData.resolved_issues[i] || 0);
  } else {
    // ── Legacy fallback ──
    const count = 12;
    labels = genDateLabels(72, 6);
    created = Array.from({ length: count }, () => rnd(30, 90));
    resolved = Array.from({ length: count }, () => rnd(20, 70));
  }

  const movAvg = movingAverage(
    created.map((c, i) => (c + resolved[i]) / 2),
    3,
  );

  chartCreatedResolved = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Created",
          data: created,
          backgroundColor: "rgba(255,107,53,0.75)",
          borderRadius: 3,
        },
        {
          label: "Resolved",
          data: resolved,
          backgroundColor: "rgba(32,201,151,0.75)",
          borderRadius: 3,
        },
        {
          label: "Moving Avg",
          type: "line",
          data: movAvg,
          borderColor: "#6384ff",
          borderWidth: 2,
          tension: 0.4,
          pointRadius: 0,
          fill: false,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          grid: { color: "rgba(255,255,255,0.04)" },
          ticks: { maxTicksLimit: 8 },
        },
        y: { grid: { color: "rgba(255,255,255,0.04)" }, beginAtZero: true },
      },
    },
  });
}

// ─── HOTSPOTS SCATTER ─────────────────────────────────────────────────────
function renderHotspots(fileRiskData) {
  const ctx = document.getElementById("chartHotspots");
  if (!ctx) return;
  if (chartHotspots) {
    chartHotspots.destroy();
  }

  let points = [];
  let labels = [];

  if (fileRiskData?.labels && fileRiskData.datasets?.length >= 2) {
    const files = fileRiskData.labels;
    const riskScores = fileRiskData.datasets[0].data;
    const counts = fileRiskData.datasets[1].data;

    files.forEach((f, i) => {
      points.push({
        x: rnd(20, 130),
        y: rnd(30, 90),
        r: Math.max(5, Math.min(25, (riskScores[i] || 5) / 4)),
      });
      labels.push(f);
    });
    setText("hotspotsSubtitle", files.length + " Hotspot Files");
  } else {
    // No real data available
    setText("hotspotsSubtitle", "No data — run analysis first");
    return;
  }

  const BUBBLE_COLORS = ["#f03e3e", "#ff6b35", "#fcc419", "#6384ff", "#20c997"];

  chartHotspots = new Chart(ctx, {
    type: "bubble",
    data: {
      datasets: points.map((p, i) => ({
        label: labels[i] || `File ${i + 1}`,
        data: [p],
        backgroundColor: BUBBLE_COLORS[i % BUBBLE_COLORS.length] + "99",
        borderColor: BUBBLE_COLORS[i % BUBBLE_COLORS.length],
        borderWidth: 1.5,
      })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}` } },
      },
      scales: {
        x: {
          title: {
            display: true,
            text: "Weekly Churn",
            color: "#4a5270",
            font: { size: 10 },
          },
          grid: { color: "rgba(255,255,255,0.04)" },
        },
        y: {
          title: {
            display: true,
            text: "Weekly Churn",
            color: "#4a5270",
            font: { size: 10 },
          },
          grid: { color: "rgba(255,255,255,0.04)" },
        },
      },
    },
  });
}

// ─── ISSUES BY TYPE BARS ──────────────────────────────────────────────────
function renderIssuesByType(typeData, severityCounts) {
  // Use new backend issue_type_distribution if available
  if (typeData?.counts) {
    const c = typeData.counts;
    const max = Math.max(...Object.values(c), 1);
    const total = Object.values(c).reduce((a, b) => a + b, 0);
    setBar("typeBarBugs", c["Bugs"] || 0, max);
    setText("typeValBugs", pctStr(c["Bugs"] || 0, total));
    setBar("typeBarVuln", c["Vulnerabilities"] || 0, max);
    setText("typeValVuln", pctStr(c["Vulnerabilities"] || 0, total));
    setBar("typeBarSmell", c["Code Smells"] || 0, max);
    setText("typeValSmell", pctStr(c["Code Smells"] || 0, total));
    setBar("typeBarPerf", c["Performance"] || 0, max);
    setText("typeValPerf", pctStr(c["Performance"] || 0, total));
    return;
  }

  // Derive from severity counts if available
  const sd = severityCounts || {};
  let crit = 0,
    high = 0,
    med = 0,
    low = 0,
    total = 0;
  if (sd.labels && sd.datasets) {
    sd.labels.forEach((l, i) => {
      const v = sd.datasets[0].data[i] || 0;
      total += v;
      if (l === "CRITICAL") crit = v;
      if (l === "HIGH") high = v;
      if (l === "MEDIUM") med = v;
      if (l === "LOW") low = v;
    });
  } else {
    crit = sd.CRITICAL || 0;
    high = sd.HIGH || 0;
    med = sd.MEDIUM || 0;
    low = sd.LOW || 0;
    total = crit + high + med + low;
  }

  if (total === 0) {
    // No real data — show zeros
    setBar("typeBarBugs", 0, 1);
    setText("typeValBugs", "0%");
    setBar("typeBarVuln", 0, 1);
    setText("typeValVuln", "0%");
    setBar("typeBarSmell", 0, 1);
    setText("typeValSmell", "0%");
    setBar("typeBarPerf", 0, 1);
    setText("typeValPerf", "0%");
    return;
  }

  const bugs = crit + high,
    vuln = crit,
    smell = med,
    perf = low;
  const tMax = Math.max(bugs, vuln, smell, perf, 1);
  setBar("typeBarBugs", bugs, tMax);
  setText("typeValBugs", pctStr(bugs, total));
  setBar("typeBarVuln", vuln, tMax);
  setText("typeValVuln", pctStr(vuln, total));
  setBar("typeBarSmell", smell, tMax);
  setText("typeValSmell", pctStr(smell, total));
  setBar("typeBarPerf", perf, tMax);
  setText("typeValPerf", pctStr(perf, total));
}

// ─── MINI RISKY FILES ─────────────────────────────────────────────────────
function renderMiniRiskyFiles(fileRiskData) {
  const container = document.getElementById("miniRiskyFiles");
  if (!container) return;

  const files = fileRiskData?.labels || [];
  const scores = fileRiskData?.datasets?.[0]?.data || [];

  if (!files.length) {
    container.innerHTML =
      '<li style="color:var(--text-dim);font-size:0.7rem;padding:4px 0">No data — run analysis first</li>';
    return;
  }

  const maxS = Math.max(...scores, 1);

  container.innerHTML = files
    .slice(0, 5)
    .map((f, i) => {
      const s = Math.round(scores[i] || 0);
      return `<li class="barlist-item">
      <span class="barlist-label" title="${escapeHtml(f)}">${escapeHtml(f.split("/").pop())}</span>
      <div class="barlist-track"><div class="barlist-fill" style="background:var(--c-high);width:${Math.round((s / maxS) * 100)}%"></div></div>
      <span class="barlist-val">${s}</span>
    </li>`;
    })
    .join("");
}

// ─── RISKY FILES TABLE ────────────────────────────────────────────────────
function renderRiskyFilesTable(fileRiskData) {
  const tbody = document.getElementById("riskyFilesTbody");
  if (!tbody) return;

  const files = fileRiskData?.labels || [];
  const scores = fileRiskData?.datasets?.[0]?.data || [];
  const counts = fileRiskData?.datasets?.[1]?.data || [];
  const maxS = Math.max(...scores, 1);
  const COLORS = ["#f03e3e", "#ff6b35", "#fcc419", "#6384ff", "#20c997"];

  if (!files.length) {
    tbody.innerHTML =
      '<tr><td colspan="3" class="loading">No file data available</td></tr>';
    return;
  }

  tbody.innerHTML = files
    .slice(0, 5)
    .map((f, i) => {
      const s = +(scores[i] || 0).toFixed(1);
      const c = counts[i] || 0;
      const pA = Math.round((s / maxS) * 100);
      const pB = Math.round((c / Math.max(...counts, 1)) * 100);
      const col = COLORS[i % COLORS.length];
      return `<tr>
      <td style="font-size:0.72rem;color:var(--text-secondary)">${escapeHtml(f.split("/").pop())}</td>
      <td>
        <div class="mini-bar-wrap">
          <div class="mini-bar" style="width:${pA}%;background:${col};height:7px;border-radius:2px"></div>
          <span style="font-size:0.65rem;color:var(--text-muted);margin-left:3px">${s}</span>
          <div class="mini-bar" style="width:${pB}%;background:rgba(32,201,151,0.6);height:7px;border-radius:2px;margin-left:3px"></div>
          <span style="font-size:0.65rem;color:var(--text-muted);margin-left:3px">${c}</span>
        </div>
      </td>
      <td class="td-right">${(s + c / 2).toFixed(1)}</td>
    </tr>`;
    })
    .join("");
}

// ─── VULNS BY TYPE TABLE ──────────────────────────────────────────────────
function renderVulnTypeTable(owaspData) {
  const tbody = document.getElementById("vulnTypeTbody");
  if (!tbody) return;

  const labels = owaspData?.labels || [];
  const data = owaspData?.datasets?.[0]?.data || [];
  const COLORS = ["#f03e3e", "#ff6b35", "#fcc419", "#6384ff", "#20c997"];
  const maxVal = Math.max(...data, 1);

  if (!labels.length) {
    tbody.innerHTML =
      '<tr><td colspan="3" class="loading">No data — run analysis first</td></tr>';
    return;
  }

  tbody.innerHTML = labels
    .slice(0, 5)
    .map((label, i) => {
      const val = data[i] || 0;
      const p = Math.round((val / maxVal) * 100);
      const col = COLORS[i % COLORS.length];
      return `<tr>
      <td style="color:var(--text-secondary);font-size:0.72rem" title="${escapeHtml(label)}">${escapeHtml(label.length > 24 ? label.slice(0, 24) + "…" : label)}</td>
      <td>
        <div class="mini-bar-wrap">
          <div class="mini-bar" style="width:${p}%;background:${col};height:7px;border-radius:2px"></div>
          <div class="mini-bar" style="width:${Math.round(p * 0.6)}%;background:rgba(32,201,151,0.5);height:7px;border-radius:2px;margin-left:2px"></div>
        </div>
      </td>
      <td class="td-right">${val}</td>
    </tr>`;
    })
    .join("");
}

// ─── GAUGES (canvas-based semi-circle) ────────────────────────────────────
function drawGauge(canvasId, norm, color) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width,
    H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const cx = W / 2,
    cy = H - 4;
  const r = Math.min(cx, cy) - 5;
  const startAngle = Math.PI;
  const endAngle = 2 * Math.PI;
  const fillAngle = startAngle + (endAngle - startAngle) * Math.min(norm, 1);

  // Track
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, endAngle);
  ctx.strokeStyle = "rgba(255,255,255,0.08)";
  ctx.lineWidth = 9;
  ctx.lineCap = "round";
  ctx.stroke();

  // Fill gradient
  const grad = ctx.createLinearGradient(0, 0, W, 0);
  grad.addColorStop(0, "#f03e3e");
  grad.addColorStop(0.45, "#fcc419");
  grad.addColorStop(1, color || "#20c997");
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, fillAngle);
  ctx.strokeStyle = grad;
  ctx.lineWidth = 9;
  ctx.lineCap = "round";
  ctx.stroke();
}

// ─── RECENT FINDINGS TABLE ─────────────────────────────────────────────────
async function loadRecentReviews(uid) {
  const tbody = document.getElementById("reviewsTableBody");
  try {
    let url = "/api/security/findings?limit=50";
    if (uid) url += `&uid=${uid}`;
    const res = await fetch(url);
    const data = await res.json();
    if (!tbody) return;

    if (!data.findings?.length) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="loading">✅ No security threats detected</td></tr>';
      return;
    }

    tbody.innerHTML = data.findings
      .map((f) => {
        const fileParts = (f.file_path || "Unknown").replace(/\\/g, "/");
        const shortFile = fileParts.split("/").slice(-2).join("/");
        const lineNum = f.line_number ? `:${f.line_number}` : "";
        const srcRef = `<code class="source-ref" title="${escapeHtml(fileParts)}">${escapeHtml(shortFile)}${lineNum}</code>`;
        const owaspBadge = f.owasp_name
          ? `<span class="owasp-badge" title="${escapeHtml(f.owasp_category || "")}">${escapeHtml(f.owasp_name)}</span>`
          : "";
        const cweBadges = (f.cwe_ids || [])
          .map((c) => `<span class="cwe-badge">${escapeHtml(c)}</span>`)
          .join(" ");
        const rawDesc = f.description || f.ai_description || "No description";
        const shortDesc =
          rawDesc.split("\n")[0].substring(0, 100) +
          (rawDesc.length > 100 ? "…" : "");
        const sev = (f.severity || "unknown").toLowerCase();

        return `<tr class="theft-row severity-row-${sev}">
        <td class="threat-type-cell">
          <span class="threat-icon">${getThreatIcon(f.type)}</span>
          <span class="threat-label">${escapeHtml(cleanThreatTitle(f.title, f.type))}</span>
        </td>
        <td class="source-cell">${srcRef}</td>
        <td><span class="badge badge-${sev}">${f.severity || "UNKNOWN"}</span></td>
        <td class="description-cell">${escapeHtml(shortDesc)}</td>
        <td class="owasp-cell">${owaspBadge}${cweBadges}</td>
        <td><button onclick="viewFinding('${f.id || f.cve_id}')" class="btn-view">🔍 View</button></td>
      </tr>`;
      })
      .join("");
  } catch (e) {
    console.error("Findings error:", e);
    if (tbody)
      tbody.innerHTML =
        '<tr><td colspan="6" class="loading">⚠️ Error loading findings</td></tr>';
  }
}

// ─── VIEW FINDING MODAL ───────────────────────────────────────────────────
async function viewFinding(findingId) {
  try {
    const uid = new URLSearchParams(window.location.search).get("uid");
    let url = `/api/security/finding/${findingId}`;
    if (uid) url += `?uid=${uid}`;
    const res = await fetch(url);
    const finding = await res.json();
    if (finding.error) {
      alert("Finding not found");
      return;
    }

    document.getElementById("modalBody").innerHTML = `
      <h2 style="margin-bottom:12px;font-size:1.1rem">${escapeHtml(finding.title || finding.summary)}</h2>
      <div class="finding-details">
        <div class="detail-row"><strong>ID</strong><code>${escapeHtml(finding.id || finding.cve_id)}</code></div>
        <div class="detail-row"><strong>Severity</strong><span class="badge badge-${(finding.severity || "unknown").toLowerCase()}">${finding.severity}</span></div>
        ${finding.file_path ? `<div class="detail-row"><strong>File</strong><code>${escapeHtml(finding.file_path)}:${finding.line_number || 0}</code></div>` : ""}
        ${finding.description ? `<div class="detail-row"><strong>Description</strong><p style="white-space:pre-wrap;line-height:1.6;font-size:0.82rem;color:var(--text-secondary)">${escapeHtml(finding.description)}</p></div>` : ""}
      </div>`;
    document.getElementById("findingModal").style.display = "block";
  } catch (e) {
    console.error(e);
    alert("Error loading finding details");
  }
}

// ─── REFRESH ──────────────────────────────────────────────────────────────
async function refreshDashboard() {
  showToast("Refreshing dashboard…");
  try {
    const res = await fetch("/api/security/refresh");
    if (res.ok) {
      await loadDashboard();
      showToast("Dashboard refreshed! ✅");
    } else {
      showToast("Refresh failed");
    }
  } catch (e) {
    showToast("Refresh error");
  }
}

// ─── HELPERS ──────────────────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function setBar(id, val, max) {
  const el = document.getElementById(id);
  if (el) el.style.width = Math.round((val / Math.max(max, 1)) * 100) + "%";
}
function cap(str) {
  return str.charAt(0) + str.slice(1).toLowerCase();
}
function rnd(a, b) {
  return Math.floor(Math.random() * (b - a + 1)) + a;
}
function pctStr(val, total) {
  return (total ? Math.round((val / total) * 100) : 0) + "%";
}
function escapeHtml(text) {
  if (!text) return "";
  const d = document.createElement("div");
  d.textContent = text;
  return d.innerHTML;
}

function normScore(rating, boost = false) {
  const r = +(rating || 0);
  return Math.min(1, (boost ? r * 1.05 : r) / 10);
}
function scoreColor(rating, boost = false) {
  const n = normScore(rating, boost);
  if (n >= 0.8) return "#20c997";
  if (n >= 0.5) return "#fcc419";
  return "#f03e3e";
}
function scoreGrade(rating, boost = false) {
  const n = normScore(rating, boost);
  if (n >= 0.9) return "A+";
  if (n >= 0.8) return "A";
  if (n >= 0.7) return "B";
  if (n >= 0.6) return "C";
  if (n >= 0.5) return "D";
  return "F";
}

function calcDebtHours(d) {
  const h =
    (d.critical_count || 0) * 8 +
    (d.high_count || 0) * 3 +
    (d.total_findings || 0) * 0.5;
  return Math.round(h);
}
function calcDefectDensity(d) {
  const f = d.total_findings || 0;
  const fl = Math.max(d.total_files || 1, 1);
  return ((f / fl) * 10).toFixed(1);
}

function formatTimeAgo(dateStr) {
  if (!dateStr) return "just now";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hour${hrs > 1 ? "s" : ""} ago`;
  return `${Math.floor(hrs / 24)} day${Math.floor(hrs / 24) > 1 ? "s" : ""} ago`;
}

function genDateLabels(days, stepDays) {
  const out = [];
  const now = new Date();
  for (let i = days; i >= 0; i -= stepDays) {
    const d = new Date(now - i * 86400000);
    out.push(
      `${d.getDate()} ${d.toLocaleString("default", { month: "short" })}`,
    );
  }
  return out;
}

function movingAverage(arr, window) {
  return arr.map((_, i) => {
    const slice = arr.slice(Math.max(0, i - window + 1), i + 1);
    return Math.round(slice.reduce((a, b) => a + b, 0) / slice.length);
  });
}

function chartLineOpts(title) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: {
        grid: { color: "rgba(255,255,255,0.04)" },
        ticks: { maxTicksLimit: 8 },
      },
      y: { grid: { color: "rgba(255,255,255,0.04)" }, beginAtZero: true },
    },
  };
}

function showToast(msg) {
  const t = document.getElementById("feedbackToast");
  if (!t) return;
  t.textContent = msg;
  t.style.display = "block";
  setTimeout(() => {
    t.style.display = "none";
  }, 3000);
}

function closeModal() {
  document.getElementById("findingModal").style.display = "none";
}
window.onclick = (e) => {
  // Close finding modal
  if (e.target === document.getElementById("findingModal")) closeModal();
};

// Close menu when clicking outside
document.addEventListener("click", (e) => {
  const wrap = document.getElementById("menuWrap");
  if (wrap && !wrap.contains(e.target)) {
    closeMenu();
  }
});

// ─── HAMBURGER MENU ───────────────────────────────────────────────────────
function toggleMenu(e) {
  e.stopPropagation();
  const btn = document.getElementById("menuBtn");
  const dropdown = document.getElementById("menuDropdown");
  if (!btn || !dropdown) return;
  const isOpen = dropdown.classList.contains("is-open");
  if (isOpen) {
    closeMenu();
  } else {
    btn.classList.add("is-open");
    dropdown.classList.add("is-open");
    btn.setAttribute("aria-expanded", "true");
  }
}

function closeMenu() {
  const btn = document.getElementById("menuBtn");
  const dropdown = document.getElementById("menuDropdown");
  if (btn) {
    btn.classList.remove("is-open");
    btn.setAttribute("aria-expanded", "false");
  }
  if (dropdown) {
    dropdown.classList.remove("is-open");
  }
}

function toggleTheme() {
  const isM = document.body.classList.toggle("monochrome");
  const btn = document.getElementById("themeToggle");
  if (btn) btn.innerHTML = isM ? "🌗 Color" : "🌗 Contrast";
  localStorage.setItem("theme", isM ? "monochrome" : "default");
}

document.addEventListener("DOMContentLoaded", () => {
  if (localStorage.getItem("theme") === "monochrome") {
    document.body.classList.add("monochrome");
    const btn = document.getElementById("themeToggle");
    if (btn) btn.innerHTML = "🌗 Color";
  }
});

// ─── THREAT HELPERS ───────────────────────────────────────────────────────
function getThreatIcon(type) {
  const icons = {
    secret: "🔑",
    injection: "💉",
    xss: "⚡",
    csrf: "🔄",
    auth: "🔐",
    dependency: "📦",
    crypto: "🔒",
    path_traversal: "📂",
    sql: "🗄️",
    rce: "💣",
    cve: "⚠️",
  };
  const t = (type || "").toLowerCase();
  for (const [k, v] of Object.entries(icons)) {
    if (t.includes(k)) return v;
  }
  return "🚨";
}

function cleanThreatTitle(title, type) {
  const t = (title || "").toLowerCase();
  const ty = (type || "").toLowerCase();
  if (t.includes("high_entropy") || t.includes("high entropy"))
    return "High Entropy Secret";
  if (t.includes("keyword_password") || t.includes("password"))
    return "Hardcoded Password";
  if (t.includes("keyword_secret") || t.includes("secret"))
    return "Hardcoded Secret";
  if (t.includes("api_key") || t.includes("apikey")) return "Exposed API Key";
  if (t.includes("token")) return "Exposed Token";
  if (t.includes("private_key") || t.includes("privatekey"))
    return "Exposed Private Key";
  if (t.includes("aws")) return "AWS Credential Leak";
  if (t.includes("sql") && t.includes("inject")) return "SQL Injection";
  if (t.includes("xss") || t.includes("cross-site scripting"))
    return "Cross-Site Scripting";
  if (t.includes("csrf")) return "CSRF Vulnerability";
  if (t.includes("path traversal") || t.includes("directory"))
    return "Path Traversal";
  if (t.includes("command inject") || t.includes("rce"))
    return "Remote Code Execution";
  if (t.includes("hardcoded")) return "Hardcoded Secret";
  if (t.includes("weak") && t.includes("crypt")) return "Weak Cryptography";
  const typeLabels = {
    secret: "Hardcoded Secret",
    injection: "Code Injection",
    xss: "Cross-Site Scripting",
    csrf: "CSRF Vulnerability",
    auth: "Auth Weakness",
    dependency: "Vulnerable Dependency",
    crypto: "Weak Cryptography",
    path_traversal: "Path Traversal",
    sql: "SQL Injection",
    rce: "Remote Code Execution",
    cve: "Known CVE",
  };
  for (const [k, l] of Object.entries(typeLabels)) {
    if (ty.includes(k)) return l;
  }
  return (title || "Unknown Threat")
    .replace(/keyword_/gi, "")
    .replace(/_/g, " ")
    .replace(/\s+Detected$/i, "")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

// ─── FEEDBACK ─────────────────────────────────────────────────────────────
async function submitFeedback(findingId, type, event) {
  if (event) event.stopPropagation();
  try {
    const res = await fetch("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId, feedback_type: type }),
    });
    if (res.ok) {
      showToast(
        `Feedback: ${type === "positive" ? "✅ Correct" : "🚫 False Positive"}`,
      );
    } else {
      showToast("Failed to save feedback");
    }
  } catch (e) {
    showToast("Error submitting feedback");
  }
}
