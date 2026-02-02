/**
 * Security Dashboard JavaScript
 *
 * Handles dashboard data loading, chart rendering, and user interactions.
 */

// Global variables for charts
let severityChart, owaspChart, trendChart, fileRiskChart;

/**
 * Load all dashboard data
 */
async function loadDashboard() {
  try {
    await Promise.all([
      loadSummary(),
      loadCharts(),
      loadFindings(),
      loadRemediationPlan(),
    ]);

    console.log("Dashboard loaded successfully");
  } catch (error) {
    console.error("Error loading dashboard:", error);
    showError("Failed to load dashboard data");
  }
}

/**
 * Load executive summary data
 */
async function loadSummary() {
  try {
    const response = await fetch("/api/security/summary");
    const data = await response.json();

    // Update risk banner
    const riskLevel = data.risk_level || "UNKNOWN";
    const riskScore = data.risk_score || 0;

    document.getElementById("riskScore").textContent = riskLevel;
    document.getElementById("riskScoreValue").textContent =
      riskScore.toFixed(2);
    document.getElementById("lastScan").textContent = formatDate(
      data.last_scan,
    );

    // Update risk banner color
    const riskBanner = document.getElementById("riskBanner");
    riskBanner.className = "risk-banner risk-" + riskLevel.toLowerCase();

    // Update metric cards
    document.getElementById("totalFindings").textContent =
      data.total_findings || 0;
    document.getElementById("criticalHigh").textContent =
      (data.critical_count || 0) + (data.high_count || 0);
    document.getElementById("cveCount").textContent = data.cve_count || 0;
    document.getElementById("dependencyHealth").textContent =
      (data.dependency_health || 0).toFixed(1) + "%";
  } catch (error) {
    console.error("Error loading summary:", error);
    throw error;
  }
}

/**
 * Load and render all charts
 */
async function loadCharts() {
  try {
    const response = await fetch("/api/security/charts");
    const chartsData = await response.json();

    if (chartsData) {
      renderSeverityChart(chartsData.severity_distribution);
      renderOWASPChart(chartsData.owasp_coverage);
      renderTrendChart(chartsData.vulnerability_trends);
      renderFileRiskChart(chartsData.file_risk_scores);
    }
  } catch (error) {
    console.error("Error loading charts:", error);
    throw error;
  }
}

/**
 * Render severity distribution donut chart
 */
function renderSeverityChart(data) {
  const ctx = document.getElementById("severityChart");
  if (!ctx) return;

  if (severityChart) {
    severityChart.destroy();
  }

  severityChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: data.labels || [],
      datasets: data.datasets || [],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: "right",
          labels: {
            font: { size: 12 },
            padding: 15,
          },
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              return context.label + ": " + context.parsed;
            },
          },
        },
      },
    },
  });
}

/**
 * Render OWASP coverage bar chart
 */
function renderOWASPChart(data) {
  const ctx = document.getElementById("owaspChart");
  if (!ctx) return;

  if (owaspChart) {
    owaspChart.destroy();
  }

  owaspChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.labels || [],
      datasets: data.datasets || [],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: "y",
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: { stepSize: 1 },
        },
      },
    },
  });
}

/**
 * Render vulnerability trends line chart
 */
function renderTrendChart(data) {
  const ctx = document.getElementById("trendChart");
  if (!ctx) return;

  if (trendChart) {
    trendChart.destroy();
  }

  trendChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: data.labels || [],
      datasets: data.datasets || [],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "top",
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: { stepSize: 1 },
        },
      },
    },
  });
}

/**
 * Render file risk scores horizontal bar chart
 */
function renderFileRiskChart(data) {
  const ctx = document.getElementById("fileRiskChart");
  if (!ctx) return;

  if (fileRiskChart) {
    fileRiskChart.destroy();
  }

  fileRiskChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.labels || [],
      datasets: data.datasets || [],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: "y",
      plugins: {
        legend: { display: true, position: "top" },
      },
      scales: {
        x: { beginAtZero: true },
      },
    },
  });
}

/**
 * Load findings table
 */
async function loadFindings(severity = null) {
  try {
    let url = "/api/security/findings?limit=20";
    if (severity) {
      url += "&severity=" + severity;
    }

    const response = await fetch(url);
    const data = await response.json();

    const tbody = document.getElementById("findingsTableBody");
    if (!tbody) return;

    if (!data.findings || data.findings.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="no-data">No findings to display</td></tr>';
      return;
    }

    tbody.innerHTML = data.findings
      .map(
        (finding) => `
            <tr>
                <td><code>${escapeHtml(
                  finding.id || finding.cve_id || "N/A",
                )}</code></td>
                <td><span class="severity-badge severity-${(
                  finding.severity || "unknown"
                ).toLowerCase()}">${finding.severity || "UNKNOWN"}</span></td>
                <td>${escapeHtml(
                  finding.title || finding.summary || "No title",
                )}</td>
                <td>${escapeHtml(finding.owasp_name || "Not Mapped")}</td>
                <td><code>${escapeHtml(
                  getFileName(finding.file_path || finding.package || "N/A"),
                )}</code></td>
                <td>
                    <div class="feedback-actions">
                        <button onclick="submitFeedback('${
                          finding.id || finding.cve_id
                        }', 'positive', event)" 
                                class="btn-feedback ${
                                  finding.user_feedback === "positive"
                                    ? "active-pos"
                                    : ""
                                }" title="Correct">👍</button>
                        <button onclick="submitFeedback('${
                          finding.id || finding.cve_id
                        }', 'negative', event)" 
                                class="btn-feedback ${
                                  finding.user_feedback === "negative"
                                    ? "active-neg"
                                    : ""
                                }" title="False Positive">👎</button>
                    </div>
                </td>
                <td>
                    <button onclick="viewFinding('${
                      finding.id || finding.cve_id
                    }')" class="btn-view">View</button>
                </td>
            </tr>
        `,
      )
      .join("");
  } catch (error) {
    console.error("Error loading find ings:", error);
    const tbody = document.getElementById("findingsTableBody");
    if (tbody) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="error">Error loading findings</td></tr>';
    }
  }
}

/**
 * Load remediation plan
 */
async function loadRemediationPlan() {
  try {
    const response = await fetch("/api/security/remediation");
    const data = await response.json();

    const container = document.getElementById("remediationList");
    if (!container) return;

    if (!data.remediation_plan || data.remediation_plan.length === 0) {
      container.innerHTML = '<div class="no-data">No remediation items</div>';
      return;
    }

    container.innerHTML = data.remediation_plan
      .slice(0, 10)
      .map(
        (item, index) => `
            <div class="remediation-item">
                <div class="remediation-header">
                    <span class="remediation-number">${index + 1}</span>
                    <span class="severity-badge severity-${(
                      item.severity || "unknown"
                    ).toLowerCase()}">${item.severity}</span>
                    <span class="remediation-title">${escapeHtml(
                      item.title,
                    )}</span>
                </div>
                <div class="remediation-details">
                    <span class="badge">Effort: ${item.estimated_effort}</span>
                    <span class="badge">Impact: ${item.impact}</span>
                    <p>${escapeHtml(item.action)}</p>
                </div>
            </div>
        `,
      )
      .join("");
  } catch (error) {
    console.error("Error loading remediation plan:", error);
  }
}

/**
 * View finding details in modal
 */
async function viewFinding(findingId) {
  try {
    const response = await fetch(`/api/security/finding/${findingId}`);
    const finding = await response.json();

    if (finding.error) {
      alert("Finding not found");
      return;
    }

    const modalBody = document.getElementById("modalBody");
    modalBody.innerHTML = `
            <h2>${escapeHtml(finding.title || finding.summary)}</h2>
            <div class="finding-details">
                <div class="detail-row">
                    <strong>ID:</strong> <code>${escapeHtml(
                      finding.id || finding.cve_id,
                    )}</code>
                </div>
                <div class="detail-row">
                    <strong>Severity:</strong>
                    <span class="severity-badge severity-${(
                      finding.severity || "unknown"
                    ).toLowerCase()}">${finding.severity}</span>
                </div>
                <div class="detail-row">
                    <strong>OWASP Category:</strong> ${escapeHtml(
                      finding.owasp_name || "Not Mapped",
                    )}
                </div>
                ${
                  finding.file_path
                    ? `<div class="detail-row"><strong>File:</strong> <code>${escapeHtml(
                        finding.file_path,
                      )}:${finding.line_number || 0}</code></div>`
                    : ""
                }
                ${
                  finding.description
                    ? `<div class="detail-row"><strong>Description:</strong> <p>${escapeHtml(
                        finding.description,
                      )}</p></div>`
                    : ""
                }
                ${
                  finding.summary
                    ? `<div class="detail-row"><strong>Summary:</strong> <p>${escapeHtml(
                        finding.summary,
                      )}</p></div>`
                    : ""
                }
                <div class="detail-row">
                    <strong>Was this finding helpful?</strong>
                    <div class="feedback-actions" style="margin-top: 10px;">
                        <button onclick="submitFeedback('${
                          finding.id || finding.cve_id
                        }', 'positive', event)" 
                                class="btn-feedback ${
                                  finding.user_feedback === "positive"
                                    ? "active-pos"
                                    : ""
                                }" title="Correct">👍 Correct</button>
                        <button onclick="submitFeedback('${
                          finding.id || finding.cve_id
                        }', 'negative', event)" 
                                class="btn-feedback ${
                                  finding.user_feedback === "negative"
                                    ? "active-neg"
                                    : ""
                                }" title="False Positive">👎 False Positive</button>
                    </div>
                </div>
            </div>
        `;

    document.getElementById("findingModal").style.display = "block";
  } catch (error) {
    console.error("Error loading finding details:", error);
    alert("Error loading finding details");
  }
}

/**
 * Filter findings by severity
 */
function filterFindings() {
  const severity = document.getElementById("severityFilter").value;
  loadFindings(severity || null);
}

/**
 * Refresh dashboard
 */
async function refreshDashboard() {
  const btn = document.querySelector(".btn-refresh");
  const originalText = btn.innerHTML;

  try {
    btn.disabled = true;
    btn.innerHTML = "⏳ Scanning...";

    // Clear cache and trigger full re-scan
    const response = await fetch("/api/security/refresh");
    const result = await response.json();

    if (response.ok) {
      // Reload all data
      await loadDashboard();
      showToast("Dashboard updated with fresh scan results");
    } else {
      showError("Refresh failed: " + (result.error || "Unknown error"));
    }
  } catch (error) {
    console.error("Error refreshing dashboard:", error);
    showError("Failed to refresh dashboard");
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
}

/**
 * Close modal
 */
function closeModal() {
  document.getElementById("findingModal").style.display = "none";
}

/**
 * Helper functions
 */
function formatDate(dateStr) {
  if (!dateStr) return "N/A";
  const date = new Date(dateStr);
  return date.toLocaleString();
}

function getFileName(path) {
  if (!path) return "N/A";
  const parts = path.split("/");
  return parts[parts.length - 1];
}

function escapeHtml(text) {
  if (!text) return "";
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function showError(message) {
  console.error(message);
  showToast(message);
}

function showSuccess(message) {
  console.log(message);
  showToast(message);
}

/**
 * Submit user feedback for a finding
 */
async function submitFeedback(findingId, type, event) {
  if (event) {
    event.stopPropagation();
  }

  try {
    const response = await fetch("/api/feedback", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        finding_id: findingId,
        feedback_type: type,
      }),
    });

    const result = await response.json();

    if (response.ok) {
      showToast(
        `Feedback saved: ${type === "positive" ? "Correct" : "False Positive"}`,
      );

      // Update button styles if possible
      const btn = event ? event.currentTarget : null;
      if (btn) {
        const parent = btn.parentElement;
        parent.querySelectorAll(".btn-feedback").forEach((b) => {
          b.classList.remove("active-pos", "active-neg");
        });
        btn.classList.add(type === "positive" ? "active-pos" : "active-neg");
      }
    } else {
      console.error("Error saving feedback:", result.error);
      showToast("Failed to save feedback");
    }
  } catch (error) {
    console.error("Error submitting feedback:", error);
    showToast("Error submitting feedback");
  }
}

/**
 * Show toast notification
 */
function showToast(message) {
  const toast = document.getElementById("feedbackToast");
  if (!toast) return;

  toast.textContent = message;
  toast.style.display = "block";

  setTimeout(() => {
    toast.style.display = "none";
  }, 3000);
}

// Close modal when clicking outside
window.onclick = function (event) {
  const modal = document.getElementById("findingModal");
  if (event.target === modal) {
    modal.style.display = "none";
  }
};

/**
 * Toggle Monochrome Theme
 */
function toggleTheme() {
  const body = document.body;
  const isMonochrome = body.classList.toggle("monochrome");

  // Update button text/icon
  const btn = document.getElementById("themeToggle");
  if (btn) {
    btn.innerHTML = isMonochrome ? "🌗 Color" : "🌗 Contrast"; // Toggling back to "Color" implies exiting contrast mode
  }

  // Save preference
  localStorage.setItem("theme", isMonochrome ? "monochrome" : "default");
}

/**
 * Initialize Theme on Load
 */
document.addEventListener("DOMContentLoaded", function () {
  const savedTheme = localStorage.getItem("theme");
  if (savedTheme === "monochrome") {
    document.body.classList.add("monochrome");
    const btn = document.getElementById("themeToggle");
    if (btn) btn.innerHTML = "🌗 Color";
  }
});
