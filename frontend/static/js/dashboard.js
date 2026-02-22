/**
 * Security Dashboard JavaScript
 *
 * Handles dashboard data loading, chart rendering, and user interactions.
 */

// Global variables for charts
let weeklyChart, issueTypesChart;

/**
 * Load all dashboard data
 */
async function loadDashboard() {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const uid = urlParams.get('uid');
    
    await Promise.all([
        loadMetrics(uid), 
        loadCharts(uid), 
        loadRecentReviews(uid)
    ]);

    console.log("Dashboard loaded successfully");
  } catch (error) {
    console.error("Error loading dashboard:", error);
    showError("Failed to load dashboard data");
  }
}


/**
 * Load metrics data
 */
async function loadMetrics(uid) {
  try {
    let url = "/api/security/summary";
    if (uid) url += `?uid=${uid}`;
    
    const response = await fetch(url);
    const data = await response.json();

    // Update last updated timestamp
    document.getElementById("lastUpdated").textContent = formatTimeAgo(data.last_scan);

    // Update metric cards with new fields
    document.getElementById("filesReviewed").textContent = data.total_files || 0;
    document.getElementById("issuesFound").textContent = data.total_findings || 0;
    document.getElementById("aiCodePercent").textContent = `${data.ai_code_percent || 0}%`;
    document.getElementById("securityRating").textContent = `${data.security_rating || 0}/10`;
  } catch (error) {
    console.error("Error loading metrics:", error);
    // Use default values if API fails
    document.getElementById("lastUpdated").textContent = "2 min ago";
  }
}


/**
 * Load and render all charts
 */
async function loadCharts(uid) {
  try {
    let url = "/api/security/charts";
    if (uid) url += `?uid=${uid}`;
    
    const response = await fetch(url);
    const data = await response.json();
    
    // Render only the histogram
    renderIssueHistogram(data.severity_distribution);
  } catch (error) {
    console.error("Error loading charts:", error);
  }
}
// ... (omitted chart rendering functions for brevity, no changes needed there) ...

/**
 * Load possible cyber security theft list
 */
async function loadRecentReviews(uid) {
  try {
    let url = "/api/security/findings?limit=50";
    if (uid) url += `&uid=${uid}`;
    
    const response = await fetch(url);
    const data = await response.json();

    const tbody = document.getElementById("reviewsTableBody");
    if (!tbody) return;

    if (!data.findings || data.findings.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="loading">✅ No security threats detected</td></tr>';
      return;
    }

    tbody.innerHTML = data.findings
      .map(
        (finding) => {
          // Build source file + line display
          const fileParts = (finding.file_path || "Unknown file").replace(/\\/g, '/');
          const shortFile = fileParts.split('/').slice(-2).join('/'); // show last 2 path parts
          const lineNum = finding.line_number ? `:${finding.line_number}` : '';
          const sourceRef = `<code class="source-ref" title="${escapeHtml(fileParts)}">${escapeHtml(shortFile)}${lineNum}</code>`;

          // Build OWASP/CWE badges
          const owaspBadge = finding.owasp_name
            ? `<span class="owasp-badge" title="${escapeHtml(finding.owasp_category || '')}">${escapeHtml(finding.owasp_name)}</span>`
            : '';
          const cweBadges = (finding.cwe_ids || [])
            .map(cwe => `<span class="cwe-badge">${escapeHtml(cwe)}</span>`)
            .join(' ');

          // Build short description (first sentence only)
          const rawDesc = finding.description || finding.ai_description || 'No description available';
          const shortDesc = rawDesc.split('\n')[0].substring(0, 120) + (rawDesc.length > 120 ? '…' : '');

          return `
            <tr class="theft-row severity-row-${(finding.severity || 'unknown').toLowerCase()}">
                <td class="threat-type-cell">
                  <div class="threat-icon">${getThreatIcon(finding.type)}</div>
                  <span class="threat-label">${escapeHtml(cleanThreatTitle(finding.title, finding.type))}</span>
                </td>
                <td class="source-cell">${sourceRef}</td>
                <td><span class="severity-badge severity-${(finding.severity || 'unknown').toLowerCase()}">${finding.severity || 'UNKNOWN'}</span></td>
                <td class="description-cell">${escapeHtml(shortDesc)}</td>
                <td class="owasp-cell">${owaspBadge}${cweBadges}</td>
                <td>
                    <button onclick="viewFinding('${finding.id || finding.cve_id}')" class="btn-view">🔍 View</button>
                </td>
            </tr>
          `;
        }
      )
      .join("");
  } catch (error) {
    console.error("Error loading security threats:", error);
    const tbody = document.getElementById("reviewsTableBody");
    if (tbody) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="loading">⚠️ Error loading security threats</td></tr>';
    }
  }
}

/**
 * Convert raw backend title to a simple, user-friendly label.
 * e.g. "Hardcoded keyword_PASSWORD Detected" → "Hardcoded Password"
 */
function cleanThreatTitle(title, type) {
  const t = (title || '').toLowerCase();
  const ty = (type || '').toLowerCase();

  // Specific pattern matches (order matters — most specific first)
  if (t.includes('high_entropy') || t.includes('high entropy'))  return 'High Entropy Secret';
  if (t.includes('keyword_password') || t.includes('password'))  return 'Hardcoded Password';
  if (t.includes('keyword_secret') || t.includes('secret'))      return 'Hardcoded Secret';
  if (t.includes('api_key') || t.includes('apikey'))             return 'Exposed API Key';
  if (t.includes('token'))                                        return 'Exposed Token';
  if (t.includes('private_key') || t.includes('privatekey'))     return 'Exposed Private Key';
  if (t.includes('aws'))                                         return 'AWS Credential Leak';
  if (t.includes('github') && t.includes('token'))              return 'GitHub Token Leak';
  if (t.includes('sql') && t.includes('inject'))                return 'SQL Injection';
  if (t.includes('xss') || t.includes('cross-site scripting'))  return 'Cross-Site Scripting';
  if (t.includes('csrf'))                                        return 'CSRF Vulnerability';
  if (t.includes('path traversal') || t.includes('directory'))  return 'Path Traversal';
  if (t.includes('command inject') || t.includes('rce'))        return 'Remote Code Execution';
  if (t.includes('insecure') && t.includes('deserializ'))       return 'Insecure Deserialization';
  if (t.includes('open redirect'))                               return 'Open Redirect';
  if (t.includes('hardcoded'))                                   return 'Hardcoded Secret';
  if (t.includes('weak') && t.includes('crypt'))                return 'Weak Cryptography';
  if (t.includes('outdated') || t.includes('vulnerable dep'))   return 'Vulnerable Dependency';
  if (t.includes('cve-'))                                        return title.match(/CVE-\d{4}-\d+/i)?.[0] || 'Known CVE';

  // Fall back to type-based label
  const typeLabels = {
    'secret':         'Hardcoded Secret',
    'injection':      'Code Injection',
    'xss':            'Cross-Site Scripting',
    'csrf':           'CSRF Vulnerability',
    'auth':           'Auth Weakness',
    'dependency':     'Vulnerable Dependency',
    'crypto':         'Weak Cryptography',
    'path_traversal': 'Path Traversal',
    'sql':            'SQL Injection',
    'rce':            'Remote Code Execution',
    'cve':            'Known CVE',
  };
  for (const [key, label] of Object.entries(typeLabels)) {
    if (ty.includes(key)) return label;
  }

  // Last resort: clean up the raw title
  return (title || 'Unknown Threat')
    .replace(/^Hardcoded\s+/i, 'Hardcoded ')
    .replace(/keyword_/gi, '')
    .replace(/_/g, ' ')
    .replace(/\s+Detected$/i, '')
    .replace(/\b\w/g, c => c.toUpperCase())
    .trim();
}

/**
 * Returns an emoji icon based on finding type
 */
function getThreatIcon(type) {
  const icons = {
    'secret':         '🔑',
    'injection':      '💉',
    'xss':            '⚡',
    'csrf':           '🔄',
    'auth':           '🔐',
    'dependency':     '📦',
    'crypto':         '🔒',
    'path_traversal': '📂',
    'sql':            '🗄️',
    'rce':            '💣',
    'cve':            '⚠️',
  };
  const t = (type || '').toLowerCase();
  for (const [key, icon] of Object.entries(icons)) {
    if (t.includes(key)) return icon;
  }
  return '🚨';
}



/**
 * View finding details in modal
 */
async function viewFinding(findingId) {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const uid = urlParams.get('uid');
    
    let url = `/api/security/finding/${findingId}`;
    if (uid) url += `?uid=${uid}`;

    const response = await fetch(url);
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
            </div>
        `;

    document.getElementById("findingModal").style.display = "block";
  } catch (error) {
    console.error("Error loading finding details:", error);
    alert("Error loading finding details");
  }
}


/**
 * Refresh dashboard
 */
async function refreshDashboard() {
  try {
    showToast("Refreshing dashboard...");
    await loadDashboard();
    showToast("Dashboard refreshed successfully");
  } catch (error) {
    console.error("Error refreshing dashboard:", error);
    showError("Failed to refresh dashboard");
  }
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
 * Render issue histogram (severity distribution)
 */
function renderIssueHistogram(severityData) {
  const ctx = document.getElementById("issueHistogram");
  if (!ctx) return;

  // Parse severity data - handle both formats
  let severityCounts = {};
  
  if (severityData && severityData.labels && severityData.datasets) {
    // Chart format from dashboard_data.json
    severityData.labels.forEach((label, index) => {
      severityCounts[label] = severityData.datasets[0]?.data[index] || 0;
    });
  } else if (severityData && typeof severityData === 'object') {
    // Simple object format {CRITICAL: 2, HIGH: 0, ...}
    severityCounts = severityData;
  }

  // Prepare data for all severity levels
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const counts = severities.map(sev => severityCounts[sev] || 0);
  const colors = {
    'CRITICAL': '#dc3545',
    'HIGH': '#fd7e14',
    'MEDIUM': '#ffc107',
    'LOW': '#28a745'
  };

  new Chart(ctx, {
    type: "bar",
    data: {
      labels: severities,
      datasets: [{
        label: "Number of Issues",
        data: counts,
        backgroundColor: severities.map(sev => colors[sev]),
        borderColor: severities.map(sev => colors[sev]),
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        },
        title: {
          display: true,
          text: 'Issues by Severity Level'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            stepSize: 1
          }
        }
      }
    }
  });
}

/**
 * Helper functions
 */
function formatDate(dateStr) {
  if (!dateStr) return "N/A";
  const date = new Date(dateStr);
  return date.toLocaleString();
}

function formatTimeAgo(dateStr) {
  if (!dateStr) return "2 min ago";
  
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins} min ago`;
  
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
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
