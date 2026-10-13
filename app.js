const AUTH_STORAGE_KEY = "defender-sentinel-auth";

let dashboardData = { stats: [], computers: [], alerts: [] };
let selectedAlertId = null;
let selectedComputer = null;
let selectedSeverity = "all";

const loginScreen = document.getElementById("loginScreen");
const appShell = document.getElementById("appShell");
const loginForm = document.getElementById("loginForm");
const loginError = document.getElementById("loginError");
const currentUser = document.getElementById("currentUser");
const logoutButton = document.getElementById("logoutButton");
const statsGrid = document.getElementById("statsGrid");
const computerTableBody = document.getElementById("computerTableBody");
const alertList = document.getElementById("alertList");
const alertDetail = document.getElementById("alertDetail");
const searchInput = document.getElementById("searchInput");
const triggerScanBtn = document.getElementById("triggerScanBtn");
const exportButton = document.getElementById("exportButton");
const toast = document.getElementById("toast");

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function getSession() {
  const stored = localStorage.getItem(AUTH_STORAGE_KEY);
  if (!stored) return null;

  try {
    return JSON.parse(stored);
  } catch {
    return null;
  }
}

function setAuthenticatedUser(username, token) {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify({ username, token }));
  currentUser.textContent = username;
  loginScreen.classList.add("hidden");
  appShell.classList.remove("hidden");
}

function clearSession() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
  appShell.classList.add("hidden");
  loginScreen.classList.remove("hidden");
  loginError.classList.add("hidden");
  loginForm.reset();
}

async function loginWithApi(domain, username, password) {
  const response = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, username, password })
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "AD authentication failed");
  }

  return payload;
}

async function loadDashboard() {
  const session = getSession();
  if (!session || !session.token) {
    clearSession();
    return;
  }

  const response = await fetch("/api/dashboard", {
    headers: {
      Authorization: `Bearer ${session.token}`
    }
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401) clearSession();
    throw new Error(payload.error || (response.status === 401 ? "Session expired" : "Unable to load live data"));
  }

  dashboardData = await response.json();
  selectedAlertId = dashboardData.alerts?.[0]?.id || null;
  document.getElementById("mini-endpoints").textContent = (dashboardData.computers || []).length.toLocaleString();
  const respondingCount = (dashboardData.computers || []).filter((computer) => computer.status !== "unknown").length;
  document.getElementById("computerStatusBadge").textContent = `${respondingCount} of ${dashboardData.computers.length} responding`;
  buildStats();
  renderComputers();
  renderAlerts();
  renderDetail();
}

function buildStats() {
  const stats = dashboardData.stats || [];
  statsGrid.innerHTML = stats
    .map(
      (stat) => `
        <article class="stat-card">
          <div class="label">
            <span>${escapeHTML(stat.label)}</span>
            <span>•</span>
          </div>
          <p class="value">${Number(stat.value).toLocaleString()}</p>
          <span class="trend ${stat.trend === "up" || stat.trend === "down" ? stat.trend : ""}">${stat.trend === "up" ? "▲ " : stat.trend === "down" ? "▼ " : ""}${escapeHTML(stat.change)}</span>
        </article>
      `
    )
    .join("");
}

function getStatusClass(status) {
  if (status === "critical") return "critical";
  if (status === "warning") return "warning";
  if (status === "healthy") return "healthy";
  return "unknown";
}

function renderComputers() {
  const query = searchInput.value.trim().toLowerCase();
  const computers = dashboardData.computers || [];

  const filteredComputers = computers.filter((computer) => {
    const haystack = `${computer.name} ${computer.domain} ${computer.user || ""} ${computer.os}`.toLowerCase();
    return haystack.includes(query);
  });

  computerTableBody.innerHTML = filteredComputers
    .map(
      (computer) => `
        <tr data-computer="${escapeHTML(computer.name)}">
          <td>
            <div class="computer-name">
              <strong>${escapeHTML(computer.name)}</strong>
              <span>${escapeHTML(computer.domain)}</span>
            </div>
          </td>
          <td>${escapeHTML(computer.os || "Not reported")}</td>
          <td><span class="status-pill ${getStatusClass(computer.status)}">${escapeHTML(computer.status)}</span></td>
          <td>${Number(computer.alerts)}</td>
          <td>${escapeHTML(computer.lastSeen)}</td>
        </tr>
      `
    )
    .join("");

  computerTableBody.querySelectorAll("tr").forEach((row) => {
    row.addEventListener("click", () => {
      const computerName = row.dataset.computer;
      selectedComputer = computerName;
      const matchingAlert = (dashboardData.alerts || []).find((alert) => alert.computer === computerName);
      selectedAlertId = matchingAlert?.id || null;
      renderAlerts();
      renderDetail();
    });
  });
}

function renderAlerts() {
  const query = searchInput.value.trim().toLowerCase();
  const alerts = dashboardData.alerts || [];

  const filteredAlerts = alerts.filter((alert) => {
    const haystack = `${alert.title} ${alert.computer} ${alert.file} ${alert.user} ${alert.category} ${alert.details?.message || ""}`.toLowerCase();
    return haystack.includes(query) && (selectedSeverity === "all" || alert.severity === selectedSeverity);
  });

  if (!filteredAlerts.some((alert) => alert.id === selectedAlertId)) {
    const computerAlert = filteredAlerts.find((alert) => alert.computer === selectedComputer);
    selectedAlertId = computerAlert?.id || (selectedComputer ? null : filteredAlerts[0]?.id || null);
  }

  alertList.innerHTML = filteredAlerts.length ? filteredAlerts
    .map(
      (alert) => `
        <div class="alert-item ${["critical", "high", "medium"].includes(alert.severity) ? alert.severity : "medium"} ${alert.id === selectedAlertId ? "active" : ""}" data-alert-id="${escapeHTML(alert.id)}">
          <div class="alert-head">
            <span>${escapeHTML(alert.title)}</span>
            <small>${escapeHTML(alert.severity)}</small>
          </div>
          <p>${escapeHTML(alert.computer)} • ${escapeHTML(new Date(alert.timestamp).toLocaleString())}</p>
        </div>
      `
    )
    .join("") : "<p class=\"empty-state\">No Defender events match this view.</p>";

  alertList.querySelectorAll(".alert-item").forEach((item) => {
    item.addEventListener("click", () => {
      selectedAlertId = item.dataset.alertId;
      selectedComputer = (dashboardData.alerts || []).find((alert) => alert.id === selectedAlertId)?.computer || null;
      renderAlerts();
      renderDetail();
    });
  });
}

function renderDetail() {
  const alerts = dashboardData.alerts || [];
  const alert = alerts.find((item) => item.id === selectedAlertId);

  if (!alert) {
    alertDetail.innerHTML = "<p class=\"empty-state\">No alerts available.</p>";
    return;
  }

  alertDetail.innerHTML = `
    <div class="detail-header">
      <h3>${escapeHTML(alert.title)}</h3>
      <div class="detail-metadata">
        <span class="meta-pill">${escapeHTML(alert.id)}</span>
        <span class="meta-pill">${escapeHTML(alert.severity)}</span>
        <span class="meta-pill">${escapeHTML(alert.computer)}</span>
        <span class="meta-pill">${escapeHTML(alert.status)}</span>
      </div>
    </div>

    <div class="detail-section">
      <h4>Alert summary</h4>
      <dl class="key-value">
        <dt>Category</dt>
        <dd>${escapeHTML(alert.category)}</dd>

        <dt>Detected</dt>
        <dd>${escapeHTML(new Date(alert.timestamp).toLocaleString())}</dd>

        <dt>File</dt>
        <dd>${escapeHTML(alert.file || "Not reported by the event")}</dd>

        <dt>User</dt>
        <dd>${escapeHTML(alert.user || "Not reported by the event")}</dd>

        <dt>Source</dt>
        <dd>${escapeHTML(alert.detectionSource)}</dd>
      </dl>
    </div>

    <div class="detail-section">
      <h4>Event details</h4>
      <dl class="key-value">
        <dt>Event ID</dt>
        <dd>${escapeHTML(alert.details.eventId)}</dd>

        <dt>Event message</dt>
        <dd>${escapeHTML(alert.details.message)}</dd>
      </dl>
    </div>

    <div class="detail-section">
      <h4>Recent activity</h4>
      <div class="log-list">
        ${(alert.logs || [])
          .map(
            (entry) => `
              <div class="log-item ${entry.type}">
                <span class="log-dot"></span>
                <div>
                  <strong>${escapeHTML(entry.title)}</strong>
                  <span>${escapeHTML(entry.time)}</span>
                </div>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.remove("hidden");
  setTimeout(() => {
    toast.classList.add("hidden");
  }, 2200);
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const domain = document.getElementById("domainInput").value;
  const username = document.getElementById("usernameInput").value;
  const password = document.getElementById("passwordInput").value;

  try {
    const result = await loginWithApi(domain, username, password);
    setAuthenticatedUser(result.user, result.token);
    loginError.classList.add("hidden");
    await loadDashboard();
    showToast(`AD session established for ${result.user}`);
  } catch (error) {
    clearSession();
    loginError.textContent = error.message || "AD authentication failed";
    loginError.classList.remove("hidden");
  }
});

logoutButton.addEventListener("click", () => {
  clearSession();
  showToast("Signed out of AD session");
});

searchInput.addEventListener("input", () => {
  renderComputers();
  renderAlerts();
  renderDetail();
});

document.querySelectorAll("[data-severity]").forEach((button) => {
  button.addEventListener("click", () => {
    selectedSeverity = button.dataset.severity;
    document.querySelectorAll("[data-severity]").forEach((item) => item.classList.toggle("active", item === button));
    renderAlerts();
    renderDetail();
  });
});

exportButton.addEventListener("click", () => {
  const file = new Blob([JSON.stringify(dashboardData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(file);
  const link = document.createElement("a");
  link.href = url;
  link.download = `defender-sentinel-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(url);
});

triggerScanBtn.addEventListener("click", async () => {
  const session = getSession();
  if (!session || !session.token) {
    clearSession();
    return;
  }

  if (!selectedComputer) {
    showToast("Select a computer or one of its alerts before scanning");
    return;
  }

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${session.token}`
      },
      body: JSON.stringify({ computer: selectedComputer })
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || "Unable to queue scan");
    }

    showToast(payload.message || `Remote scan queued for ${selectedComputer}`);
  } catch (error) {
    showToast(error.message || "Unable to queue scan");
  }
});

async function restoreSession() {
  const session = getSession();
  if (!session || !session.token) {
    clearSession();
    return;
  }

  setAuthenticatedUser(session.user, session.token);
  try {
    await loadDashboard();
  } catch {
    clearSession();
  }
}

restoreSession();
