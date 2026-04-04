const backendUrlInput = document.getElementById("backendUrl");
const saveBtn = document.getElementById("saveBtn");
const statusEl = document.getElementById("status");
const reportsBody = document.getElementById("reportsBody");

const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";

function setStatus(message) {
  statusEl.textContent = message;
}

function hostnameFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function renderReports(reports) {
  reportsBody.innerHTML = "";
  for (const report of reports) {
    const tr = document.createElement("tr");
    const signals = [
      report.page_signals?.microphone ? "Mic" : null,
      report.page_signals?.camera ? "Camera" : null,
      report.page_signals?.location ? "Location" : null,
      report.page_signals?.third_party_data_alert ? "3rd-party data alert" : null
    ].filter(Boolean).join(", ") || "None";
    tr.innerHTML = `
      <td>${hostnameFromUrl(report.url)}</td>
      <td>${report.risk_score}</td>
      <td>${report.severity}</td>
      <td>${signals}</td>
      <td>
        <div class="actions">
          <button type="button" class="secondary-btn small-btn" data-action="download" data-report-id="${report.report_id}">Download</button>
          <button type="button" class="danger-btn small-btn" data-action="delete" data-report-id="${report.report_id}">Delete</button>
        </div>
      </td>
      <td>${new Date(report.scanned_at).toLocaleString()}</td>
    `;
    reportsBody.appendChild(tr);
  }

  if (!reports.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = "<td colspan='6'>No reports available yet.</td>";
    reportsBody.appendChild(tr);
  }
}

async function loadSettings() {
  const settings = await chrome.storage.sync.get(["backendUrl"]);
  backendUrlInput.value = settings.backendUrl || DEFAULT_BACKEND_URL;

  const state = await chrome.storage.local.get(["reports"]);
  renderReports(state.reports || []);
}

saveBtn.addEventListener("click", async () => {
  const backendUrl = backendUrlInput.value.trim();
  if (!backendUrl) {
    setStatus("Please provide a backend URL.");
    return;
  }

  await chrome.storage.sync.set({ backendUrl });
  setStatus("Settings saved.");
});

async function getBackendUrl() {
  const settings = await chrome.storage.sync.get(["backendUrl"]);
  return settings.backendUrl || DEFAULT_BACKEND_URL;
}

async function getLocalReport(reportId) {
  const state = await chrome.storage.local.get(["reports"]);
  const reports = Array.isArray(state.reports) ? state.reports : [];
  return reports.find((item) => item.report_id === reportId) || null;
}

async function downloadReport(reportId) {
  console.log("Starting download for report:", reportId);
  
  try {
    const backendUrl = await getBackendUrl();
    const localReport = await getLocalReport(reportId);
    const pdfUrl = `${backendUrl}/report/${reportId}/pdf`;
    console.log("Downloading PDF from:", pdfUrl);
    let response = await fetch(pdfUrl);

    if (!response.ok && localReport) {
      console.log("Report not found in backend memory. Generating PDF from local snapshot.");
      response = await fetch(`${backendUrl}/report/pdf`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(localReport)
      });
    }

    if (!response.ok) {
      throw new Error(`Failed to download PDF report ${reportId}: ${response.status} ${response.statusText}`);
    }

    const blob = await response.blob();
    if (blob.type !== "application/pdf") {
      throw new Error("Backend did not return a PDF file");
    }

    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = `privacy-sentinel-${reportId}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(objectUrl);
    
    console.log("Download completed");
  } catch (error) {
    console.error("Download failed:", error);
    throw error;
  }
}

async function deleteReport(reportId) {
  console.log("Starting delete for report:", reportId);

  const backendUrl = await getBackendUrl();
  try {
    console.log("Sending DELETE request to:", `${backendUrl}/report/${reportId}`);
    const response = await fetch(`${backendUrl}/report/${reportId}`, { method: "DELETE" });
    if (!response.ok && response.status !== 404) {
      console.warn(`Backend delete returned ${response.status} ${response.statusText}`);
    }
  } catch (error) {
    console.warn("Backend delete skipped due to network or server error:", error);
  }

  const state = await chrome.storage.local.get(["reports"]);
  const reports = Array.isArray(state.reports) ? state.reports : [];
  console.log("Total reports before deletion:", reports.length);

  const nextReports = reports.filter((report) => report.report_id !== reportId);
  console.log("Total reports after deletion:", nextReports.length);

  await chrome.storage.local.set({ reports: nextReports });
  renderReports(nextReports);

  console.log("Report deleted successfully from local storage");
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) {
    return;
  }

  const action = button.getAttribute("data-action");
  const reportId = button.getAttribute("data-report-id");

  if (!action || !reportId) {
    console.warn("Button missing action or reportId", { action, reportId });
    return;
  }

  button.disabled = true;
  console.log(`Performing ${action} on report ${reportId}`);

  try {
    if (action === "download") {
      console.log("Downloading report...");
      await downloadReport(reportId);
      setStatus("Report downloaded successfully.");
    } else if (action === "delete") {
      console.log("Deleting report...");
      await deleteReport(reportId);
      setStatus("Report deleted successfully.");
    }
  } catch (error) {
    console.error("Error:", error);
    setStatus(`Error: ${error.message}`);
  } finally {
    button.disabled = false;
  }
});

loadSettings().catch((error) => {
  console.error("Failed to load settings:", error);
  setStatus(`Failed to load settings: ${error.message}`);
});
