const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");

const riskScoreEl = document.getElementById("riskScore");
const severityEl = document.getElementById("severity");
const totalCookiesEl = document.getElementById("totalCookies");
const thirdPartyEl = document.getElementById("thirdParty");
const trackersEl = document.getElementById("trackers");
const insecureEl = document.getElementById("insecure");
const microphoneSignalEl = document.getElementById("microphoneSignal");
const cameraSignalEl = document.getElementById("cameraSignal");
const locationSignalEl = document.getElementById("locationSignal");
const thirdPartyDataSignalEl = document.getElementById("thirdPartyDataSignal");
const recommendationsEl = document.getElementById("recommendations");

function setStatus(message) {
  statusEl.textContent = message;
}

function renderResult(result) {
  resultEl.classList.remove("hidden");
  riskScoreEl.textContent = String(result.risk_score);
  severityEl.textContent = result.severity;
  totalCookiesEl.textContent = String(result.total_cookies);
  thirdPartyEl.textContent = String(result.third_party_cookies);
  trackersEl.textContent = String(result.tracking_indicators);
  insecureEl.textContent = String(result.insecure_cookies);

  const pageSignals = result.page_signals || {};
  microphoneSignalEl.textContent = pageSignals.microphone ? "Detected" : "Not detected";
  cameraSignalEl.textContent = pageSignals.camera ? "Detected" : "Not detected";
  locationSignalEl.textContent = pageSignals.location ? "Detected" : "Not detected";
  thirdPartyDataSignalEl.textContent = pageSignals.third_party_data_alert ? "Alert" : "No alert";

  recommendationsEl.innerHTML = "";
  for (const recommendation of result.recommendations.slice(0, 4)) {
    const li = document.createElement("li");
    li.textContent = recommendation;
    recommendationsEl.appendChild(li);
  }
}

async function getActiveTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs.length || !tabs[0].url) {
    throw new Error("Unable to identify active tab URL.");
  }
  return tabs[0].url;
}

function sendScanRequest(url) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: "SCAN_TAB", url }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response?.ok) {
        reject(new Error(response?.error || "Unknown scan error."));
        return;
      }
      resolve(response.result);
    });
  });
}

scanBtn.addEventListener("click", async () => {
  scanBtn.disabled = true;
  setStatus("Scanning cookies and analyzing tracking behavior...");

  try {
    const url = await getActiveTabUrl();
    const result = await sendScanRequest(url);
    renderResult(result);
    setStatus(`Analysis complete for ${new URL(url).hostname}`);
  } catch (error) {
    setStatus(`Scan failed: ${error.message}`);
  } finally {
    scanBtn.disabled = false;
  }
});
