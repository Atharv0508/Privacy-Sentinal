const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";

function normalizeSameSite(sameSite) {
  if (!sameSite) return "unspecified";
  return String(sameSite).toLowerCase();
}

function isHttpScheme(url) {
  return url.startsWith("http://") || url.startsWith("https://");
}

async function getBackendUrl() {
  const result = await chrome.storage.sync.get(["backendUrl"]);
  return result.backendUrl || DEFAULT_BACKEND_URL;
}

async function saveReportSummary(report) {
  const state = await chrome.storage.local.get(["reports"]);
  const reports = Array.isArray(state.reports) ? state.reports : [];
  reports.unshift({
    report_id: report.report_id,
    url: report.url,
    risk_score: report.risk_score,
    severity: report.severity,
    scanned_at: report.scanned_at,
    tracking_indicators: report.tracking_indicators,
    third_party_cookies: report.third_party_cookies,
    insecure_cookies: report.insecure_cookies,
    total_cookies: report.total_cookies,
    first_party_cookies: report.first_party_cookies,
    findings: Array.isArray(report.findings) ? report.findings : [],
    page_signals: report.page_signals || {
      microphone: false,
      camera: false,
      location: false,
      third_party_data_alert: false,
      third_party_endpoints: [],
      evidence: []
    },
    recommendations: Array.isArray(report.recommendations) ? report.recommendations.slice(0, 5) : []
  });

  await chrome.storage.local.set({ reports: reports.slice(0, 50) });
}

async function collectPageSignals(tabId, tabUrl) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      args: [tabUrl],
      func: async (pageUrl) => {
      const siteHost = new URL(pageUrl).hostname.toLowerCase();

      const normalizeHost = (value) => {
        try {
          return new URL(value).hostname.toLowerCase();
        } catch {
          return String(value || "").replace(/^\.+/, "").toLowerCase();
        }
      };

      const isThirdParty = (resourceUrl) => {
        const resourceHost = normalizeHost(resourceUrl);
        if (!resourceHost || !siteHost) {
          return false;
        }
        return resourceHost !== siteHost && !resourceHost.endsWith(`.${siteHost}`) && !siteHost.endsWith(`.${resourceHost}`);
      };

      const collectText = () => {
        const parts = [];
        if (document.documentElement?.innerHTML) {
          parts.push(document.documentElement.innerHTML);
        }
        if (document.body?.innerText) {
          parts.push(document.body.innerText);
        }
        for (const script of document.scripts || []) {
          if (script.textContent) {
            parts.push(script.textContent);
          }
          const src = script.getAttribute?.("src");
          if (src) {
            parts.push(src);
          }
        }
        return parts.join("\n").toLowerCase();
      };

      const allowedFeatures = (() => {
        const policy = document.permissionsPolicy || document.featurePolicy;
        if (!policy?.allowedFeatures) {
          return [];
        }
        try {
          return policy.allowedFeatures();
        } catch {
          return [];
        }
      })();

      const permissionStates = {
        microphone: "unsupported",
        camera: "unsupported",
        geolocation: "unsupported"
      };

      const readPermissionState = async (name) => {
        if (!navigator.permissions?.query) {
          return "unsupported";
        }
        try {
          const result = await navigator.permissions.query({ name });
          return result?.state || "unsupported";
        } catch {
          return "unsupported";
        }
      };

      const sourceText = collectText();
      const lowerUrl = String(location.href || "").toLowerCase();
      const keywordMap = {
        microphone: ["getusermedia", "microphone", "audioinput", "mediadevices", "webrtc", "audiocontext"],
        camera: ["getusermedia", "camera", "videoinput", "mediadevices", "webrtc", "facingmode"],
        location: ["geolocation", "watchposition", "getcurrentposition", "navigator.geolocation"]
      };

      const hasIframeAllowToken = (token) => {
        const iframes = Array.from(document.querySelectorAll("iframe[allow]"));
        return iframes.some((iframe) => {
          const allow = String(iframe.getAttribute("allow") || "").toLowerCase();
          return allow.includes(token);
        });
      };

      const activeTracks = (() => {
        try {
          const mediaEls = Array.from(document.querySelectorAll("video, audio"));
          const result = { audio: false, video: false };
          for (const el of mediaEls) {
            const stream = el.srcObject;
            if (!stream || typeof stream.getTracks !== "function") {
              continue;
            }
            const tracks = stream.getTracks();
            if (tracks.some((track) => track.readyState === "live" && track.kind === "audio")) {
              result.audio = true;
            }
            if (tracks.some((track) => track.readyState === "live" && track.kind === "video")) {
              result.video = true;
            }
            if (result.audio && result.video) {
              break;
            }
          }
          return result;
        } catch {
          return { audio: false, video: false };
        }
      })();

      const resourceHints = (() => {
        const resources = Array.from(performance.getEntriesByType("resource") || []);
        const values = resources.map((entry) => String(entry.name || "").toLowerCase());
        return {
          mic: values.some((value) => value.includes("getusermedia") || value.includes("webrtc") || value.includes("mediadevices")),
          cam: values.some((value) => value.includes("getusermedia") || value.includes("webrtc") || value.includes("mediadevices")),
          geo: values.some((value) => value.includes("geo") || value.includes("maps") || value.includes("location"))
        };
      })();

      permissionStates.microphone = await readPermissionState("microphone");
      permissionStates.camera = await readPermissionState("camera");
      permissionStates.geolocation = await readPermissionState("geolocation");

      const sourceHas = (keywords) => keywords.some((keyword) => sourceText.includes(keyword) || lowerUrl.includes(keyword));
      const micPolicy = allowedFeatures.includes("microphone") || hasIframeAllowToken("microphone");
      const camPolicy = allowedFeatures.includes("camera") || hasIframeAllowToken("camera");
      const geoPolicy = allowedFeatures.includes("geolocation") || hasIframeAllowToken("geolocation");

      const micPermissionPossible = permissionStates.microphone === "granted" || permissionStates.microphone === "prompt";
      const camPermissionPossible = permissionStates.camera === "granted" || permissionStates.camera === "prompt";
      const geoPermissionPossible = permissionStates.geolocation === "granted" || permissionStates.geolocation === "prompt";

      const micIntent = sourceHas(keywordMap.microphone);
      const camIntent = sourceHas(keywordMap.camera);
      const geoIntent = sourceHas(keywordMap.location);

      const micGranted = permissionStates.microphone === "granted";
      const camGranted = permissionStates.camera === "granted";
      const geoGranted = permissionStates.geolocation === "granted";

      const micDetected =
        activeTracks.audio ||
        (micGranted && (micIntent || micPolicy || resourceHints.mic)) ||
        (micIntent && (micPolicy || resourceHints.mic));
      const camDetected =
        activeTracks.video ||
        (camGranted && (camIntent || camPolicy || resourceHints.cam)) ||
        (camIntent && (camPolicy || resourceHints.cam));
      const geoDetected =
        (geoGranted && (geoIntent || geoPolicy || resourceHints.geo)) ||
        (geoIntent && (geoPolicy || resourceHints.geo));

      const pageSignals = {
        microphone: micDetected,
        camera: camDetected,
        location: geoDetected,
        third_party_data_alert: false,
        third_party_endpoints: [],
        evidence: []
      };

      const resources = Array.from(performance.getEntriesByType("resource") || []);
      const thirdPartyResources = resources.map((entry) => entry.name).filter((resourceUrl) => isThirdParty(resourceUrl));
      const thirdPartyEndpoints = Array.from(new Set(thirdPartyResources)).slice(0, 10);
      const suspiciousThirdParty = thirdPartyEndpoints.filter((resourceUrl) => {
        const lowered = resourceUrl.toLowerCase();
        return lowered.includes("track") || lowered.includes("analytics") || lowered.includes("pixel") || lowered.includes("beacon") || lowered.includes("collect") || lowered.includes("adservice");
      });

      if (thirdPartyEndpoints.length > 0) {
        pageSignals.evidence.push(`Detected ${thirdPartyEndpoints.length} third-party network endpoint(s).`);
      }
      if (suspiciousThirdParty.length > 0) {
        pageSignals.third_party_data_alert = true;
        pageSignals.evidence.push("Suspicious third-party tracking endpoints were detected.");
      }
      if (pageSignals.microphone || pageSignals.camera || pageSignals.location) {
        pageSignals.evidence.push("Page source or policy indicates sensitive browser permissions are in use or requested.");
      }

      if (activeTracks.audio || activeTracks.video) {
        pageSignals.evidence.push(
          `Detected active media stream usage (audio: ${activeTracks.audio}, video: ${activeTracks.video}).`
        );
      }

      if (permissionStates.microphone !== "unsupported" || permissionStates.camera !== "unsupported" || permissionStates.geolocation !== "unsupported") {
        pageSignals.evidence.push(
          `Permission states - mic: ${permissionStates.microphone}, cam: ${permissionStates.camera}, geo: ${permissionStates.geolocation}.`
        );
      }

      pageSignals.third_party_endpoints = thirdPartyEndpoints;
      return pageSignals;
      }
    });

    return results[0]?.result || {
      microphone: false,
      camera: false,
      location: false,
      third_party_data_alert: false,
      third_party_endpoints: [],
      evidence: ["Unable to collect page privacy signals."]
    };
  } catch {
    return {
    microphone: false,
    camera: false,
    location: false,
    third_party_data_alert: false,
    third_party_endpoints: [],
    evidence: ["Unable to collect page privacy signals."]
    };
  }
}

async function scanTab(tabUrl) {
  if (!tabUrl || !isHttpScheme(tabUrl)) {
    throw new Error("Only http/https pages can be scanned.");
  }

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabId = tabs[0]?.id;
  if (typeof tabId !== "number") {
    throw new Error("Unable to identify the active tab.");
  }

  const cookies = await chrome.cookies.getAll({ url: tabUrl });
  const state = await chrome.storage.local.get(["reports"]);
  const recentReports = Array.isArray(state.reports) ? state.reports.slice(0, 10) : [];
  const pageSignals = await collectPageSignals(tabId, tabUrl);
  const payload = {
    url: tabUrl,
    scanned_at: new Date().toISOString(),
    recent_reports: recentReports,
    page_signals: pageSignals,
    cookies: cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: normalizeSameSite(c.sameSite),
      session: c.session,
      expirationDate: c.expirationDate || null
    }))
  };

  const backendUrl = await getBackendUrl();
  const response = await fetch(`${backendUrl}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Backend error ${response.status}: ${text}`);
  }

  const result = await response.json();
  await saveReportSummary(result);
  return result;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SCAN_TAB") {
    scanTab(message.url)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "GET_REPORTS") {
    chrome.storage.local.get(["reports"]).then((state) => {
      sendResponse({ ok: true, reports: state.reports || [] });
    });
    return true;
  }

  return false;
});
