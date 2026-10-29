const API = "http://127.0.0.1:5000/api/scan";
const ownPages = new Set(["chrome://", "chrome-extension://", "edge://", "about:", "devtools://", "view-source:"]);

function shouldSkip(url) {
  if (!url || ownPages.has(url.slice(0, url.indexOf(":") + 1))) return true;
  return !url.startsWith("http://") && !url.startsWith("https://");
}

async function scanUrl(url, tabId) {
  if (shouldSkip(url)) return;
  try {
    const response = await fetch(API, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url}),
      signal: AbortSignal.timeout(3500)
    });
    if (!response.ok) throw new Error("Backend returned HTTP " + response.status);
    const data = await response.json();
    await chrome.storage.local.set({lastScan: {...data, checkedAt: new Date().toISOString(), tabId}});
    const color = data.label === "HIGH RISK" ? "#d93025" : data.label === "SUSPICIOUS" ? "#e5a000" : "#188038";
    await chrome.action.setBadgeBackgroundColor({color, tabId});
    await chrome.action.setBadgeText({text: data.risk_score >= 30 ? "!" : "OK", tabId});
    if (data.risk_score >= 60) {
      chrome.notifications.create("cybershield-" + tabId, {
        type: "basic", iconUrl: "icon.png",
        title: "CyberShield: High-risk URL",
        message: "Risk score " + data.risk_score + "/100. Avoid entering passwords or payment details.",
        priority: 2
      }).catch(() => {});
    } else if (data.risk_score >= 30) {
      chrome.notifications.create("cybershield-" + tabId, {
        type: "basic", iconUrl: "icon.png",
        title: "CyberShield: Suspicious URL",
        message: "Risk score " + data.risk_score + "/100. Review the URL before sharing information.",
        priority: 1
      }).catch(() => {});
    }
  } catch (error) {
    await chrome.storage.local.set({lastError: "Could not reach local scanner. Start the Python backend at 127.0.0.1:5000.", lastUrl: url});
    await chrome.action.setBadgeText({text: "OFF", tabId});
    await chrome.action.setBadgeBackgroundColor({color: "#64748b", tabId});
  }
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) scanUrl(details.url, details.tabId);
});
chrome.tabs.onActivated.addListener(async ({tabId}) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url) scanUrl(tab.url, tabId);
  } catch (_) {}
});
