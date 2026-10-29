const content = document.getElementById("content");
chrome.storage.local.get(["lastScan", "lastError"], ({lastScan, lastError}) => {
  if (!lastScan) {
    content.textContent = lastError || "No scan yet. Start the local backend and visit a website.";
    return;
  }
  const label = document.createElement("div");
  label.className = "label " + (lastScan.label === "HIGH RISK" ? "high" : lastScan.label === "SUSPICIOUS" ? "medium" : "low");
  label.textContent = lastScan.label;
  const score = document.createElement("div");
  score.className = "score";
  score.textContent = lastScan.risk_score + "/100";
  const url = document.createElement("p");
  url.className = "url muted";
  url.textContent = lastScan.normalized_url;
  const heading = document.createElement("p");
  heading.textContent = "Warning signs";
  const list = document.createElement("ul");
  list.className = "reasons";
  (lastScan.reasons || []).slice(0, 5).forEach(reason => {
    const item = document.createElement("li");
    item.textContent = reason;
    list.appendChild(item);
  });
  content.replaceChildren(label, score, url, heading, list);
});
