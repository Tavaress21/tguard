import { t, falsePositiveUrl } from "./strings.js";

let data = { url: "", reasons: [] };
try { data = JSON.parse(decodeURIComponent(location.hash.slice(1))); } catch {}

const $ = (id) => document.getElementById(id);
document.documentElement.lang = navigator.language || "pt-PT";
document.title = "TGuard · " + t("title");
$("title").textContent = t("title");
$("lead").textContent = t("lead");
$("url").textContent = data.url;
$("why").textContent = t("why");
$("back").textContent = t("back");
$("report").textContent = t("report");
$("report").href = falsePositiveUrl(data.url);
$("note").textContent = t("proceedNote");
$("proceed").textContent = t("proceed");
$("footer").textContent = t("footer");

for (const r of (data.reasons || []).sort((a, b) => b.score - a.score)) {
  const li = document.createElement("li");
  li.textContent = t(r.key, ...(r.args || []));
  $("reasons").appendChild(li);
}

$("back").addEventListener("click", () => {
  if (history.length > 2) history.go(-2);
  else chrome.tabs.getCurrent((tab) => tab && chrome.tabs.remove(tab.id));
});

$("proceed").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "allow", url: data.url });
});
