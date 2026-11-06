import { t, lang, reportUrl } from "./strings.js";

const $ = (id) => document.getElementById(id);
const send = (message) => new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));

$("subtitle").textContent = chrome.runtime.getManifest().version;
$("listsLabel").textContent = t("lists");
$("blockedLabel").textContent = t("blocked");
$("updatedLabel").textContent = t("updated");
$("update").textContent = t("updateNow");
$("report").textContent = t("reportSite");
$("footer").textContent = t("footer");

async function render() {
  const s = await send({ type: "status" });
  $("state").className = "state " + (s.enabled ? "on" : "off");
  $("stateText").textContent = s.enabled ? t("on") : t("off");
  $("toggle").textContent = s.enabled ? t("turnOff") : t("turnOn");
  $("toggle").onclick = async () => { await send({ type: "toggle", enabled: !s.enabled }); render(); };
  $("lists").textContent = s.count.toLocaleString(lang === "pt" ? "pt-PT" : "en-GB");
  $("blocked").textContent = s.blocked.toLocaleString(lang === "pt" ? "pt-PT" : "en-GB");
  $("updated").textContent = s.updated ? new Date(s.updated).toLocaleString(lang === "pt" ? "pt-PT" : "en-GB", { dateStyle: "short", timeStyle: "short" }) : t("never");
}

chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
  if (!tab || !/^https?:/i.test(tab.url || "")) { $("report").style.display = "none"; return; }
  $("report").href = reportUrl(tab.url);
  const r = await send({ type: "check", url: tab.url });
  const host = new URL(tab.url).hostname;
  $("site").innerHTML = "";
  const b = document.createElement("b");
  b.textContent = host;
  $("site").append(b, " · ", r.score >= 40 ? t("risky") : t("safe"));
});

$("update").addEventListener("click", async () => {
  $("update").disabled = true;
  $("update").textContent = t("updating");
  await send({ type: "update" });
  $("update").disabled = false;
  $("update").textContent = t("updateNow");
  render();
});

render();
