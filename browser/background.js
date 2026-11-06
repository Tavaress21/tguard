import { analyze } from "./analyzer.js";
import { hex, verify } from "./feeds.js";

const BASE = "https://tguard.luis-tavares.pt/updates/";
const FEEDS_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOnT4E1OQKC+pM8t/XL6AhFCqGOA8GeZqHwfjFHxfZRJtP9BPrltnjNIIwzBS9dHesYV5h6omGLgjU4Qs2KuijQ==";
const BLOCK_SCORE = 50;
const UPDATE_MINUTES = 180;

let lists = null;

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("update", { periodInMinutes: UPDATE_MINUTES, delayInMinutes: 1 });
  updateLists().catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create("update", { periodInMinutes: UPDATE_MINUTES, delayInMinutes: 1 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "update") updateLists().catch(() => {});
});

async function get(name) {
  const r = await fetch(BASE + name, { cache: "no-store" });
  if (!r.ok) throw new Error(`${name}: ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

async function updateLists() {
  const manifestBytes = await get("feeds.json");
  const signature = await get("feeds.json.sig");
  if (!(await verify(manifestBytes, signature, FEEDS_KEY))) throw new Error("invalid signature");
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
  const entry = manifest.urls;
  if (!entry || !entry.name) throw new Error("no url list");
  const file = await get(entry.name);
  if (hex(await crypto.subtle.digest("SHA-256", file)) !== String(entry.sha256).toLowerCase()) throw new Error("hash mismatch");
  const text = new TextDecoder().decode(file);
  const count = text.split("\n").filter((l) => l.trim() && !l.startsWith("#")).length;
  await chrome.storage.local.set({ listText: text, listUpdated: Date.now(), listCount: count, listGenerated: manifest.generated || null });
  lists = null;
  return count;
}

async function getLists() {
  if (lists) return lists;
  const { listText = "" } = await chrome.storage.local.get("listText");
  const urls = new Set();
  const hosts = new Set();
  for (const raw of listText.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("host:")) hosts.add(line.slice(5).toLowerCase());
    else urls.add(line);
  }
  lists = { urls, hosts };
  return lists;
}

async function isEnabled() {
  const { enabled = true } = await chrome.storage.local.get("enabled");
  return enabled;
}

async function isAllowed(host) {
  const { allowed = [] } = await chrome.storage.session.get("allowed");
  return allowed.includes(host);
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
  if (!(await isEnabled())) return;
  let host;
  try { host = new URL(details.url).hostname.toLowerCase(); } catch { return; }
  if (await isAllowed(host)) return;
  const result = analyze(details.url, await getLists());
  if (result.score < BLOCK_SCORE) return;
  const { blocked = 0 } = await chrome.storage.local.get("blocked");
  await chrome.storage.local.set({ blocked: blocked + 1, lastBlocked: { url: details.url, at: Date.now() } });
  const payload = encodeURIComponent(JSON.stringify({ url: details.url, score: result.score, reasons: result.reasons }));
  chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL("blocked.html") + "#" + payload });
});

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  (async () => {
    if (message.type === "status") {
      const data = await chrome.storage.local.get(["listUpdated", "listCount", "blocked", "enabled"]);
      reply({ enabled: data.enabled !== false, updated: data.listUpdated || null, count: data.listCount || 0, blocked: data.blocked || 0 });
    } else if (message.type === "toggle") {
      await chrome.storage.local.set({ enabled: !!message.enabled });
      reply({ ok: true });
    } else if (message.type === "update") {
      try { reply({ ok: true, count: await updateLists() }); } catch (e) { reply({ ok: false, error: String(e.message || e) }); }
    } else if (message.type === "allow") {
      let host = "";
      try { host = new URL(message.url).hostname.toLowerCase(); } catch { reply({ ok: false }); return; }
      const { allowed = [] } = await chrome.storage.session.get("allowed");
      if (!allowed.includes(host)) allowed.push(host);
      await chrome.storage.session.set({ allowed });
      if (sender.tab && sender.tab.id !== undefined) chrome.tabs.update(sender.tab.id, { url: message.url });
      reply({ ok: true });
    } else if (message.type === "check") {
      reply(analyze(message.url, await getLists()));
    }
  })();
  return true;
});
