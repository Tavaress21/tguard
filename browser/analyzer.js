export const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
  "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "shorturl.gg", "v.gd"]);

export const RISKY_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "cam",
  "icu", "monster", "sbs", "cfd", "lol", "quest", "buzz", "cyou", "bond"]);

export const FREE_HOSTING = ["000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app", "pages.dev", "workers.dev",
  "glitch.me", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "netlify.app", "vercel.app", "blogspot.com",
  "ipfs.io", "dweb.link", "r2.dev", "duckdns.org", "github.io", "square.site", "webflow.io", "framer.app"];

export const BRANDS = {
  paypal: "paypal.com", microsoft: "microsoft.com", office365: "office.com", outlook: "outlook.com", apple: "apple.com",
  icloud: "icloud.com", google: "google.com", amazon: "amazon.com", netflix: "netflix.com", facebook: "facebook.com",
  instagram: "instagram.com", whatsapp: "whatsapp.com", fedex: "fedex.com", caixadirecta: "cgd.pt", caixageral: "cgd.pt",
  millenniumbcp: "millenniumbcp.pt", millennium: "millenniumbcp.pt", novobanco: "novobanco.pt", santander: "santander.pt",
  bancobpi: "bancobpi.pt", mbway: "mbway.pt", portaldasfinancas: "portaldasfinancas.gov.pt", financas: "portaldasfinancas.gov.pt",
  "seg-social": "seg-social.pt", segsocial: "seg-social.pt", vodafone: "vodafone.pt", activobank: "activobank.pt",
  montepio: "montepio.pt", creditoagricola: "creditoagricola.pt", linkedin: "linkedin.com", docusign: "docusign.com",
  dropbox: "dropbox.com", binance: "binance.com", coinbase: "coinbase.com", steam: "steampowered.com", correios: "ctt.pt",
  "ctt-expresso": "ctt.pt", worten: "worten.pt", continente: "continente.pt", viaverde: "viaverde.pt", bancoctt: "bancoctt.pt",
};

const HOMOGLYPHS = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a" };
const SECOND_LEVEL = new Set(["co", "com", "gov", "org", "net", "edu", "ac"]);
const OFFICIAL = new Set(Object.values(BRANDS));

export function registeredDomain(host) {
  const parts = host.toLowerCase().replace(/^\.+|\.+$/g, "").split(".");
  if (parts.length >= 3 && SECOND_LEVEL.has(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) return parts.slice(-3).join(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : host.toLowerCase();
}

export function levenshtein(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

const LOGIN_WORDS = /login|signin|verify|account|password|conta|senha|pagamento|entrar|reembolso|multa|encomenda/i;

export function analyze(rawUrl, lists) {
  const reasons = [];
  let url;
  try { url = new URL(rawUrl); } catch { return { score: 0, reasons }; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return { score: 0, reasons };
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return { score: 0, reasons };

  const add = (score, key, ...args) => reasons.push({ score, key, args });

  if (lists && (lists.urls.has(rawUrl) || lists.urls.has(rawUrl.replace(/\/$/, "")) || hostListed(host, lists.hosts))) add(90, "blocklist");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) add(30, "ip");
  if (url.username) add(35, "userinfo");
  if (host.includes("xn--")) add(30, "punycode", host);
  if (SHORTENERS.has(host)) add(10, "shortener", host);
  const tld = host.slice(host.lastIndexOf(".") + 1);
  if (RISKY_TLDS.has(tld)) add(15, "tld", tld);
  if (FREE_HOSTING.some((f) => host === f || host.endsWith("." + f))) add(15, "freehost", host);
  if ((host.match(/\./g) || []).length >= 4) add(10, "subdomains");
  if (url.protocol === "http:" && LOGIN_WORDS.test(rawUrl)) add(15, "httplogin");

  const reg = registeredDomain(host);
  const regLabel = reg.split(".")[0].replace(/-/g, "");
  const normalized = [...host].map((c) => HOMOGLYPHS[c] || c).filter((c) => c !== "-").join("");
  const official = [...OFFICIAL].some((o) => reg === o || host.endsWith("." + o));
  if (!official) {
    for (const [brand, home] of Object.entries(BRANDS)) {
      const b = brand.replace(/-/g, "");
      if (b.length >= 5 && normalized.includes(b)) { add(LOGIN_WORDS.test(rawUrl) ? 50 : 35, "brand", brand, home); break; }
      if (b.length >= 5 && regLabel.length >= 4 && levenshtein(regLabel, b) === 1) { add(50, "typo", home); break; }
    }
  }

  const sorted = reasons.map((r) => r.score).sort((a, b) => b - a);
  const score = sorted.length ? Math.min(100, sorted[0] + Math.floor(sorted.slice(1).reduce((s, x) => s + x, 0) / 2)) : 0;
  return { score, reasons };
}

function hostListed(host, hosts) {
  if (!hosts || hosts.size === 0) return false;
  const parts = host.split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    if (hosts.has(parts.slice(i).join("."))) return true;
  }
  return false;
}
