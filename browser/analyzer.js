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
  ctt: "ctt.pt", cgd: "cgd.pt", bpi: "bancobpi.pt", edp: "edp.pt", meo: "meo.pt",
};

export const OFFICIAL_DOMAINS = new Set([
  "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "azure.com", "windows.net", "sharepoint.com",
  "msn.com", "bing.com", "xbox.com", "skype.com", "microsoft.com", "hotmail.com", "msauth.net", "msftauth.net",
  "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "gmail.com", "google.com", "withgoogle.com",
  "apple.com", "icloud.com", "apple.news", "mzstatic.com", "paypal.com", "paypal.me", "paypalobjects.com",
  "amazonaws.com", "media-amazon.com", "amazon.com", "a2z.com", "facebook.com", "fb.com", "fbcdn.net", "messenger.com",
  "meta.com", "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net", "linkedin.com", "licdn.com",
  "netflix.com", "nflxext.com", "steampowered.com", "steamcommunity.com", "steamstatic.com", "dropbox.com",
  "dropboxusercontent.com", "docusign.com", "docusign.net", "binance.com", "coinbase.com", "fedex.com",
  "caixadirecta.cgd.pt", "cgd.pt", "millenniumbcp.pt", "novobanco.pt", "santander.pt", "bancobpi.pt", "mbway.pt",
  "portaldasfinancas.gov.pt", "seg-social.pt", "vodafone.pt", "activobank.pt", "montepio.pt", "creditoagricola.pt",
  "ctt.pt", "worten.pt", "continente.pt", "viaverde.pt", "bancoctt.pt", "sibs.pt", "sibs.com", "bpi.pt", "edp.pt", "edp.com", "meo.pt",
]);

const GLOBAL_BRANDS = new Set(["amazon", "google", "apple", "microsoft", "paypal", "netflix", "facebook", "instagram", "linkedin", "dropbox",
  "docusign", "binance", "coinbase", "fedex", "santander", "vodafone", "whatsapp", "outlook", "icloud"]);
const SHORT_BRANDS = new Set(["ctt", "cgd", "bpi", "edp", "meo"]);
const GENERIC_WORDS = new Set(["financas", "continente", "steam", "apple", "outlook", "correios"]);

const HOMOGLYPHS = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a" };
const SECOND_LEVEL = new Set(["co", "com", "gov", "org", "net", "edu", "ac"]);

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
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) add(LOGIN_WORDS.test(rawUrl) ? 50 : 30, "ip");
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
  const imitated = imitatedBrand(host);
  if (imitated) add(imitationScore(host, imitated, rawUrl), "brand", imitated, BRANDS[imitated]);
  else if (!isOfficialHost(host) && regLabel.length >= 6) {
    for (const [brand, home] of Object.entries(BRANDS)) {
      const b = brand.replace(/-/g, "");
      if (b.length >= 6 && levenshtein(regLabel, b) === 1 && ![...OFFICIAL_DOMAINS].some((o) => o.split(".")[0] === regLabel)) {
        add(50, "typo", home);
        break;
      }
    }
  }

  const sorted = reasons.map((r) => r.score).sort((a, b) => b - a);
  const score = sorted.length ? Math.min(100, sorted[0] + Math.floor(sorted.slice(1).reduce((s, x) => s + x, 0) / 2)) : 0;
  return { score, reasons };
}

export function isOfficialHost(host) {
  const reg = registeredDomain(host);
  if (OFFICIAL_DOMAINS.has(reg) || [...OFFICIAL_DOMAINS].some((o) => host.endsWith("." + o))) return true;
  return GLOBAL_BRANDS.has(reg.split(".")[0]);
}

const LURES = /reembolso|pagamento|pagar|multa|encomenda|entrega|seguranca|acesso|verifica|verify|login|signin|conta|apoio|suporte|support|update|atualiza|bloque|cancel|premio|oferta|cliente|portal|online|secure|app/;

export function imitationScore(host, brand, rawUrl) {
  const b = brand.replace(/-/g, "");
  const reg = registeredDomain(host);
  const regLabel = reg.split(".")[0].replace(/-/g, "");
  let score = 35;
  if (norm(regLabel) === norm(b) || norm(host) !== host.toLowerCase()) score = 55;
  if (LURES.test(host)) score = Math.max(score, 55);
  if (LOGIN_WORDS.test(rawUrl)) score += 5;
  if (reg.endsWith(".pt")) score = Math.min(score, 45);
  return Math.min(score, 70);
}

const norm = (s) => [...s.toLowerCase()].map((c) => HOMOGLYPHS[c] || c).join("");

export function imitatedBrand(host) {
  if (isOfficialHost(host)) return null;
  const normalized = norm(host);
  const tokens = normalized.split(/[.-]/);
  const joined = normalized.replace(/-/g, "");
  for (const brand of Object.keys(BRANDS)) {
    const b = norm(brand.replace(/-/g, ""));
    if (b.length < 5 && !SHORT_BRANDS.has(b)) continue;
    if (tokens.includes(b)) return brand;
    if (brand.includes("-") && joined.includes(b)) return brand;
    if (GENERIC_WORDS.has(b) || b.length < 6) continue;
    if (tokens.some((t) => t.length <= b.length + 10 && (t.startsWith(b) || t.endsWith(b)))) return brand;
  }
  return null;
}

function hostListed(host, hosts) {
  if (!hosts || hosts.size === 0) return false;
  const parts = host.split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    if (hosts.has(parts.slice(i).join("."))) return true;
  }
  return false;
}
