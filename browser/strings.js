const PT = {
  title: "Site bloqueado",
  lead: "O TGuard bloqueou esta página porque pode ser uma burla ou phishing.",
  why: "Porque foi bloqueado",
  back: "Voltar para trás",
  proceed: "Abrir mesmo assim",
  proceedNote: "Só continues se tiveres a certeza de que o site é seguro. Nunca introduzas dados bancários ou códigos MB WAY num site que chegou por SMS ou email.",
  report: "Isto é um erro? Avisa-nos",
  blocklist: "Está na lista de sites maliciosos do TGuard",
  ip: "O endereço é um número IP em vez de um nome",
  userinfo: "O endereço esconde o destino real com um @",
  punycode: "Usa letras parecidas para imitar outro site ({0})",
  shortener: "Link encurtado ({0})",
  tld: "Domínio .{0}, muito usado em burlas",
  freehost: "Alojamento gratuito usado em phishing ({0})",
  subdomains: "Demasiados subdomínios",
  httplogin: "Pede dados sem ligação segura (http)",
  brand: "Imita {0}, mas não é o site oficial ({1})",
  typo: "Nome muito parecido com {0}",
  on: "Proteção ativa",
  off: "Proteção desligada",
  turnOn: "Ligar",
  turnOff: "Desligar",
  lists: "Sites na lista",
  blocked: "Bloqueados",
  updated: "Lista atualizada",
  never: "nunca",
  updateNow: "Atualizar lista",
  updating: "A atualizar…",
  reportSite: "Denunciar este site",
  safe: "Este site parece seguro",
  risky: "Este site tem sinais de risco",
  footer: "TGuard · luis-tavares.pt",
};

const EN = {
  title: "Site blocked",
  lead: "TGuard blocked this page because it may be a scam or phishing.",
  why: "Why it was blocked",
  back: "Go back",
  proceed: "Open anyway",
  proceedNote: "Only continue if you're sure the site is safe. Never enter bank details or MB WAY codes on a site that reached you by SMS or email.",
  report: "Is this a mistake? Let us know",
  blocklist: "It's on TGuard's list of malicious sites",
  ip: "The address is an IP number instead of a name",
  userinfo: "The address hides its real destination with an @",
  punycode: "Uses look-alike letters to imitate another site ({0})",
  shortener: "Shortened link ({0})",
  tld: ".{0} domain, widely used in scams",
  freehost: "Free hosting often used for phishing ({0})",
  subdomains: "Too many subdomains",
  httplogin: "Asks for details without a secure connection (http)",
  brand: "Imitates {0} but isn't the official site ({1})",
  typo: "Name very close to {0}",
  on: "Protection on",
  off: "Protection off",
  turnOn: "Turn on",
  turnOff: "Turn off",
  lists: "Sites on the list",
  blocked: "Blocked",
  updated: "List updated",
  never: "never",
  updateNow: "Update list",
  updating: "Updating…",
  reportSite: "Report this site",
  safe: "This site looks safe",
  risky: "This site shows risk signs",
  footer: "TGuard · luis-tavares.pt",
};

export const lang = (navigator.language || "pt").toLowerCase().startsWith("pt") ? "pt" : "en";

export function t(key, ...args) {
  const s = (lang === "pt" ? PT : EN)[key] ?? key;
  return args.reduce((acc, a, i) => acc.replaceAll(`{${i}}`, String(a)), s);
}

export function reportUrl(url) {
  return "https://luis-tavares.pt/tguard/denunciar?tipo=scam&valor=" + encodeURIComponent(url);
}

export function falsePositiveUrl(url) {
  return "https://luis-tavares.pt/tguard/denunciar?tipo=other&valor=" + encodeURIComponent(url);
}
