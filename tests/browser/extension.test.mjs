import { createSign, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { analyze } from "../../browser/analyzer.js";
import { verify } from "../../browser/feeds.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const keys = path.join(here, "..", "TGuard.Tests", "keys");
let failed = 0;
const check = (ok, msg) => {
  if (ok) console.log("  ok    " + msg);
  else { console.log("  FAIL  " + msg); failed++; }
};

const safe = [
  "https://www.amazon.es/dp/123", "https://login.microsoftonline.com/common/oauth2", "https://accounts.google.pt/signin",
  "https://www.minhasfinancas.pt/login", "https://mainstream.com/", "https://apply.com/", "https://www.pineapple.pt/",
  "https://www.paypal.com/signin", "https://www.santander.es/", "https://store.steampowered.com/login", "https://www.continente.pt/",
  "https://supercontinente.pt/", "https://www.portaldasfinancas.gov.pt/pt/home.action", "https://www.office.com/",
  "https://outlook.live.com/mail/", "https://www.youtube.com/watch?v=1", "https://www.mbway.pt/", "https://www.cgd.pt",
  "https://online.millenniumbcp.pt/", "https://www.github.com/login", "https://app.revolut.com/login", "https://luis-tavares.pt/",
];
const scams = [
  "https://mbway-reembolso.com/login", "https://mbway.com/pagar", "https://ctt-encomendas.top/pagar", "https://millenium-bcp.com/entrar",
  "http://amazon-pagamentos.com/verify", "https://caixageral-acesso.top/entrar", "https://paypa1.com/login",
  "https://portaldasfinancas-reembolso.com/", "https://seg-social-apoio.com/", "http://185.22.1.9/cgd/login",
];
for (const u of safe) check(analyze(u, null).score < 50, `allowed ${u}`);
for (const u of scams) check(analyze(u, null).score >= 50, `blocked ${u}`);

const lists = { urls: new Set(["http://phish.example/login"]), hosts: new Set(["burla.example"]) };
check(analyze("http://phish.example/login", lists).score >= 90, "exact URL from the list");
check(analyze("https://pagar.burla.example/x", lists).score >= 90, "subdomain of a listed host");
check(analyze("https://naoburla.example/x", lists).score < 50, "similar host is not listed");

const pem = readFileSync(path.join(keys, "test-feeds.key.pem"), "utf8");
const pub = readFileSync(path.join(keys, "test-feeds.pub.pem"), "utf8").replace(/-----[^-]+-----|\s/g, "");
let good = 0;
let tampered = 0;
for (let i = 0; i < 200; i++) {
  const data = randomBytes(64 + i);
  const sig = createSign("SHA256").update(data).sign(pem);
  if (await verify(data, new Uint8Array(sig), pub)) good++;
  const bad = Buffer.from(data);
  bad[3] ^= 0xff;
  if (!(await verify(bad, new Uint8Array(sig), pub))) tampered++;
}
check(good === 200, `valid signatures accepted (${good}/200)`);
check(tampered === 200, `tampered data rejected (${tampered}/200)`);

console.log(failed === 0 ? "\nall passed" : `\n${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
