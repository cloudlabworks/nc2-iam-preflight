#!/usr/bin/env node
// Snapshot the public Nutanix NC2 documentation pages this tool's permission lists come from.
// The portal renders client-side, so a headless Chrome loads each page and saves the topic text
// to sources/<name>.txt with the URL and fetch time. Guest access only: no login, no cookies.
//   node tools/fetch-sources.mjs            (needs Google Chrome installed)
import { spawn } from "node:child_process"; import { writeFileSync, mkdtempSync, rmSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
const P = "https://portal.nutanix.com/page/documents/details?targetId=";
const PAGES = {
  "gcp-appendix-role-permissions": P + "Nutanix-Cloud-Clusters-Google-Cloud:nc2-clusters-google-cloud-appendix-role-permissions-c.html",
  "gcp-service-accounts": P + "Nutanix-Cloud-Clusters-Google-Cloud:nc2-clusters-google-cloud-service-account-c.html",
  "gcp-sa-cluster-nodes": P + "Nutanix-Cloud-Clusters-Google-Cloud:nc2-clusters-google-cloud-enable-compute-engine-api-t.html",
  "gcp-sa-nc2-console": P + "Nutanix-Cloud-Clusters-Google-Cloud:nc2-clusters-google-cloud-config-service-account-nc2-t.html",
  "gcp-requirements": P + "Nutanix-Cloud-Clusters-Google-Cloud:nc2-clusters-google-cloud-prerequisites-c.html",
  "aws-requirements": P + "Nutanix-Clusters-AWS:aws-clusters-aws-requirements-c.html",
  "azure-custom-role": P + "Nutanix-Cloud-Clusters-Azure:nc2-clusters-azure-create-custom-iam-role-t.html",
};
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const ud = mkdtempSync(join(tmpdir(), "nc2src-"));
const chrome = spawn(CHROME, ["--headless=new", "--remote-debugging-port=9334", "--user-data-dir=" + ud, "--no-first-run", "about:blank"], { stdio: "ignore" });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let ws; for (let i = 0; i < 40 && !ws; i++) { try { const t = await (await fetch("http://127.0.0.1:9334/json")).json(); const p = t.find((x) => x.type === "page"); if (p) ws = new WebSocket(p.webSocketDebuggerUrl); } catch {} if (!ws) await wait(250); }
await new Promise((r) => ws.addEventListener("open", r));
let id = 0; const pend = {}; ws.addEventListener("message", (m) => { const d = JSON.parse(m.data); if (d.id && pend[d.id]) { pend[d.id](d); delete pend[d.id]; } });
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pend[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => (await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true })).result?.result?.value;
let failed = 0;
for (const [name, url] of Object.entries(PAGES)) {
  await send("Page.navigate", { url });
  let text = "";
  for (let i = 0; i < 20; i++) { await wait(1000);
    // the topic body sits after the last occurrence of its own title (the first is the table of contents)
    text = await ev(`(()=>{const t=document.body.innerText;const h=document.querySelector('h1,h2.title,.title');const k=t.indexOf('Last Updated:');if(k<0)return '';const s=t.lastIndexOf('\\n',t.lastIndexOf('\\n',k-1)-1);const e=t.indexOf('Documentation Support and Feedback',k);return t.slice(s+1,e>0?e:undefined).trim()})()`);
    if (text && text.length > 200) break; }
  if (!text) { console.error("FAIL", name); failed++; continue; }
  writeFileSync(new URL(`../sources/${name}.txt`, import.meta.url), `Source: ${url}\nFetched: ${new Date().toISOString()} (guest view, public)\n\n${text}\n`);
  console.log("ok  ", name, text.length);
}
ws.close(); chrome.kill(); rmSync(ud, { recursive: true, force: true }); process.exit(failed ? 1 : 0);
