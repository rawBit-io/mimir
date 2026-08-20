import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html", host: "localhost" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the guarded five-by-five visual composer", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Mimir — Bitcoin Script Builder<\/title>/);
  assert.match(html, /Build recovery paths\. Keep the freedom\./);
  assert.match(html, /5 keys · 5 paths · guarded Miniscript · offline/i);
  assert.match(html, />Keys</);
  assert.match(html, />New path</);
  assert.match(html, /PATH BLOCKS/);
  assert.match(html, /PATH CANVAS/);
  assert.match(html, />Your paths</);
  assert.match(html, /COMPATIBILITY GUARD/);
  assert.match(html, /exact same set/i);
  assert.match(html, /Owner \/ Recovery marks are visual only/);
  assert.match(html, /LIVE BITCOIN SCRIPT/i);
  assert.match(html, /Load demo/);
  assert.match(html, /Add key/);
  assert.match(html, /ADD PATH/i);
  assert.match(html, /Technical details/);
  assert.match(html, /http:\/\/localhost\/og\.png/);
  assert.match(html, /noindex/);
  assert.match(html, /connect-src &#x27;none&#x27;/);
  assert.doesNotMatch(
    html,
    /MIMIR \/\/ 5×5 RECOVERY|One primary path\. Up to four recovery stages\.|Up to five public keys · up to five fixed spending paths|Each later CLTV date needs one fewer signature\.|Recovery ladder/i,
  );
  assert.doesNotMatch(
    html,
    /20 public keys|20 keys|up to 20|10 rules|RULE BLOCKS|RULE CANVAS|YOUR RULES|PUBLIC KEY REGISTRY|locked by rule|Used in saved rule|datetime-local|COMPILE POLICY|fingerprint|xpub/i,
  );
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("source keeps guarded drag-and-drop paths, public-only input, and offline runtime", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /Build recovery paths\. Keep the freedom\./);
  assert.match(page, /5 keys · 5 paths · guarded Miniscript · offline/i);
  assert.match(page, /Keys/);
  assert.match(page, /New path/);
  assert.match(page, /PATH BLOCKS/);
  assert.match(page, /PATH CANVAS/);
  assert.match(page, /Your paths/);
  assert.match(page, /Compatible reuse/);
  assert.match(page, /exact signer set/i);
  assert.match(page, /Owner \/ Recovery marks are visual only/);
  assert.match(page, /LIVE BITCOIN SCRIPT/i);
  assert.match(page, /Load demo/);
  assert.match(page, /DEMO KEYS — never fund this address/i);
  assert.match(page, /DEMO · DO NOT FUND/);
  assert.match(page, /Address copy and policy export are blocked/);
  assert.match(page, /disabled=\{addressAndExportBlocked\}/);
  assert.match(page, /Add key/);
  assert.match(page, /ADD PATH/i);
  assert.match(page, /Export policy JSON/);
  assert.match(page, /Technical details/);
  assert.match(page, /guarded-rule-composer/);
  assert.match(page, /compileGuardedRulePolicy/);
  assert.match(page, /mimir-guarded-rule-request/);
  assert.match(page, /canonical_manifest/);
  assert.match(page, /new Blob\(\[live\.compiled\.canonical_manifest\]/);
  assert.match(page, /MAX_GUARDED_KEYS/);
  assert.match(page, /MAX_GUARDED_RULES/);
  assert.match(page, /DRAFT_BLOCK_MIME/);
  assert.match(page, /draggable/);
  assert.match(page, /onDragStart/);
  assert.match(page, /onDrop/);
  assert.match(page, /type="date"/);
  assert.match(page, /value === "regtest" \|\| value === "signet"/);
  assert.doesNotMatch(
    page,
    /MIMIR \/\/ 5×5 RECOVERY|One primary path\. Up to four recovery stages\.|Up to five public keys · up to five fixed spending paths|Each later CLTV date needs one fewer signature\.|recovery-template|compileRecoveryTemplate|mimir-recovery-request|primary_threshold|recovery_dates/i,
  );
  assert.doesNotMatch(
    page,
    /MAX_KEYS\s*=\s*20|MAX_PATHS\s*=\s*10|RULE BLOCKS|RULE CANVAS|YOUR RULES|Owner \/ Heir marks are visual only|datetime-local|COMPILE POLICY|PUBLIC KEY REGISTRY|fingerprint|xpub|crypto\.randomUUID/i,
  );
  assert.match(layout, /connect-src 'none'/);
  assert.match(layout, /index: false, follow: false/);
  assert.doesNotMatch(layout, /next\/font|codex-preview|_sites-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});
