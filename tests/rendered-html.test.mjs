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

test("server-renders the focused Mimir 5×5 recovery template", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Mimir — Bitcoin Script Builder<\/title>/);
  assert.match(html, /MIMIR \/\/ 5×5 RECOVERY/);
  assert.match(html, /One primary path\. Up to four recovery stages\./);
  assert.match(html, /Up to five public keys · up to five fixed spending paths · compiled locally/);
  assert.match(html, />Signers</);
  assert.match(html, />Primary path</);
  assert.match(html, />Recovery ladder</);
  assert.match(html, /Each later CLTV date needs one fewer signature\./);
  assert.match(html, />Path review</);
  assert.match(html, /Primary and Recovery are functional\./);
  assert.match(html, /LIVE BITCOIN SCRIPT/);
  assert.match(html, /Load demo keys/);
  assert.match(html, /Add signer/);
  assert.match(html, /Export policy JSON/);
  assert.match(html, /Technical details/);
  assert.match(html, /http:\/\/localhost\/og\.png/);
  assert.match(html, /noindex/);
  assert.match(html, /connect-src &#x27;none&#x27;/);
  assert.doesNotMatch(
    html,
    /NEW RULE|RULE BLOCKS|RULE CANVAS|DROP BLOCKS HERE|ADD RULE|YOUR RULES|drag(?:gable)?|Owner \/ Heir marks are visual only|datetime-local|COMPILE POLICY|PUBLIC KEY REGISTRY|fingerprint|xpub/i,
  );
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("source keeps the fixed template, public-only input, and offline runtime", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /MIMIR \/\/ 5×5 RECOVERY/);
  assert.match(page, /One primary path\. Up to four recovery stages\./);
  assert.match(page, /Up to five public keys · up to five fixed spending paths · compiled locally/);
  assert.match(page, /Signers/);
  assert.match(page, /Primary path/);
  assert.match(page, /Recovery ladder/);
  assert.match(page, /Each later CLTV date needs one fewer signature\./);
  assert.match(page, /Path review/);
  assert.match(page, /Primary and Recovery are functional\./);
  assert.match(page, /LIVE BITCOIN SCRIPT/);
  assert.match(page, /Load demo keys/);
  assert.match(page, /DEMO KEYS — never fund this address/);
  assert.match(page, /DEMO · DO NOT FUND/);
  assert.match(page, /copyDisabled=\{hasDemoKey\}/);
  assert.match(page, /Add signer/);
  assert.match(page, /Export policy JSON/);
  assert.match(page, /Technical details/);
  assert.match(page, /recovery-template/);
  assert.match(page, /compileRecoveryTemplate/);
  assert.match(page, /mimir-recovery-request/);
  assert.match(page, /primary_threshold/);
  assert.match(page, /recovery_dates/);
  assert.match(page, /canonical_manifest/);
  assert.match(page, /new Blob\(\[live\.compiled\.canonical_manifest\]/);
  assert.match(page, /value === "regtest" \|\| value === "signet"/);
  assert.match(page, /type="date"/);
  assert.doesNotMatch(
    page,
    /DRAFT_BLOCK_MIME|draggable=|onDragStart=|onDrop=|NEW RULE|RULE BLOCKS|RULE CANVAS|DROP BLOCKS HERE|ADD RULE|YOUR RULES|Owner \/ Heir marks are visual only|datetime-local|COMPILE POLICY|PUBLIC KEY REGISTRY|fingerprint|xpub|crypto\.randomUUID/i,
  );
  assert.match(layout, /connect-src 'none'/);
  assert.match(layout, /index: false, follow: false/);
  assert.doesNotMatch(layout, /next\/font|codex-preview|_sites-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});
