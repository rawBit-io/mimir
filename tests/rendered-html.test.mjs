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

test("server-renders the live Mimir script builder", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Mimir — Bitcoin Script Builder<\/title>/);
  assert.match(html, />MIMIR</);
  assert.match(html, /Build a Bitcoin recovery script\./);
  assert.match(html, /Public keys only · updates live · offline/);
  assert.match(html, /LIVE BITCOIN SCRIPT/);
  assert.match(html, /ADD KEY/);
  assert.match(html, /Technical details/);
  assert.match(html, /http:\/\/localhost\/og\.png/);
  assert.match(html, /noindex/);
  assert.match(html, /connect-src &#x27;none&#x27;/);
  assert.doesNotMatch(
    html,
    /MIMIR \/\/ POLICY TERMINAL|COMPILE POLICY|PUBLIC KEY REGISTRY|ACTIVE DROP|DRAG|DROP|Step 1|fingerprint|xpub/i,
  );
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("removes the disposable starter and external runtime assets", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /Build a Bitcoin recovery script\./);
  assert.match(page, /Public keys only · updates live · offline/);
  assert.match(page, /LIVE BITCOIN SCRIPT/);
  assert.match(page, /ADD KEY/);
  assert.match(page, /Technical details/);
  assert.match(page, /canonical_manifest/);
  assert.match(page, /value === "regtest" \|\| value === "signet"/);
  assert.doesNotMatch(
    page,
    /MIMIR \/\/ POLICY TERMINAL|COMPILE POLICY|PUBLIC KEY REGISTRY|draggable|onDragStart|onDrop|activeTarget|fingerprint|xpub|crypto\.randomUUID/i,
  );
  assert.match(layout, /connect-src 'none'/);
  assert.match(layout, /index: false, follow: false/);
  assert.doesNotMatch(layout, /next\/font|codex-preview|_sites-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});
