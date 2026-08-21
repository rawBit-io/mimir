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

test("server-renders the terminal session interface", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Mimir — Bitcoin Script Builder<\/title>/);
  assert.match(html, /<strong>MIMIR<\/strong>/);
  assert.match(html, /v6 · PREVIEW/);
  assert.match(html, /Declare your keys\. Compose the/);
  assert.match(html, /Watch the script compile\./);
  assert.match(html, />KEYS<\/h2>/);
  assert.match(html, />POLICY<\/h2>/);
  assert.match(html, />SPENDING PATHS<\/h2>/);
  assert.match(html, />BITCOIN SCRIPT<\/h2>/);
  assert.match(html, /BLOCKS · click or drag into the selected path/);
  assert.match(html, />AND<\/strong>/);
  assert.match(html, />OR<\/strong>/);
  assert.match(html, />MULTISIG<\/strong>/);
  assert.match(html, />TIMELOCK<\/strong>/);
  assert.match(html, /KEYS · reusable in every path/);
  assert.match(html, /DROP KEY OR MULTISIG HERE/);
  assert.match(html, /\+ ADD OR BRANCH/);
  assert.match(html, /LIVE/);
  assert.match(html, /TECHNICAL DETAILS · HEX · CHECKS/);
  assert.match(html, /P2WSH ADDRESS · ARTIFACT/);
  assert.match(html, /<option value="bitcoin">MAINNET<\/option>/);
  assert.match(html, /<option value="testnet">TESTNET<\/option>/);
  assert.match(html, /<option value="signet">SIGNET<\/option>/);
  assert.match(html, /<option value="regtest" selected="">REGTEST<\/option>/);
  assert.match(html, /Nothing leaves this page\./);
  assert.match(html, /http:\/\/localhost\/og-v2\.png/);
  assert.match(html, /noindex/);
  assert.match(html, /connect-src &#x27;none&#x27;/);
  assert.doesNotMatch(
    html,
    /COMPILE POLICY|lucide/i,
  );
  assert.doesNotMatch(html, /KEYRING|COMPOSE PATH|pre-commit|\[ ADD PATH \]|datetime-local|fingerprint|xpub/i);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("source keeps the read-once normalizer, public-only input, and offline runtime behind the terminal ui", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /Declare your keys\. Compose the/);
  assert.match(page, /BLOCKS · click or drag into the selected path/);
  assert.match(page, /KEYS · reusable in every path/);
  assert.match(page, /DROP KEY OR MULTISIG HERE/);
  assert.match(page, /ADD OR BRANCH/);
  assert.match(page, /SPENDING PATHS/);
  assert.match(page, /P2WSH ADDRESS · ARTIFACT/);
  assert.match(page, /Bitcoin Core funding command belongs to the next workflow step/);
  assert.match(page, /LIVE/);
  assert.match(page, /BITCOIN SCRIPT/);
  assert.match(page, /DEMO KEYS — DO NOT FUND/);
  assert.match(page, /DO-NOT-FUND/);
  assert.match(page, /address copy and export are blocked/);
  assert.match(page, /disabled=\{addressAndExportBlocked\}/);
  assert.match(page, /EXPORT POLICY\.JSON/);
  assert.match(page, /read-once-normalizer/);
  assert.match(page, /compileReadOncePolicy/);
  assert.match(page, /mimir-read-once-policy-request/);
  assert.match(page, /canonical_manifest/);
  assert.match(page, /new Blob\(\[live\.compiled\.canonical_manifest\]/);
  assert.match(page, /MAX_READ_ONCE_KEYS/);
  assert.match(page, /MAX_READ_ONCE_PATHS/);
  assert.match(page, /Owner repeats visually but is emitted once after normalization/);
  assert.match(page, /DRAG_MIME/);
  assert.match(page, /draggable=\{!disabled\}/);
  assert.match(page, /onDragStart/);
  assert.match(page, /onDragOver/);
  assert.match(page, /onDrop/);
  assert.match(page, /dataTransfer/);
  assert.match(page, /type="date"/);
  assert.match(page, /max="2038-01-19"/);
  assert.match(page, /value === "bitcoin" \|\| value === "testnet" \|\| value === "signet" \|\| value === "regtest"/);
  assert.doesNotMatch(page, /network-button/);
  assert.doesNotMatch(page, /type="checkbox"|lucide-react|window\.confirm/);
  assert.doesNotMatch(
    page,
    /recovery-template|compileRecoveryTemplate|mimir-recovery-request|primary_threshold|recovery_dates/i,
  );
  assert.doesNotMatch(page, /partially overlaps saved set|compileGuardedRulePolicy|mimir-guarded-rule-request/);
  assert.doesNotMatch(
    page,
    /MAX_KEYS\s*=\s*20|MAX_PATHS\s*=\s*10|datetime-local|COMPILE POLICY|PUBLIC KEY REGISTRY|fingerprint|xpub|crypto\.randomUUID/i,
  );
  assert.match(layout, /connect-src 'none'/);
  assert.match(layout, /index: false, follow: false/);
  assert.doesNotMatch(layout, /next\/font|codex-preview|_sites-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton|lucide-react/);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});
