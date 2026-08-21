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
  assert.match(html, /mimir v6/);
  assert.match(html, /read-once p2wsh · 5 keys · 5 visual paths · offline/);
  assert.match(html, /\[1\] KEYRING/);
  assert.match(html, /\[2\] COMPOSE PATH/);
  assert.match(html, /\[3\] VISUAL PATHS/);
  assert.match(html, />STDOUT</);
  assert.match(html, /pre-commit/);
  assert.match(html, /lock until date \(UTC\)/);
  assert.match(html, /keys may repeat across paths; the normalizer must remove every repeated script check\./);
  assert.match(html, /marks are visual only\. saved paths alone define who can spend\./);
  assert.match(html, /no paths\. stdout is empty until the first path is saved\./);
  assert.match(html, /\[ ADD PATH \]/);
  assert.match(html, /register key/);
  assert.match(html, /\[load demo\]/);
  assert.match(html, /\[reset\]/);
  assert.match(html, /descriptor · hex · checks/);
  assert.match(html, /nothing leaves this page\./);
  assert.match(html, /compressed public keys only\. private keys never belong in this page\./);
  assert.match(html, /http:\/\/localhost\/og\.png/);
  assert.match(html, /noindex/);
  assert.match(html, /connect-src &#x27;none&#x27;/);
  assert.doesNotMatch(
    html,
    /MIMIR \/\/ GUARDED|COMPILE POLICY|lucide/i,
  );
  assert.doesNotMatch(html, /RULE BLOCKS|RULE CANVAS|YOUR RULES|PUBLIC KEY REGISTRY|datetime-local|fingerprint|xpub/i);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("source keeps the read-once normalizer, public-only input, and offline runtime behind the terminal ui", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /read-once p2wsh · 5 keys · 5 visual paths · offline/);
  assert.match(page, /\[1\] KEYRING/);
  assert.match(page, /\[2\] COMPOSE PATH/);
  assert.match(page, /\[3\] VISUAL PATHS/);
  assert.match(page, /STDOUT/);
  assert.match(page, /pre-commit/);
  assert.match(page, /NORMALIZE ▸ OK/);
  assert.match(page, /NORMALIZE ▸ FAIL/);
  assert.match(page, /visual key uses become/);
  assert.match(page, /no equivalent read-once Miniscript was found/);
  assert.match(page, /marks are visual only\. saved paths alone define who can spend\./);
  assert.match(page, /any one satisfied path spends\. there is no other door\./);
  assert.match(page, /DEMO KEYS — DO NOT FUND\./);
  assert.match(page, /DO-NOT-FUND/);
  assert.match(page, /address copy and export stay blocked until every demo key is replaced\./);
  assert.match(page, /disabled=\{addressAndExportBlocked\}/);
  assert.match(page, /\[ ADD PATH \]/);
  assert.match(page, /\[ export policy\.json \]/);
  assert.match(page, /read-once-normalizer/);
  assert.match(page, /compileReadOncePolicy/);
  assert.match(page, /mimir-read-once-policy-request/);
  assert.match(page, /canonical_manifest/);
  assert.match(page, /new Blob\(\[live\.compiled\.canonical_manifest\]/);
  assert.match(page, /MAX_READ_ONCE_KEYS/);
  assert.match(page, /MAX_READ_ONCE_PATHS/);
  assert.match(page, /Owner is reused visually in every path, then factored to one emitted key check/);
  assert.match(page, /type="checkbox"/);
  assert.match(page, /type="date"/);
  assert.match(page, /max="2038-01-19"/);
  assert.match(page, /value === "regtest" \|\| value === "signet"/);
  assert.doesNotMatch(
    page,
    /draggable|onDragStart|onDragOver|onDrop|DRAFT_BLOCK_MIME|dataTransfer|lucide-react|window\.confirm/,
  );
  assert.doesNotMatch(
    page,
    /recovery-template|compileRecoveryTemplate|mimir-recovery-request|primary_threshold|recovery_dates/i,
  );
  assert.doesNotMatch(page, /partially overlaps saved set|compileGuardedRulePolicy|mimir-guarded-rule-request/);
  assert.doesNotMatch(
    page,
    /MAX_KEYS\s*=\s*20|MAX_PATHS\s*=\s*10|RULE BLOCKS|RULE CANVAS|YOUR RULES|datetime-local|COMPILE POLICY|PUBLIC KEY REGISTRY|fingerprint|xpub|crypto\.randomUUID/i,
  );
  assert.match(layout, /connect-src 'none'/);
  assert.match(layout, /index: false, follow: false/);
  assert.doesNotMatch(layout, /next\/font|codex-preview|_sites-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton|lucide-react/);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});
