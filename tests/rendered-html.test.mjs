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

test("server-renders the compact specification-sheet interface", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Mimir — Bitcoin Script Builder<\/title>/);
  assert.match(html, /<strong>MIMIR<\/strong>/);
  assert.match(html, /BITCOIN SPENDING POLICY/);
  assert.doesNotMatch(html, /SPECIFICATION SHEET|SHEET 1 OF 1/);
  assert.match(html, />KEYHOLDERS<\/h2>/);
  assert.match(html, />SPENDING CLAUSES<\/h2>/);
  assert.match(html, />COMPILED ARTIFACTS<\/h2>/);
  assert.doesNotMatch(html, />VERIFICATION<\/h2>/);
  assert.match(html, /compressed public keys, entered by hand/);
  assert.match(html, /each clause becomes one explicit Script branch/);
  assert.match(html, /KEYHOLDERS IN THIS CLAUSE/);
  assert.match(html, />SIGNATURES<\/legend>/);
  assert.match(html, />EFFECTIVE<\/legend>/);
  assert.match(html, />AT ONCE<\/button>/);
  assert.match(html, />FROM DATE<\/button>/);
  assert.doesNotMatch(html, />AND<\/strong>|>OR<\/strong>/);
  assert.match(html, /ADD KEYHOLDER/);
  assert.match(html, /AWAITING A COMPLETE CLAUSE/);
  assert.match(html, /Generated locally from public keys only/);
  assert.match(html, /http:\/\/localhost\/og-v2\.png/);
  assert.match(html, /noindex/);
  assert.match(html, /connect-src &#x27;none&#x27;/);
  assert.doesNotMatch(
    html,
    /COMPILE POLICY|lucide/i,
  );
  assert.doesNotMatch(html, /KEYRING|COMPOSE PATH|pre-commit|\[ ADD PATH \]|datetime-local|fingerprint|xpub|click or drag|DROP KEY/i);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("source keeps the restricted Direct Script compiler, public-only input, and offline runtime behind the sheet ui", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /BITCOIN SPENDING POLICY/);
  assert.match(page, /KEYHOLDERS IN THIS CLAUSE/);
  assert.match(page, /ADD KEYHOLDER/);
  assert.match(page, /ADD CLAUSE/);
  assert.match(page, /AT ONCE/);
  assert.match(page, /FROM DATE/);
  assert.doesNotMatch(page, /andSlot|addOrBranch|\["and", "AND"\]|\["or", "OR"\]/);
  assert.match(page, /SPENDING CLAUSES/);
  assert.match(page, /P2WSH ADDRESS/);
  assert.doesNotMatch(page, /OUTPUT ARTIFACT|Bitcoin Core funding command belongs to the next workflow step/);
  assert.match(page, /BITCOIN SCRIPT · ASM/);
  assert.match(page, /Formatted Bitcoin Script/);
  assert.match(page, /formatBitcoinScript/);
  assert.doesNotMatch(page, /asmMeaning|decodeScriptNumber/);
  assert.match(page, /DEMO KEYS · DO NOT FUND/);
  assert.match(page, /Address copy and JSON export are blocked/);
  assert.match(page, /disabled=\{addressAndExportBlocked\}/);
  assert.match(page, /DOWNLOAD POLICY JSON/);
  assert.doesNotMatch(page, />STATE<|>REVISION<|>TEMPLATE<|>STATUS<|REVIEWED BY|REHEARSED ON|manifest sha256/);
  assert.doesNotMatch(page, /verification-summary|verification-grid|VERIFICATION DETAILS|OPERATING NOTICES/);
  assert.match(page, /direct-script-policy/);
  assert.match(page, /compileDirectScriptPolicy/);
  assert.match(page, /mimir-direct-script-policy-request/);
  assert.match(page, /canonical_manifest/);
  assert.match(page, /new Blob\(\[live\.compiled\.canonical_manifest\]/);
  assert.match(page, /MAX_DIRECT_SCRIPT_KEYS/);
  assert.match(page, /MAX_DIRECT_SCRIPT_CLAUSES/);
  assert.doesNotMatch(page, /DRAG_MIME|draggable=|onDragStart|onDragOver|onDrop|dataTransfer/);
  assert.match(page, /type="date"/);
  assert.match(page, /max="2106-02-07"/);
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
  assert.doesNotMatch(page, /MINISCRIPT|read-once/i);
  assert.doesNotMatch(packageJson, /bitcoinerlab|mini(?:script)/i);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});
