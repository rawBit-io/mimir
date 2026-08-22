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

test("server-renders the restrained console interface", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Mimir — Bitcoin Script Builder<\/title>/);
  assert.match(html, /<strong>MIMIR<\/strong>/);
  assert.match(html, /mimir compile --network=(?:<!-- -->)?regtest(?:<!-- -->)? --clauses=(?:<!-- -->)?1/);
  assert.match(html, /<i aria-hidden="true"><\/i>/);
  assert.match(html, />INPUT<\/h1>/);
  assert.match(html, />keys and clauses<\/span>/);
  assert.match(html, />OUTPUT<\/h2>/);
  assert.match(html, />bitcoin script and address<\/span>/);
  assert.match(html, />KEYS<\/h2>/);
  assert.match(html, />CLAUSES<\/h2>/);
  assert.match(html, /clause\[1\] = select keyholders @ now/);
  assert.match(html, />k =<\/legend>/);
  assert.match(html, />opens<\/legend>/);
  assert.match(html, />at once<\/button>/);
  assert.match(html, />from date<\/button>/);
  assert.match(html, /console-outline-action[^>]*>.*?add key.*?<\/button>/is);
  assert.match(html, /console-actions.*?>.*?demo.*?<\/button>/is);
  assert.match(html, /console-actions.*?>.*?reset.*?<\/button>/is);
  assert.match(html, /AWAITING POLICY/);
  assert.match(html, />\[ copy script \]<\/button>/);
  assert.match(html, />\[ copy address \]<\/button>/);
  assert.match(html, />\[ export json \]<\/button>/);
  assert.match(html, /http:\/\/localhost\/og-v2\.png/);
  assert.match(html, /noindex/);
  assert.match(html, /connect-src &#x27;none&#x27;/);
  assert.doesNotMatch(html, /COMPRESSED PUBLIC KEY · secp256k1|>LABEL<|>AND<|>OR<|MINISCRIPT|click or drag|DROP KEY/i);
  assert.doesNotMatch(html, /SESSION COMPILED|validate keys|build branches|TIMELINE|SPENDING EACH BRANCH|sigops|VERIFICATION|OPERATING NOTICES/i);
  assert.doesNotMatch(html, />MAINNET<\/button>|>TESTNET<\/button>|>SIGNET<\/button>|>REGTEST<\/button>/i);
  assert.doesNotMatch(html, /SPECIFICATION SHEET|SHEET 1 OF 1|KEYRING|COMPOSE PATH|pre-commit|\[ ADD PATH \]|datetime-local|fingerprint|xpub|lucide/i);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("source keeps the current Direct Script workflow behind the console ui without reference-only features", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /const commandNetwork = network === "bitcoin" \? "mainnet" : network/);
  assert.match(page, /mimir compile --network=\{commandNetwork\} --clauses=\{branches\.length\}/);
  assert.match(page, /<i aria-hidden="true"><\/i>/);
  assert.match(page, /<h1 id="input-heading">INPUT<\/h1>/);
  assert.match(page, /<h2 id="output-heading">OUTPUT<\/h2>/);
  assert.match(page, />keys and clauses<\/span>/);
  assert.match(page, />bitcoin script and address<\/span>/);
  assert.match(page, /<h2 id="keys-heading">KEYS<\/h2>/);
  assert.match(page, /<h2 id="clauses-heading">CLAUSES<\/h2>/);
  assert.doesNotMatch(page, /COMPRESSED PUBLIC KEY · secp256k1|key-console-head|>LABEL</);
  assert.match(page, /key limit reached" : "add key"/i);
  assert.match(page, /\[ \+ add clause \]/i);
  assert.match(page, /`clause\[\$\{index \+ 1\}\] = \$\{.*?\} @ \$\{branch\.unlockDate \?\? "now"\}`/s);
  assert.match(page, /<legend>k =<\/legend>/);
  assert.match(page, /<legend>opens<\/legend>/);
  assert.match(page, />at once<\/button>/);
  assert.match(page, />from date<\/button>/);
  assert.match(page, /toggleKeyInBranch/);
  assert.match(page, /setThreshold/);
  assert.match(page, /removeKeyRow/);
  assert.match(page, /removeBranch/);
  assert.doesNotMatch(page, /andSlot|addOrBranch|\["and", "AND"\]|\["or", "OR"\]/);
  assert.match(page, /P2WSH ADDRESS/);
  assert.doesNotMatch(page, /OUTPUT ARTIFACT|Bitcoin Core funding command belongs to the next workflow step/);
  assert.match(page, /BITCOIN SCRIPT · ASM/);
  assert.match(page, /Formatted Bitcoin Script/);
  assert.match(page, /formatBitcoinScript/);
  assert.doesNotMatch(page, /asmMeaning|decodeScriptNumber/);
  assert.match(page, /DEMO KEYS · DO NOT FUND/);
  assert.match(page, /Address copy and JSON export are blocked/);
  assert.equal(
    page.match(/disabled=\{!live\.compiled \|\| addressAndExportBlocked\}/g)?.length,
    2,
  );
  assert.match(page, /idleLabel="\[ copy script \]"/);
  assert.match(page, /idleLabel="\[ copy address \]"/);
  assert.match(page, />\[ export json \]<\/button>/);
  assert.match(page, /<select aria-label="Bitcoin network"/);
  assert.doesNotMatch(page, />STATE<|>REVISION<|>TEMPLATE<|>STATUS<|REVIEWED BY|REHEARSED ON|manifest sha256/);
  assert.doesNotMatch(page, /verification-summary|verification-grid|VERIFICATION DETAILS|OPERATING NOTICES|SESSION COMPILED|validate keys|build branches|TIMELINE|SPENDING EACH BRANCH|sigops|script_bytes|op_count/i);
  assert.doesNotMatch(page, /witness table|selector ↑/i);
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
  assert.doesNotMatch(page, />MAINNET<\/button>|>TESTNET<\/button>|>SIGNET<\/button>|>REGTEST<\/button>/i);
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
  assert.match(layout, /@fontsource\/jetbrains-mono\/latin-400\.css/);
  assert.match(layout, /@fontsource\/jetbrains-mono\/latin-500\.css/);
  assert.match(layout, /@fontsource\/jetbrains-mono\/latin-700\.css/);
  assert.match(layout, /index: false, follow: false/);
  assert.doesNotMatch(layout, /next\/font|codex-preview|_sites-preview/);
  assert.match(packageJson, /@fontsource\/jetbrains-mono/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton|lucide-react/);
  assert.doesNotMatch(page, /MINISCRIPT|read-once/i);
  assert.doesNotMatch(packageJson, /bitcoinerlab|mini(?:script)/i);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});
