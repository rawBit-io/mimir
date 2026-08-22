# Mimir Read-Only Audit Report

**Audit date:** 2026-08-22  
**Audited version:** `7.0.0-preview.1`  
**Audited commit:** `98ca940` (`fix(ui): preserve delayed clause when date is cleared`)  
**Scope:** Direct Script compiler, policy validation, P2WSH artifacts, UI workflow, build/runtime, dependencies, accessibility, and release readiness  
**Application code changes made during the audit:** None. This report was added afterward at the user's request.

## Executive summary

Mimir's restricted 5-key × 5-clause Direct Script compiler appears deterministic and internally correct. The audit found no confirmed compiler defect, policy corruption, stale-artifact export, or incorrect P2WSH address derivation.

The current release status is:

| Area | Assessment |
| --- | --- |
| Local preview and policy experimentation | Ready |
| Deterministic Direct Script construction | Strong |
| Validation and fail-closed behavior | Strong |
| UI workflow | Functional, with several edge cases |
| Regtest funding and signed spending | Not fully proven |
| Testnet or mainnet use with real funds | Not ready |

The main blocker is execution testing. Bitcoin Core independently parsed generated scripts and produced matching addresses, but the repository does not yet construct, sign, broadcast, and spend the generated outputs. Until that harness exists, Mimir can claim strong structural and deterministic verification, but not end-to-end spending proof.

## Implemented policy language

Mimir currently implements a deliberately small policy language:

```text
Policy = OR of 1–5 clauses

Clause = optional absolute timestamp lock
         AND
         one signature threshold over 1–5 keys
```

Each authored clause is preserved literally. Mimir does not use Miniscript, does not normalize repeated public keys away, and does not expose arbitrary Script construction.

Important implementation locations:

- Limits and constants: [`lib/direct-script-policy.ts`](lib/direct-script-policy.ts#L5)
- Clause instruction construction: [`lib/direct-script-policy.ts`](lib/direct-script-policy.ts#L306)
- Right-nested branch construction: [`lib/direct-script-policy.ts`](lib/direct-script-policy.ts#L325)
- Witness-selector construction: [`lib/direct-script-policy.ts`](lib/direct-script-policy.ts#L336)
- Request normalization and validation: [`lib/direct-script-policy.ts`](lib/direct-script-policy.ts#L342)
- P2WSH artifact construction: [`lib/direct-script-policy.ts`](lib/direct-script-policy.ts#L443)

## Test summary

| Check | Result |
| --- | ---: |
| Production build under Node 22 | Pass |
| ESLint | Pass |
| Committed automated tests | 11/11 pass |
| Initial server-rendered page | Pass |
| Missing route | Correctly returns 404 |
| Generated static assets | All requested assets returned 200 |
| `git diff --check` | Pass |
| Working tree after audit | Clean |
| Full TypeScript check | Fails in unused Cloudflare scaffold |
| Production dependency audit | 0 vulnerabilities reported |
| Full development dependency audit | 18 findings |
| Real signed Bitcoin Core spends | Not implemented |
| Hydrated browser interaction suite | Not implemented |

The project declares Node `>=22.13.0` in [`package.json`](package.json#L5). The machine's default Node version during the audit was 20.19.5, which is not sufficient for the current Vinext toolchain.

## Compiler verification

### Committed tests

The committed suite covers:

- Exact single-key Script vectors.
- Immediate and delayed clauses.
- K-of-N multisig clauses.
- Repeated keys across independent clauses.
- Deterministic key ordering.
- Mainnet, Testnet, Signet, and Regtest address encoding.
- Invalid public keys.
- Duplicate identifiers, labels, and public keys.
- Five-key and five-clause limits.
- All 160 possible single-clause subset/threshold/timing shapes.
- A maximal five-clause policy.
- Initial rendered UI structure and source-level regression assertions.

The central compiler suite is [`tests/direct-script-policy-core.test.ts`](tests/direct-script-policy-core.test.ts).

### Additional temporary property tests

The audit ran additional read-only property checks without adding them to the repository.

One audit pass made 46,241 compiler calls:

- 640 single-clause shapes across all four networks.
- All 25,600 ordered pairs of the 160 primitive clause shapes.
- 20,000 deterministic pseudo-random policies containing one to five clauses.
- One maximal 5-key × 5-clause policy.

A separate branch-focused audit covered:

- 160/160 primitive subset/threshold/timing shapes.
- 2,400 policies with clauses in different branch positions.
- 573,824 exact branch/key-mask/locktime evaluations.
- 71,730 final-sequence rejection evaluations.
- 71,730 height-versus-timestamp locktime mismatch evaluations.
- 2,610 selected-key-order permutations.
- 19,200 registry-order permutations.
- 160 input-ID remapping cases.
- 640 network/address cases.
- 43,923 valid whole-day CLTV serializations.
- 56 malformed requests that all failed closed as expected.

No mismatch was found.

These checks are audit evidence, not persistent regression coverage. The most valuable cases should be promoted into committed tests.

### Independent calculations

The audit independently recomputed the following values instead of trusting Mimir's corresponding result fields:

- Witness-script SHA-256.
- P2WSH scriptPubKey.
- Bech32 address.
- Canonical manifest SHA-256.
- Witness-script byte count.
- Counted opcode count.
- Sigop count.
- Clause assembly and branch placement.
- Allowed opcode set.

All independently computed values matched Mimir's output.

### Bitcoin Core parsing

Bitcoin Core 31.1 independently parsed 175 generated witness scripts, recognized their outputs as `witness_v0_scripthash`, and produced Regtest addresses matching Mimir.

This confirms parsing and address construction. It does not prove that complete signed witness stacks are accepted.

## Maximum-policy resource usage

The largest tested five-clause, five-key delayed policy produced:

| Resource | Result | Enforced limit |
| --- | ---: | ---: |
| Witness-script size | 917 bytes | 3,600 bytes |
| Counted opcodes | 27 | 201 |
| Sigops | 25 | Within the tested transaction budget |

The maximum tested policy is therefore comfortably below Mimir's standard P2WSH script-size and opcode ceilings.

P2WSH commits to the SHA-256 of the witness script. Consensus permits a larger witness script than Mimir's standardness limit, while Bitcoin Core's standard transaction policy applies the tighter relay limits used by the compiler:

- [BIP 141: Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [Bitcoin Core standard policy constants](https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.h)

A maximal Mimir satisfaction requires, excluding the witness script itself:

- One historical `CHECKMULTISIG` dummy element.
- Up to five signatures.
- Up to four branch-selector elements.

That is at most ten witness-stack elements, below the current standard P2WSH stack-item limit.

## Confirmed compiler properties

The audit confirmed these properties:

- Only compressed, on-curve secp256k1 public keys are accepted.
- Duplicate key IDs fail closed.
- Duplicate labels fail closed.
- Duplicate public keys fail closed.
- Duplicate use of a key inside one clause fails closed.
- Thresholds outside `1..N` fail closed.
- Key registration order does not alter the witness script.
- Key selection order inside a clause does not alter the witness script.
- Clause order remains deterministic and meaningful.
- Repeated keys across separate clauses remain explicit.
- No Miniscript normalization or key factoring is performed.
- Every tested first, middle, and final branch selector selected its intended clause.
- Locktimes must be timestamp locks, integers, and exact whole UTC days.
- CLTV values use minimal signed-magnitude Script-number encoding.
- Witness-script hashes, scriptPubKeys, and addresses are reproducible.
- Mainnet uses `bc1`.
- Testnet and Signet intentionally share `tb1` encoding.
- Regtest uses `bcrt1`.
- Canonical manifest JSON and its SHA-256 are reproducible.
- Compiler inputs are not mutated.
- Returned policy and manifest structures are defensively cloned.
- Invalid compilation withholds live artifacts instead of showing a previous address.

## Release blocker: signed Bitcoin Core execution

The planned execution harness is documented in [`BITCOIN_CORE_REGTEST_TEST_PLAN.md`](BITCOIN_CORE_REGTEST_TEST_PLAN.md).

Before real funds are used, the generated outputs should be funded and spent through Bitcoin Core on Regtest. The harness should demonstrate:

1. The intended branch can spend.
2. Every incorrect branch selector fails.
3. Every valid K-signature subset succeeds.
4. Too few signatures fail.
5. Signatures supplied in the wrong Script order fail.
6. A missing or nonempty `CHECKMULTISIG` dummy fails.
7. A delayed clause fails before its locktime.
8. A delayed clause succeeds after its locktime.
9. A final input sequence disables CLTV and fails.
10. A height-type transaction locktime fails against a timestamp lock.
11. Wrong, missing, excessive, and non-minimal selectors fail.
12. Successful spends satisfy clean-stack and standard mempool policy.

CLTV requires the transaction locktime to reach the Script operand and the input executing the Script to use a non-final sequence. See [BIP 65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki).

Timestamp locks are evaluated against median time past, not merely the user's wall clock. A clause can therefore become spendable somewhat after its displayed UTC date. See [BIP 113](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki).

`CHECKMULTISIG` requires a leading empty dummy witness element. See [BIP 147](https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki).

Until the Core execution harness passes, the accurate assurance statement is:

> Mimir deterministically constructs structurally valid P2WSH scripts whose parsing and address derivation match Bitcoin Core.

It is not yet appropriate to claim:

> Every produced policy has been proven spendable through real signed Bitcoin Core transactions.

## Persistent test-suite gap

The committed symbolic test currently compares:

```text
some authored clause succeeds
```

against:

```text
some generated branch succeeds
```

See [`tests/direct-script-policy-core.test.ts`](tests/direct-script-policy-core.test.ts#L149).

This proves the overall union of permitted spends. In theory, it could miss a regression where two branch selectors were exchanged while the same overall set of spends remained available.

The temporary audit compared every generated branch directly with its intended authored clause, and all tested selectors passed. This is therefore a persistent regression-coverage gap, not evidence of a current compiler defect.

## UI workflow findings

### Confirmed behavior

The following behavior was confirmed through source inspection, SSR tests, and compiler tests:

- The empty initial policy exposes no stale address or Script.
- Keys are limited to five.
- Clauses are limited to five.
- Public keys are validated before compilation.
- Thresholds clamp safely when selected keys are removed.
- Selecting a second key naturally defaults a clause to 2-of-2.
- A delayed clause whose date is cleared remains delayed and incomplete.
- Clearing a date no longer removes the date input.
- An empty delayed date fails closed instead of becoming immediate.
- Deleting the only clause clears it.
- Deleting one of multiple clauses recompiles the remaining policy.
- Demo keys are visibly identified.
- Demo policies block the address-copy button and JSON export.
- Stale locks preserve exact artifacts for review but block address copy and export.
- Reset uses a two-click confirmation.
- Replacing non-pristine input with the demo requires confirmation.
- Copy success and failure are announced.
- JSON export uses the exact canonical manifest bytes.
- Script copy uses the real opcode-and-key representation.
- All four address networks are available beside the address.
- Desktop panels scroll independently.
- The UI stacks below 900px.
- Most controls receive larger touch targets below 720px.
- Focus-visible and reduced-motion behavior is present.

### High coverage gap: no browser interaction suite

The rendered UI test primarily checks initial HTML and searches source text for expected expressions. It does not actually:

- Type or paste public keys.
- Clear a date field.
- Switch between `at once` and `from date`.
- Add or delete clauses.
- Change thresholds.
- Change networks.
- Exercise reset confirmation timing.
- Exercise clipboard permissions.
- Download and inspect a JSON file.
- Test keyboard-only navigation.
- Measure 320px, tablet, and desktop overflow.

See [`tests/rendered-html.test.mjs`](tests/rendered-html.test.mjs#L63).

The available interactive browser connection could not be initialized during this audit. Compiled-state layout and interaction conclusions are therefore based on source, CSS, SSR, and server behavior rather than a hydrated click-and-screenshot run.

### Medium: selected invalid key can become trapped

If a selected key is subsequently cleared, corrupted, or made duplicate:

- Its clause chip becomes disabled.
- Its key-row delete operation is blocked because the clause still references it.

The user can recover by repairing the key, deleting the whole clause, or resetting. The natural operation—deselecting the invalid key—is unavailable.

Relevant code:

- Clause-key disabling: [`app/page.tsx`](app/page.tsx#L644)
- Used-key deletion guard: [`app/page.tsx`](app/page.tsx#L445)

### Medium: clause completeness ignores key validity

`branchComplete()` checks the signing mode, selected-key count, and delayed-date presence. It does not include the validity of the selected key rows: [`app/page.tsx`](app/page.tsx#L164).

Therefore `add clause` may remain available after a selected public key becomes invalid: [`app/page.tsx`](app/page.tsx#L577).

Adding a new blank clause can then mask the more useful invalid-key error with the blank clause's missing-key error.

### Medium: timeline can misrepresent extreme ranges

The textual dates remain exact, but the timeline is an approximate visualization.

The latest unlock date defines the end of a 34-cell scale. A clause at that exact endpoint receives `openFrom = 34`, which renders all 34 cells dormant and no visible open segment.

Conversely, if one clause opens tomorrow and another opens near 2106, rounding can map tomorrow's delay to zero cells and make its lane appear entirely open.

The relevant calculation is in [`app/page.tsx`](app/page.tsx#L391).

The timeline should be treated as orientation, not an exact execution indicator. Its scaling should eventually guarantee a visible waiting segment for future dates and a visible open segment at the final endpoint.

### Medium: insufficient visual contrast

Several small labels and control boundaries have limited contrast against white:

- Faint text: approximately 3.07:1.
- Placeholder text: approximately 2.55:1.
- Default control border: approximately 1.41:1.

Theme variables are defined in [`app/globals.css`](app/globals.css#L1).

This affects panel subtitles, timeline years, placeholders, local guidance, and some input/button boundaries.

### Medium: missing inline delayed-date error

When a delayed date is empty, the field receives `aria-invalid`, but it has no adjacent visible explanation and no `aria-describedby` association. The compiler message may be shown in the output panel far from the input.

See [`app/page.tsx`](app/page.tsx#L663).

### Low: conflicting delete semantics

Some guarded delete buttons expose `aria-disabled="true"` while remaining focusable and clickable. The handler safely rejects the operation and supplies feedback, but assistive technology announces an unavailable control that still reacts to activation.

See [`app/page.tsx`](app/page.tsx#L619).

### Low: tablet touch targets

At approximately 768px the layout stacks, but some controls retain desktop dimensions:

- Remove controls are approximately 18×28px.
- Threshold controls are approximately 26×26px.

The 44px mobile target rules begin only below 720px.

### Low: long labels can overflow

Labels may contain up to 80 characters. Some clause chips, natural-language summaries, and timeline legend entries do not force wrapping of unbroken strings, so unusual labels can overflow narrow layouts.

### Low: copy blocking is an accident-prevention feature

Demo and stale-policy copy/export buttons are correctly blocked. The address remains selectable text and can still be manually copied. The UI guard should therefore be described as accident prevention, not as a security boundary.

## Manifest and future Bitcoin Core exporter

The manifest exports `signature_order` in canonical Script key order: [`lib/direct-script-policy.ts`](lib/direct-script-policy.ts#L475).

For K-of-N clauses, this does not mean that all N signatures are required. A future Bitcoin Core command exporter must:

1. Determine the selected K signing keys.
2. Sort those K signatures according to their corresponding positions in the complete Script key list.
3. Prepend the empty `CHECKMULTISIG` dummy.
4. Append the correct branch-selector elements.
5. Append the witness script.

This interpretation should be explicit in the command-export specification and tests.

Unused valid registry keys can change the canonical manifest and manifest hash without changing the witness script or address. The behavior is deterministic, but users should understand that an identical address does not necessarily imply byte-identical policy JSON.

## Runtime and operational findings

### Good local-only properties

The application source does not initiate application-level use of:

- `fetch`
- `XMLHttpRequest`
- WebSockets
- `localStorage`
- `sessionStorage`
- IndexedDB
- Cookies
- Private keys

Generated assets are local. Responses use `Cache-Control: no-store`, and the page's CSP includes `connect-src 'none'`.

### Development server listens on all interfaces

The running preview server was bound to `*:3000`, not explicitly to `127.0.0.1`. Other devices may therefore reach it when the host firewall and network allow access.

For a tool described as local-only, loopback-only binding would be the safer operational default.

### Default Node version is incompatible

The active shell used Node 20.19.5 while Mimir requires Node 22.13 or later. Plain `npm run dev` can therefore reproduce the `node:fs/promises.glob` startup failure.

A working temporary invocation is:

```bash
npm exec --yes --package=node@22 -- npm run dev
```

A permanent local Node 22 selection is preferable.

### Full TypeScript check fails in unused infrastructure

`tsc --noEmit` reports unresolved Cloudflare ambient types in:

- [`db/index.ts`](db/index.ts)
- [`worker/index.ts`](worker/index.ts)

These errors do not originate in the Direct Script compiler or main UI. Nevertheless, a release repository should ideally have a clean whole-project typecheck.

The unused Cloudflare, D1, and ChatGPT scaffold also increases installation size and maintenance surface for an application currently intended to run only locally.

### Dependency audit

Audit snapshot on 2026-08-22:

- `npm audit --omit=dev`: 0 vulnerabilities.
- Full `npm audit`: 18 findings.
  - 13 high.
  - 4 moderate.
  - 1 low.
  - 0 critical.

The findings are concentrated in development and build tooling, including Vinext, Vite, Wrangler, Miniflare, and React Server Components. They are not automatically proof of an exploitable path in Mimir.

Because the local development server currently listens on all interfaces, the toolchain findings still deserve review. Broad automatic `npm audit fix` changes should be avoided; upgrades should be applied and tested deliberately.

### CSP framing limitation

The application supplies CSP through a `<meta>` element. `frame-ancestors 'none'` is not enforced from a meta CSP and requires an HTTP response header.

This is low priority while Mimir remains loopback-only, but it matters if the app is later hosted.

### Missing automated release gates

The repository currently has no GitHub Actions workflow automatically running:

- Node 22 build.
- Lint.
- Unit/property tests.
- Typecheck.
- Future Bitcoin Core Regtest execution tests.

The public repository also has no license file. A license should be added if the intent is to make the source legally reusable by others.

## Recommended next steps

### Priority 0: before real funds

1. Implement the Bitcoin Core Regtest execution harness.
2. Execute every branch position.
3. Exercise every K-of-N signature subset.
4. Test locktime, sequence, median-time-past, selector, dummy, and failure cases.
5. Pin transaction IDs, witness stacks, scripts, and addresses as permanent vectors.

### Priority 1: before calling the UI release-grade

1. Add hydrated browser interaction tests.
2. Automate the cleared delayed-date regression exactly as a user performs it.
3. Allow an invalid selected key to be deselected.
4. Include selected-key validity in clause completeness.
5. Make timeline edge cases fail-honest.
6. Add an inline delayed-date validation message.
7. Improve contrast and tablet-size touch targets.

### Priority 1: repository and operational cleanup

1. Make Node 22 the effective local runtime.
2. Bind the development server to loopback for local-only use.
3. Remove or isolate unused Cloudflare/D1 scaffolding.
4. Restore a clean full TypeScript check.
5. Review and deliberately update vulnerable development tooling.
6. Add continuous integration.
7. Add a license if the repository is intended to be open-source.

## Final assessment

Mimir is materially simpler than its earlier Miniscript-based designs. The current Direct Script language is small enough to specify, reason about, exhaustively exercise at the policy level, and independently audit.

The expanded audit found:

- No confirmed compiler defect.
- No address mismatch.
- No determinism failure.
- No stale-artifact export defect.
- Strong script-size and opcode headroom.
- Several correct fail-closed validation paths.

The remaining distinction is assurance level:

- Construction logic: strong.
- Determinism: strong.
- Static validation: strong.
- Bitcoin Core parsing/address agreement: strong.
- Real signed transaction execution: not yet proven.
- Browser workflow regression coverage: insufficient.

The recommended next milestone is not another policy feature. It is the Bitcoin Core Regtest execution harness plus real browser workflow tests. Those two additions would improve confidence more than expanding the current 5×5 language.
