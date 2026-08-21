"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  MAX_READ_ONCE_KEYS,
  MAX_READ_ONCE_PATHS,
  TEMPLATE_ID_READ_ONCE,
  compileReadOncePolicy,
  unixFromReadOnceDate,
  validateReadOncePublicKey,
  type CompiledReadOncePolicy,
  type ReadOnceNetwork,
  type ReadOncePolicyRequest,
} from "../lib/read-once-normalizer";

type UiNetwork = ReadOnceNetwork;
type KeyRow = { id: string; label: string; publicKey: string };
type SigningMode = "key" | "multisig" | null;
type PolicyBranch = {
  id: string;
  signingMode: SigningMode;
  keyRowIds: string[];
  threshold: number;
  unlockDate: string | null;
};
type FieldState = {
  labelError: string | null;
  publicKeyError: string | null;
  normalizedPublicKey: string | null;
};
type LiveResult = { compiled: CompiledReadOncePolicy | null; message: string | null };

const DEMO_PUBLIC_KEYS = [
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
] as const;

const NETWORK_OPTIONS: ReadonlyArray<{ value: UiNetwork; label: string }> = [
  { value: "bitcoin", label: "MAINNET" },
  { value: "testnet", label: "TESTNET" },
  { value: "signet", label: "SIGNET" },
  { value: "regtest", label: "REGTEST" },
];

function firstFutureDate(): string {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}

function defaultUnlockDate(): string {
  const date = new Date();
  date.setUTCFullYear(date.getUTCFullYear() + 1);
  return date.toISOString().slice(0, 10);
}

function futureYearDates(count: number): string[] {
  return Array.from({ length: count }, (_, index) => {
    const date = new Date();
    date.setUTCFullYear(date.getUTCFullYear() + index + 1);
    return date.toISOString().slice(0, 10);
  });
}

function makeBranch(id: string): PolicyBranch {
  return { id, signingMode: null, keyRowIds: [], threshold: 1, unlockDate: null };
}

function initialRows(): KeyRow[] {
  return [
    { id: "key-row-1", label: "Owner", publicKey: "" },
    { id: "key-row-2", label: "Recovery", publicKey: "" },
  ];
}

function demoRows(): KeyRow[] {
  return [
    { id: "key-row-1", label: "Owner", publicKey: DEMO_PUBLIC_KEYS[0] },
    { id: "key-row-2", label: "Cosigner", publicKey: DEMO_PUBLIC_KEYS[1] },
    { id: "key-row-3", label: "Recovery 1", publicKey: DEMO_PUBLIC_KEYS[2] },
    { id: "key-row-4", label: "Recovery 2", publicKey: DEMO_PUBLIC_KEYS[3] },
  ];
}

function demoBranches(): PolicyBranch[] {
  const dates = futureYearDates(3);
  const all = ["key-row-1", "key-row-2", "key-row-3", "key-row-4"];
  return [
    { ...makeBranch("branch-1"), signingMode: "key", keyRowIds: ["key-row-1"] },
    { ...makeBranch("branch-2"), signingMode: "multisig", keyRowIds: all, threshold: 3, unlockDate: dates[0] },
    { ...makeBranch("branch-3"), signingMode: "multisig", keyRowIds: all, threshold: 2, unlockDate: dates[1] },
    { ...makeBranch("branch-4"), signingMode: "multisig", keyRowIds: all, threshold: 1, unlockDate: dates[2] },
  ];
}

function isUiNetwork(value: string): value is UiNetwork {
  return value === "bitcoin" || value === "testnet" || value === "signet" || value === "regtest";
}

function cluster4(value: string): string {
  return value.match(/.{1,4}/g)?.join(" ") ?? value;
}

function lowerFirst(value: string): string {
  return value ? value.charAt(0).toLowerCase() + value.slice(1) : value;
}

function readableDate(value: string | null): string {
  if (!value) return "immediately";
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return "the selected date";
  const [, year, month, day] = match;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${Number(day)} ${months[Number(month) - 1]} ${year} 00:00 UTC`;
}

function naturalList(values: string[]): string {
  if (values.length < 2) return values[0] ?? "an unnamed keyholder";
  return `${values.slice(0, -1).join(", ")} and ${values.at(-1)}`;
}

function branchStarted(branch: PolicyBranch): boolean {
  return branch.signingMode !== null || branch.unlockDate !== null;
}

function branchComplete(branch: PolicyBranch): boolean {
  return branch.signingMode !== null && branch.keyRowIds.length > 0;
}

function validateRows(rows: KeyRow[]): Map<string, FieldState> {
  const labels = rows.map((row) => row.label.trim().normalize("NFC"));
  const labelCounts = new Map<string, number>();
  for (const label of labels) {
    const identity = label.toLocaleLowerCase("en-US");
    labelCounts.set(identity, (labelCounts.get(identity) ?? 0) + 1);
  }
  const publicKeys = rows.map((row) => {
    try { return validateReadOncePublicKey(row.publicKey); } catch { return null; }
  });
  const publicKeyCounts = new Map<string, number>();
  for (const publicKey of publicKeys) {
    if (publicKey) publicKeyCounts.set(publicKey, (publicKeyCounts.get(publicKey) ?? 0) + 1);
  }
  return new Map(rows.map((row, index) => {
    const label = labels[index];
    const publicKey = publicKeys[index];
    const labelError = !label ? "enter a label"
      : label.length > 80 ? "use at most 80 characters"
        : /\p{Cc}/u.test(label) ? "remove control characters"
          : (labelCounts.get(label.toLocaleLowerCase("en-US")) ?? 0) > 1 ? "label must be unique" : null;
    const publicKeyError = !publicKey
      ? row.publicKey.trim() ? "not a compressed secp256k1 point" : "awaiting public key"
      : (publicKeyCounts.get(publicKey) ?? 0) > 1 ? "public key already registered" : null;
    return [row.id, { labelError, publicKeyError, normalizedPublicKey: publicKey }];
  }));
}

function compileTree(rows: KeyRow[], branches: PolicyBranch[], network: UiNetwork): LiveResult {
  const active = branches.filter(branchStarted);
  if (active.length === 0) return { compiled: null, message: null };
  const emptyClauseIndex = branches.findIndex((branch) => !branchStarted(branch));
  if (emptyClauseIndex >= 0) {
    return { compiled: null, message: `clause 2.${emptyClauseIndex + 1} needs at least one keyholder` };
  }
  try {
    const rowById = new Map(rows.map((row) => [row.id, row]));
    active.forEach((branch, index) => {
      if (!branch.signingMode || branch.keyRowIds.length === 0) {
        throw new Error(`clause 2.${index + 1} needs at least one keyholder`);
      }
      if (branch.threshold < 1 || branch.threshold > branch.keyRowIds.length) {
        throw new Error(`clause 2.${index + 1} has an invalid signature threshold`);
      }
      if (branch.unlockDate) unixFromReadOnceDate(branch.unlockDate);
    });

    const usedIds = [...new Set(active.flatMap((branch) => branch.keyRowIds))];
    for (const id of usedIds) {
      const row = rowById.get(id);
      if (!row) throw new Error("a clause references a removed keyholder");
      if (!row.label.trim()) throw new Error("every keyholder used by a clause needs a label");
      validateReadOncePublicKey(row.publicKey);
    }

    const completeRows = rows.flatMap((row) => {
      const label = row.label.trim().normalize("NFC");
      if (!label || !row.publicKey.trim()) return [];
      try { return [{ row, label, publicKey: validateReadOncePublicKey(row.publicKey) }]; }
      catch { return []; }
    }).sort((left, right) =>
      left.publicKey.localeCompare(right.publicKey) || left.label.localeCompare(right.label));
    if (new Set(completeRows.map((entry) => entry.label.toLocaleLowerCase("en-US"))).size !== completeRows.length) {
      throw new Error("registered keyholder labels must be unique");
    }
    if (new Set(completeRows.map((entry) => entry.publicKey)).size !== completeRows.length) {
      throw new Error("each public key may be registered only once");
    }
    const requestIdByRowId = new Map(completeRows.map((entry, index) => [
      entry.row.id, `key-${String(index + 1).padStart(2, "0")}`,
    ]));
    const request: ReadOncePolicyRequest = {
      format: "mimir-read-once-policy-request",
      version: 6,
      network,
      template_id: TEMPLATE_ID_READ_ONCE,
      keys: completeRows.map((entry, index) => ({
        id: `key-${String(index + 1).padStart(2, "0")}`,
        label: entry.label,
        public_key: entry.publicKey,
      })),
      paths: active.map((branch) => ({
        key_ids: branch.keyRowIds.map((rowId) => {
          const id = requestIdByRowId.get(rowId);
          if (!id) throw new Error("complete every keyholder used in a clause");
          return id;
        }),
        threshold: branch.keyRowIds.length === 1 ? 1 : branch.threshold,
        unlock_unix: branch.unlockDate ? unixFromReadOnceDate(branch.unlockDate) : null,
      })),
    };
    return { compiled: compileReadOncePolicy(request), message: null };
  } catch (error) {
    return { compiled: null, message: error instanceof Error ? error.message : "the policy could not be compiled" };
  }
}

function CopyButton({ value, label, disabled = false }: { value: string; label: string; disabled?: boolean }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  async function copy() {
    if (disabled) return;
    try { await navigator.clipboard.writeText(value); setState("copied"); }
    catch { setState("failed"); }
    window.setTimeout(() => setState("idle"), 1_500);
  }
  return <>
    <button className="copy-button" type="button" onClick={copy} disabled={disabled} aria-label={`copy ${label}`}>
      {state === "copied" ? "COPIED" : state === "failed" ? "FAILED" : "COPY"}
    </button>
    <span className="sr-only" role="status" aria-live="polite">
      {state === "copied" ? `${label} copied.` : state === "failed" ? `${label} could not be copied.` : ""}
    </span>
  </>;
}

function TechnicalItem({ label, value, clustered }: { label: string; value: string; clustered?: boolean }) {
  return <div className="technical-item">
    <div><h4>{label}</h4><CopyButton key={value} value={value} label={label} /></div>
    <code>{clustered ? cluster4(value) : value}</code>
  </div>;
}

type AsmInstruction = {
  depth: number;
  kind: "control" | "opcode" | "number" | "pubkey" | "data";
  meaning: string;
  token: string;
};

function decodeScriptNumber(token: string): number | null {
  const match = token.match(/^<([0-9a-fA-F]+)>$/);
  if (!match || match[1].length % 2 !== 0 || match[1].length > 10) return null;
  const bytes = match[1].match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16));
  if (!bytes?.length) return null;
  const last = bytes.length - 1;
  const negative = (bytes[last] & 0x80) !== 0;
  bytes[last] &= 0x7f;
  const value = bytes.reduce((sum, byte, index) => sum + byte * 2 ** (8 * index), 0);
  return negative ? -value : value;
}

function asmMeaning(token: string, next: string | undefined, keyLabels: Map<string, string>): Pick<AsmInstruction, "kind" | "meaning"> {
  if (/^(?:0|[1-9]|1[0-6])$/.test(token)) {
    return { kind: "number", meaning: next === "OP_CHECKMULTISIG" ? "KEY COUNT" : next?.startsWith("<02") || next?.startsWith("<03") ? "SIGNATURES" : "NUMBER" };
  }
  const pushed = token.match(/^<([0-9a-fA-F]*)>$/);
  if (pushed) {
    const publicKey = pushed[1].toLowerCase();
    if (publicKey.length === 66 && /^(?:02|03)/.test(publicKey)) {
      return { kind: "pubkey", meaning: keyLabels.get(publicKey) ? `PUBLIC KEY · ${keyLabels.get(publicKey)}` : "PUBLIC KEY" };
    }
    if (next === "OP_CHECKLOCKTIMEVERIFY") {
      const locktime = decodeScriptNumber(token);
      const date = locktime !== null && locktime >= 500_000_000 && locktime <= 2_147_483_647
        ? new Date(locktime * 1_000).toISOString().slice(0, 10)
        : null;
      return { kind: "data", meaning: date ? `LOCKTIME · ${date} UTC` : "LOCKTIME DATA" };
    }
    return { kind: "data", meaning: "PUSH DATA" };
  }
  const meanings: Record<string, string> = {
    OP_IF: "IF BRANCH",
    OP_NOTIF: "IF NOT BRANCH",
    OP_ELSE: "ELSE BRANCH",
    OP_ENDIF: "END BRANCH",
    OP_CHECKLOCKTIMEVERIFY: "CHECK LOCKTIME",
    OP_CHECKSIG: "CHECK SIGNATURE",
    OP_CHECKSIGVERIFY: "CHECK + VERIFY SIGNATURE",
    OP_CHECKMULTISIG: "CHECK MULTISIG",
    OP_CHECKMULTISIGVERIFY: "CHECK + VERIFY MULTISIG",
    OP_VERIFY: "REQUIRE TRUE",
    OP_EQUAL: "COMPARE",
    OP_EQUALVERIFY: "COMPARE + VERIFY",
    OP_ADD: "ADD",
    OP_BOOLAND: "BOOLEAN AND",
    OP_BOOLOR: "BOOLEAN OR",
    OP_DUP: "DUPLICATE",
    OP_SWAP: "SWAP",
  };
  const control = token === "OP_IF" || token === "OP_NOTIF" || token === "OP_ELSE" || token === "OP_ENDIF";
  return { kind: control ? "control" : "opcode", meaning: meanings[token] ?? "OPCODE" };
}

function formatAsm(asm: string, keyLabels: Map<string, string>): AsmInstruction[] {
  const tokens = asm.trim().split(/\s+/).filter(Boolean);
  let depth = 0;
  return tokens.map((token, index) => {
    if (token === "OP_ELSE" || token === "OP_ENDIF") depth = Math.max(0, depth - 1);
    const instruction = { depth, token, ...asmMeaning(token, tokens[index + 1], keyLabels) };
    if (token === "OP_IF" || token === "OP_NOTIF" || token === "OP_ELSE") depth += 1;
    return instruction;
  });
}

function BitcoinScriptView({ asm, keyLabels }: { asm: string; keyLabels: Map<string, string> }) {
  const instructions = formatAsm(asm, keyLabels);
  return <>
    <div className="asm-view" role="region" aria-label="Formatted Bitcoin Script instructions" tabIndex={0}>
      <div className="asm-columns" aria-hidden="true"><span>STEP</span><span>MEANING</span><span>INSTRUCTION</span></div>
      <ol>{instructions.map((instruction, index) => <li key={`${index}-${instruction.token}`} style={{ paddingLeft: `${12 + instruction.depth * 18}px` }}>
        <span className="asm-index">{String(index + 1).padStart(2, "0")}</span>
        <span className={`asm-meaning is-${instruction.kind}`}>{instruction.meaning}</span>
        <code className={`asm-token is-${instruction.kind}`}>{instruction.token}</code>
      </li>)}</ol>
    </div>
    <small className="asm-note">Formatted for reading. COPY preserves the exact raw compiler output.</small>
  </>;
}

export default function Home() {
  const [rows, setRows] = useState<KeyRow[]>(initialRows);
  const [branches, setBranches] = useState<PolicyBranch[]>([makeBranch("branch-1")]);
  const [network, setNetwork] = useState<UiNetwork>("regtest");
  const [futureMinimum, setFutureMinimum] = useState(firstFutureDate);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [armed, setArmed] = useState<"demo" | "reset" | null>(null);
  const nextKeyId = useRef(3);
  const nextBranchId = useRef(2);
  const armTimer = useRef<number | null>(null);

  useEffect(() => {
    const refresh = () => setFutureMinimum(firstFutureDate());
    const visible = () => { if (document.visibilityState === "visible") refresh(); };
    const timer = window.setInterval(refresh, 60_000);
    document.addEventListener("visibilitychange", visible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", visible);
      if (armTimer.current !== null) window.clearTimeout(armTimer.current);
    };
  }, []);

  const rowById = useMemo(() => new Map(rows.map((row) => [row.id, row])), [rows]);
  const fieldState = useMemo(() => validateRows(rows), [rows]);
  const keyLabels = useMemo(() => new Map(rows.flatMap((row) => {
    try { return [[validateReadOncePublicKey(row.publicKey), row.label.trim() || "unnamed"] as const]; }
    catch { return []; }
  })), [rows]);
  const live = useMemo(() => compileTree(rows, branches, network), [rows, branches, network]);
  const activeBranches = branches.filter(branchStarted);
  const usedByBranch = useMemo(() => new Set(branches.flatMap((branch) => branch.keyRowIds)), [branches]);
  const hasDemoKey = useMemo(() => rows.some((row) =>
    DEMO_PUBLIC_KEYS.some((key) => key === row.publicKey.trim().toLowerCase())), [rows]);
  const hasNonFutureDelay = useMemo(() => branches.some((branch) =>
    branch.unlockDate !== null && branch.unlockDate < futureMinimum), [branches, futureMinimum]);
  const addressAndExportBlocked = hasDemoKey || hasNonFutureDelay;
  const opcodeCount = live.compiled
    ? live.compiled.asm.split(/\s+/).filter((token) => token.startsWith("OP_")).length
    : 0;

  function updateRow(id: string, patch: Partial<Omit<KeyRow, "id">>) {
    setRows((current) => current.map((row) => row.id === id ? { ...row, ...patch } : row));
    setFeedback(null);
  }

  function updateBranch(id: string, transform: (branch: PolicyBranch) => PolicyBranch) {
    setBranches((current) => current.map((branch) => branch.id === id ? transform(branch) : branch));
    setFeedback(null);
  }

  function addKeyRow() {
    if (rows.length >= MAX_READ_ONCE_KEYS) return;
    const id = `key-row-${nextKeyId.current}`;
    nextKeyId.current += 1;
    setRows((current) => [...current, { id, label: "", publicKey: "" }]);
    setFeedback(`keyholder ${rows.length + 1} added`);
  }

  function removeKeyRow(id: string) {
    if (usedByBranch.has(id)) {
      setFeedback("keyholder is used by a clause — remove it from that clause first");
      return;
    }
    if (rows.length === 1) return;
    setRows((current) => current.filter((row) => row.id !== id));
    setFeedback("keyholder removed");
  }

  function addSpendingPath() {
    if (branches.some((branch) => !branchComplete(branch))) {
      setFeedback("complete the current clause before adding another");
      return;
    }
    if (branches.length >= MAX_READ_ONCE_PATHS) return;
    const id = `branch-${nextBranchId.current}`;
    nextBranchId.current += 1;
    setBranches((current) => [...current, makeBranch(id)]);
    setFeedback("new spending clause added");
  }

  function removeBranch(id: string) {
    if (branches.length === 1) {
      setBranches([makeBranch("branch-1")]);
      setFeedback("clause cleared");
      return;
    }
    setBranches((current) => current.filter((branch) => branch.id !== id));
    setFeedback("clause removed — artifacts recompiled");
  }

  function toggleKeyInBranch(branchId: string, rowId: string) {
    const state = fieldState.get(rowId);
    if (!state || state.labelError || state.publicKeyError) {
      setFeedback("complete and verify that keyholder before using it");
      return;
    }
    updateBranch(branchId, (branch) => {
      const selected = branch.keyRowIds.includes(rowId);
      const keyRowIds = selected
        ? branch.keyRowIds.filter((id) => id !== rowId)
        : [...branch.keyRowIds, rowId];
      const signingMode: SigningMode = keyRowIds.length === 0 ? null : keyRowIds.length === 1 ? "key" : "multisig";
      const threshold = keyRowIds.length < 2
        ? 1
        : !selected && branch.keyRowIds.length === 1
          ? 2
          : Math.min(Math.max(1, branch.threshold), keyRowIds.length);
      return { ...branch, signingMode, keyRowIds, threshold };
    });
  }

  function setThreshold(branchId: string, threshold: number) {
    updateBranch(branchId, (branch) => ({ ...branch, threshold }));
  }

  function setImmediate(branchId: string) {
    updateBranch(branchId, (branch) => ({ ...branch, unlockDate: null }));
  }

  function setDelayed(branchId: string) {
    updateBranch(branchId, (branch) => ({ ...branch, unlockDate: branch.unlockDate ?? defaultUnlockDate() }));
  }

  function arm(kind: "demo" | "reset") {
    if (armTimer.current !== null) window.clearTimeout(armTimer.current);
    if (armed === kind) {
      setArmed(null);
      if (kind === "demo") loadDemo();
      else reset();
      return;
    }
    setArmed(kind);
    armTimer.current = window.setTimeout(() => setArmed(null), 5_000);
  }

  function loadDemo() {
    setRows(demoRows());
    setBranches(demoBranches());
    setNetwork("regtest");
    nextKeyId.current = 5;
    nextBranchId.current = 5;
    setFeedback("demo loaded — public demonstration keys must never receive funds");
  }

  function requestDemo() {
    if (activeBranches.length === 0 && rows.every((row) => !row.publicKey.trim())) loadDemo();
    else arm("demo");
  }

  function reset() {
    setRows(initialRows());
    setBranches([makeBranch("branch-1")]);
    setNetwork("regtest");
    setFutureMinimum(firstFutureDate());
    nextKeyId.current = 3;
    nextBranchId.current = 2;
    setFeedback("sheet reset — nothing was persisted");
  }

  function downloadPolicy() {
    if (!live.compiled || hasDemoKey) return;
    const currentMinimum = firstFutureDate();
    if (branches.some((branch) => branch.unlockDate && branch.unlockDate < currentMinimum)) {
      setFutureMinimum(currentMinimum);
      setFeedback("export blocked — replace the clause whose lock date is active or past");
      return;
    }
    const blob = new Blob([live.compiled.canonical_manifest], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `mimir-${live.compiled.request.network}-${live.compiled.policy_manifest_sha256.slice(0, 12)}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function clauseSentence(branch: PolicyBranch): string {
    const names = branch.keyRowIds.map((id) => rowById.get(id)?.label.trim() || "an unnamed keyholder");
    if (names.length === 0) return "No keyholders are selected yet, so this clause cannot be compiled.";
    const who = names.length === 1 ? names[0] : `any ${branch.threshold} of ${naturalList(names)}`;
    if (!branch.unlockDate) return `${who.charAt(0).toUpperCase()}${who.slice(1)} may spend at any time.`;
    return `From ${readableDate(branch.unlockDate)} onward, ${who} may spend.`;
  }

  const statusLabel = live.compiled
    ? addressAndExportBlocked ? "REVIEW" : "COMPILES"
    : live.message ? "UNRESOLVED" : "INCOMPLETE";
  const statusTone = live.compiled
    ? addressAndExportBlocked ? "warning" : "valid"
    : live.message ? "error" : "draft";
  const revision = live.compiled ? live.compiled.policy_manifest_sha256.slice(0, 12) : "not issued";
  const canAddClause = branches.length < MAX_READ_ONCE_PATHS && branches.every(branchComplete);

  return (
    <main className="sheet-shell">
      <article className="spec-sheet">
        <header className="sheet-header">
          <div className="sheet-titlebar">
            <strong>MIMIR</strong>
            <span>BITCOIN SPENDING POLICY · SPECIFICATION SHEET</span>
            <b>SHEET 1 OF 1</b>
          </div>
          <div className="sheet-meta">
            <div><span>REVISION</span><strong>{revision}</strong></div>
            <div><span>TEMPLATE</span><strong>read-once paths v1</strong></div>
            <div><span>STATUS</span><strong className={`status-stamp is-${statusTone}`}><i></i>{statusLabel}</strong></div>
            <div className="sheet-actions"><span>SESSION</span><p>
              <button type="button" onClick={requestDemo} onBlur={() => setArmed(null)}>{armed === "demo" ? "REALLY LOAD?" : "DEMO"}</button>
              <button type="button" onClick={() => arm("reset")} onBlur={() => setArmed(null)}>{armed === "reset" ? "REALLY RESET?" : "RESET"}</button>
            </p></div>
          </div>
        </header>

        {hasDemoKey ? <div className="sheet-alert is-warning" role="alert"><strong>DEMO KEYS · DO NOT FUND</strong><span>These private keys are public knowledge. Address copy and JSON export are blocked.</span></div> : null}
        {hasNonFutureDelay ? <div className="sheet-alert is-error" role="alert"><strong>LOCK DATE REQUIRES REVIEW</strong><span>A clause is already active or past. Exact artifacts remain visible; address copy and export are blocked.</span></div> : null}

        <section className="sheet-section keyholder-section" aria-labelledby="keyholders-heading">
          <header className="section-title"><span>§1</span><h2 id="keyholders-heading">KEYHOLDERS</h2><p>compressed public keys, entered by hand</p><i></i><b>{rows.length} of {MAX_READ_ONCE_KEYS}</b></header>
          <div className="key-table-head" aria-hidden="true"><span>NO</span><span>LABEL</span><span>PUBLIC KEY · secp256k1</span><span>STATE</span><span></span></div>
          <div className="key-table">{rows.map((row, index) => {
            const state = fieldState.get(row.id);
            const usedCount = branches.filter((branch) => branch.keyRowIds.includes(row.id)).length;
            const verified = Boolean(state?.normalizedPublicKey && !state.publicKeyError && !state.labelError);
            const hasInputError = Boolean(row.publicKey.trim() && state?.publicKeyError);
            return <div className="keyholder-row" key={row.id}>
              <span className="row-index">{String(index + 1).padStart(2, "0")}</span>
              <label><span className="sr-only">keyholder {index + 1} label</span><input value={row.label}
                onChange={(event) => updateRow(row.id, { label: event.target.value })} placeholder="label"
                maxLength={80} autoComplete="off" aria-invalid={Boolean(state?.labelError)} /></label>
              <label><span className="sr-only">keyholder {index + 1} compressed public key</span><input value={row.publicKey}
                onChange={(event) => updateRow(row.id, { publicKey: event.target.value.replace(/\s+/g, "") })}
                placeholder="02… or 03… + 64 hex" autoComplete="off" autoCapitalize="none" spellCheck={false}
                aria-invalid={Boolean(state?.publicKeyError)} /></label>
              <p className={verified ? "is-valid" : hasInputError ? "is-error" : ""}>
                {verified ? `verified · ${usedCount ? `${usedCount} ${usedCount === 1 ? "clause" : "clauses"}` : "unused"}` : state?.publicKeyError ?? "awaiting entry"}
              </p>
              <button type="button" className="remove-button" onClick={() => removeKeyRow(row.id)}
                aria-label={`remove ${row.label.trim() || `keyholder ${index + 1}`}`} aria-disabled={usedByBranch.has(row.id)}>×</button>
            </div>;
          })}</div>
          <button className="outline-action" type="button" onClick={addKeyRow} disabled={rows.length >= MAX_READ_ONCE_KEYS}>+ {rows.length >= MAX_READ_ONCE_KEYS ? "KEYHOLDER LIMIT REACHED" : "ADD KEYHOLDER"}</button>
        </section>

        <section className="sheet-section clauses-section" aria-labelledby="clauses-heading">
          <header className="section-title"><span>§2</span><h2 id="clauses-heading">SPENDING CLAUSES</h2><p>any single complete clause is sufficient to spend</p><i></i><b>{branches.length} of {MAX_READ_ONCE_PATHS}</b></header>
          <div className="clause-list">{branches.map((branch, index) => {
            const locked = Boolean(branch.unlockDate);
            return <article className={`clause${locked ? " is-delayed" : ""}`} key={branch.id}>
              <header><span>2.{index + 1}</span><p>{clauseSentence(branch)}</p><button type="button" className="remove-button" onClick={() => removeBranch(branch.id)} aria-label={`remove clause ${index + 1}`}>×</button></header>
              <div className="clause-controls">
                <fieldset className="keyholder-picker"><legend>KEYHOLDERS IN THIS CLAUSE</legend><div>{rows.map((row, rowIndex) => {
                  const state = fieldState.get(row.id);
                  const selected = branch.keyRowIds.includes(row.id);
                  const invalid = Boolean(state?.labelError || state?.publicKeyError);
                  return <button type="button" key={row.id} className={selected ? "is-selected" : ""}
                    onClick={() => toggleKeyInBranch(branch.id, row.id)} disabled={invalid}
                    aria-pressed={selected} title={selected ? "remove from this clause" : "add to this clause"}>
                    {row.label.trim() || `keyholder ${rowIndex + 1}`}
                  </button>;
                })}</div></fieldset>
                <fieldset className="signature-picker"><legend>SIGNATURES</legend><div>{branch.keyRowIds.length
                  ? branch.keyRowIds.map((_, thresholdIndex) => {
                    const value = thresholdIndex + 1;
                    return <button type="button" key={value} className={branch.threshold === value ? "is-selected" : ""}
                      onClick={() => setThreshold(branch.id, value)} aria-pressed={branch.threshold === value}>{value}</button>;
                  })
                  : <span>—</span>}</div></fieldset>
                <fieldset className="effective-picker"><legend>EFFECTIVE</legend><div className="effective-row">
                  <span className="segmented-control"><button type="button" className={!locked ? "is-selected" : ""} onClick={() => setImmediate(branch.id)} aria-pressed={!locked}>AT ONCE</button><button type="button" className={locked ? "is-selected" : ""} onClick={() => setDelayed(branch.id)} aria-pressed={locked}>FROM DATE</button></span>
                  {branch.unlockDate ? <label><span className="sr-only">clause {index + 1} unlock date</span><input type="date"
                    value={branch.unlockDate} min={futureMinimum} max="2038-01-19"
                    onChange={(event) => updateBranch(branch.id, (current) => ({ ...current, unlockDate: event.target.value }))} /></label> : null}
                </div></fieldset>
              </div>
            </article>;
          })}</div>
          {canAddClause ? <button className="outline-action" type="button" onClick={addSpendingPath}>+ ADD CLAUSE</button> : null}
          <p className="activity-line" role="status" aria-live="polite">{feedback ?? "Each clause is an alternative. Timelocks apply automatically to their clause."}</p>
        </section>

        <section className="sheet-section artifacts-section" aria-labelledby="artifacts-heading">
          <header className="section-title"><span>§3</span><h2 id="artifacts-heading">COMPILED ARTIFACTS</h2><p>{live.compiled ? "deterministic for the clauses above" : "issued when every visible clause is complete"}</p><i></i></header>

          {live.message ? <div className="error-sheet" role="alert"><strong>1 UNRESOLVED ITEM · NO ARTIFACTS ISSUED</strong><p>— {live.message}</p></div> : null}
          {!live.compiled && !live.message ? <div className="awaiting-sheet"><strong>AWAITING A COMPLETE CLAUSE</strong><span>Select verified keyholders in §2 to compile the policy.</span></div> : null}

          {live.compiled ? <div className="artifact-stack">
            <section className="artifact-block"><header><h3>MINISCRIPT</h3><span></span><CopyButton value={live.compiled.miniscript} label="Miniscript" /></header><pre><code>{live.compiled.miniscript}</code></pre></section>
            <section className="artifact-block asm-artifact"><header><h3>BITCOIN SCRIPT · ASM</h3><span>{live.compiled.witness_script_bytes} / 3600 bytes · {opcodeCount} opcodes</span><CopyButton value={live.compiled.asm} label="Bitcoin Script ASM" /></header><BitcoinScriptView asm={live.compiled.asm} keyLabels={keyLabels} /></section>
            <section className="artifact-block address-artifact"><header><h3>P2WSH ADDRESS · OUTPUT ARTIFACT</h3><label className="network-select"><span className="sr-only">Bitcoin network</span><select aria-label="Bitcoin network" value={network} onChange={(event) => {
              const value = event.currentTarget.value;
              if (isUiNetwork(value)) setNetwork(value);
            }}>{NETWORK_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><CopyButton value={live.compiled.address} label="P2WSH address" disabled={addressAndExportBlocked} /></header><p>{live.compiled.address}</p><small>The Bitcoin Core funding command belongs to the next workflow step.</small></section>
            <section className="artifact-block"><header><h3>DESCRIPTOR</h3><span>checksummed</span><CopyButton value={live.compiled.descriptor} label="descriptor" /></header><pre><code>{live.compiled.descriptor}</code></pre></section>
          </div> : null}
        </section>

        <section className="sheet-section verification-section" aria-labelledby="verification-heading">
          <header className="section-title"><span>§4</span><h2 id="verification-heading">VERIFICATION</h2><p>compiler checks for the exact issued artifacts</p><i></i></header>
          {live.compiled ? <>
            <div className="normalization-note"><strong>{live.compiled.manifest.normalization.authored_key_occurrences} visual key uses → {live.compiled.manifest.normalization.emitted_key_checks} read-once checks</strong><p>{live.compiled.manifest.normalization.notes.join(" ")}</p></div>
            <div className="verification-grid">{live.compiled.invariants.map((invariant) => <div key={invariant.id}><span>{invariant.ok ? "✓" : "×"}</span><p><strong>{invariant.ok ? "passed" : "failed"}</strong>{invariant.label}</p></div>)}</div>
            <details className="technical-details"><summary>TECHNICAL DETAILS · HEX · HASH</summary><div>
              <TechnicalItem label="witness script · hex" value={live.compiled.witness_script_hex} />
              <TechnicalItem label="scriptpubkey · hex" value={live.compiled.script_pubkey_hex} />
              <TechnicalItem label="manifest · sha-256" value={live.compiled.policy_manifest_sha256} clustered />
            </div></details>
            <div className="notice-list"><h3>NOTICES</h3>{live.compiled.warnings.map((warning) => <p key={warning}><span>!</span>{lowerFirst(warning)}</p>)}</div>
            <div className="export-row"><button type="button" onClick={downloadPolicy} disabled={addressAndExportBlocked}>↓ DOWNLOAD POLICY JSON</button><span>{addressAndExportBlocked ? `blocked · ${hasDemoKey ? "demo keys" : "review date"}` : `manifest sha256 ${live.compiled.policy_manifest_sha256.slice(0, 20)}…`}</span></div>
          </> : <div className="empty-verification">Verification appears after successful compilation.</div>}
        </section>

        <footer className="sheet-footer">
          <div><span>REVIEWED BY</span><i></i></div>
          <div><span>REHEARSED ON</span><i></i></div>
          <p>Generated locally from public keys only. Nothing is signed, stored, or transmitted. Reproduce the descriptor with independent tooling and rehearse every clause on {network} before funding.</p>
        </footer>
      </article>
    </main>
  );
}
