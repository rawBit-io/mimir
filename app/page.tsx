"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  MAX_DIRECT_SCRIPT_CLAUSES,
  MAX_DIRECT_SCRIPT_KEYS,
  TEMPLATE_ID_DIRECT_SCRIPT,
  compileDirectScriptPolicy,
  unixFromDirectScriptDate,
  validateDirectScriptPublicKey,
  type CompiledDirectScriptPolicy,
  type DirectScriptNetwork,
  type DirectScriptPolicyRequest,
} from "../lib/direct-script-policy";

type UiNetwork = DirectScriptNetwork;
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
};
type LiveResult = { compiled: CompiledDirectScriptPolicy | null; message: string | null };

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
    try { return validateDirectScriptPublicKey(row.publicKey); } catch { return null; }
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
    return [row.id, { labelError, publicKeyError }];
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
      if (branch.unlockDate) unixFromDirectScriptDate(branch.unlockDate);
    });

    const usedIds = [...new Set(active.flatMap((branch) => branch.keyRowIds))];
    for (const id of usedIds) {
      const row = rowById.get(id);
      if (!row) throw new Error("a clause references a removed keyholder");
      if (!row.label.trim()) throw new Error("every keyholder used by a clause needs a label");
      validateDirectScriptPublicKey(row.publicKey);
    }

    const completeRows = rows.flatMap((row) => {
      const label = row.label.trim().normalize("NFC");
      if (!label || !row.publicKey.trim()) return [];
      try { return [{ row, label, publicKey: validateDirectScriptPublicKey(row.publicKey) }]; }
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
    const request: DirectScriptPolicyRequest = {
      format: "mimir-direct-script-policy-request",
      version: 7,
      network,
      template_id: TEMPLATE_ID_DIRECT_SCRIPT,
      keys: completeRows.map((entry, index) => ({
        id: `key-${String(index + 1).padStart(2, "0")}`,
        label: entry.label,
        public_key: entry.publicKey,
      })),
      clauses: active.map((branch) => ({
        key_ids: branch.keyRowIds.map((rowId) => {
          const id = requestIdByRowId.get(rowId);
          if (!id) throw new Error("complete every keyholder used in a clause");
          return id;
        }),
        threshold: branch.keyRowIds.length === 1 ? 1 : branch.threshold,
        unlock_unix: branch.unlockDate ? unixFromDirectScriptDate(branch.unlockDate) : null,
      })),
    };
    return { compiled: compileDirectScriptPolicy(request), message: null };
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

function formatBitcoinScript(asm: string): string {
  const tokens = asm.trim().split(/\s+/).filter(Boolean);
  const control = new Set(["OP_IF", "OP_NOTIF", "OP_ELSE", "OP_ENDIF"]);
  const lineEnd = new Set([
    "OP_VERIFY", "OP_DROP", "OP_CHECKSIG", "OP_CHECKSIGVERIFY",
    "OP_CHECKMULTISIG", "OP_CHECKMULTISIGVERIFY", "OP_EQUAL",
    "OP_EQUALVERIFY", "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_0NOTEQUAL",
    "OP_BOOLAND", "OP_BOOLOR",
  ]);
  const lines: string[] = [];
  let current: string[] = [];
  let depth = 0;
  const flush = () => {
    if (!current.length) return;
    lines.push(`${"    ".repeat(depth)}${current.join(" ")}`);
    current = [];
  };

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (control.has(token)) {
      flush();
      if (token === "OP_ELSE" || token === "OP_ENDIF") depth = Math.max(0, depth - 1);
      lines.push(`${"    ".repeat(depth)}${token}`);
      if (token === "OP_IF" || token === "OP_NOTIF" || token === "OP_ELSE") depth += 1;
      continue;
    }

    if (/^(?:[1-9]|1[0-6])$/.test(token) && /^<[0-9a-f]{66}>$/i.test(tokens[index + 1] ?? "")) {
      let cursor = index + 1;
      const publicKeys: string[] = [];
      while (/^<[0-9a-f]{66}>$/i.test(tokens[cursor] ?? "")) {
        publicKeys.push(tokens[cursor]);
        cursor += 1;
      }
      if (/^(?:[1-9]|1[0-6])$/.test(tokens[cursor] ?? "") && tokens[cursor + 1] === "OP_CHECKMULTISIG") {
        flush();
        lines.push(`${"    ".repeat(depth)}${token}`);
        publicKeys.forEach((publicKey) => lines.push(`${"    ".repeat(depth + 1)}${publicKey}`));
        lines.push(`${"    ".repeat(depth)}${tokens[cursor]} OP_CHECKMULTISIG`);
        index = cursor + 1;
        continue;
      }
    }

    current.push(token);
    const next = tokens[index + 1];
    const continuesLocktime = token === "OP_CHECKLOCKTIMEVERIFY" && (next === "OP_VERIFY" || next === "OP_DROP" || next === "OP_0NOTEQUAL");
    if (!continuesLocktime && (lineEnd.has(token) || control.has(next))) flush();
  }
  flush();
  return lines.join("\n");
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
  const live = useMemo(() => compileTree(rows, branches, network), [rows, branches, network]);
  const formattedAsm = useMemo(() => live.compiled ? formatBitcoinScript(live.compiled.asm) : "", [live.compiled]);
  const activeBranches = branches.filter(branchStarted);
  const usedByBranch = useMemo(() => new Set(branches.flatMap((branch) => branch.keyRowIds)), [branches]);
  const hasDemoKey = useMemo(() => rows.some((row) =>
    DEMO_PUBLIC_KEYS.some((key) => key === row.publicKey.trim().toLowerCase())), [rows]);
  const hasNonFutureDelay = useMemo(() => branches.some((branch) =>
    branch.unlockDate !== null && branch.unlockDate < futureMinimum), [branches, futureMinimum]);
  const addressAndExportBlocked = hasDemoKey || hasNonFutureDelay;

  function updateRow(id: string, patch: Partial<Omit<KeyRow, "id">>) {
    setRows((current) => current.map((row) => row.id === id ? { ...row, ...patch } : row));
    setFeedback(null);
  }

  function updateBranch(id: string, transform: (branch: PolicyBranch) => PolicyBranch) {
    setBranches((current) => current.map((branch) => branch.id === id ? transform(branch) : branch));
    setFeedback(null);
  }

  function addKeyRow() {
    if (rows.length >= MAX_DIRECT_SCRIPT_KEYS) return;
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
    if (branches.length >= MAX_DIRECT_SCRIPT_CLAUSES) return;
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

  const canAddClause = branches.length < MAX_DIRECT_SCRIPT_CLAUSES && branches.every(branchComplete);

  return (
    <main className="sheet-shell">
      <article className="spec-sheet">
        <header className="sheet-header">
          <div className="sheet-titlebar">
            <strong>MIMIR</strong>
            <span>BITCOIN SPENDING POLICY</span>
            <p className="header-actions">
              <button type="button" onClick={requestDemo} onBlur={() => setArmed(null)}>{armed === "demo" ? "REALLY LOAD?" : "DEMO"}</button>
              <button type="button" onClick={() => arm("reset")} onBlur={() => setArmed(null)}>{armed === "reset" ? "REALLY RESET?" : "RESET"}</button>
            </p>
          </div>
        </header>

        {hasDemoKey ? <div className="sheet-alert is-warning" role="alert"><strong>DEMO KEYS · DO NOT FUND</strong><span>These private keys are public knowledge. Address copy and JSON export are blocked.</span></div> : null}
        {hasNonFutureDelay ? <div className="sheet-alert is-error" role="alert"><strong>LOCK DATE REQUIRES REVIEW</strong><span>A clause is already active or past. Exact artifacts remain visible; address copy and export are blocked.</span></div> : null}

        <section className="sheet-section keyholder-section" aria-labelledby="keyholders-heading">
          <header className="section-title"><span>§1</span><h2 id="keyholders-heading">KEYHOLDERS</h2><p>compressed public keys, entered by hand</p><i></i><b>{rows.length} of {MAX_DIRECT_SCRIPT_KEYS}</b></header>
          <div className="key-table-head" aria-hidden="true"><span>NO</span><span>LABEL</span><span>PUBLIC KEY · secp256k1</span><span></span></div>
          <div className="key-table">{rows.map((row, index) => {
            const state = fieldState.get(row.id);
            const visibleLabelError = row.label.trim() || row.publicKey.trim() ? state?.labelError : null;
            const visiblePublicKeyError = row.publicKey.trim() ? state?.publicKeyError : null;
            const visibleErrors = [
              visibleLabelError ? `label: ${visibleLabelError}` : null,
              visiblePublicKeyError ? `public key: ${visiblePublicKeyError}` : null,
            ].filter((message): message is string => Boolean(message));
            const errorId = `keyholder-${index + 1}-error`;
            return <div className="keyholder-row" key={row.id}>
              <span className="row-index">{String(index + 1).padStart(2, "0")}</span>
              <label><span className="sr-only">keyholder {index + 1} label</span><input value={row.label}
                onChange={(event) => updateRow(row.id, { label: event.target.value })} placeholder="label"
                maxLength={80} autoComplete="off" aria-invalid={Boolean(visibleLabelError)}
                aria-describedby={visibleErrors.length ? errorId : undefined} /></label>
              <label><span className="sr-only">keyholder {index + 1} compressed public key</span><input value={row.publicKey}
                onChange={(event) => updateRow(row.id, { publicKey: event.target.value.replace(/\s+/g, "") })}
                placeholder="02… or 03… + 64 hex" autoComplete="off" autoCapitalize="none" spellCheck={false}
                aria-invalid={Boolean(visiblePublicKeyError)} aria-describedby={visibleErrors.length ? errorId : undefined} /></label>
              {visibleErrors.length ? <p id={errorId} className="is-error">{visibleErrors.join(" · ")}</p> : null}
              <button type="button" className="remove-button" onClick={() => removeKeyRow(row.id)}
                aria-label={`remove ${row.label.trim() || `keyholder ${index + 1}`}`} aria-disabled={usedByBranch.has(row.id)}>×</button>
            </div>;
          })}</div>
          <button className="outline-action" type="button" onClick={addKeyRow} disabled={rows.length >= MAX_DIRECT_SCRIPT_KEYS}>+ {rows.length >= MAX_DIRECT_SCRIPT_KEYS ? "KEYHOLDER LIMIT REACHED" : "ADD KEYHOLDER"}</button>
        </section>

        <section className="sheet-section clauses-section" aria-labelledby="clauses-heading">
          <header className="section-title"><span>§2</span><h2 id="clauses-heading">SPENDING CLAUSES</h2><p>each clause becomes one explicit Script branch</p><i></i><b>{branches.length} of {MAX_DIRECT_SCRIPT_CLAUSES}</b></header>
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
                    value={branch.unlockDate} min={futureMinimum} max="2106-02-07"
                    onChange={(event) => updateBranch(branch.id, (current) => ({ ...current, unlockDate: event.target.value }))} /></label> : null}
                </div></fieldset>
              </div>
            </article>;
          })}</div>
          {canAddClause ? <button className="outline-action" type="button" onClick={addSpendingPath}>+ ADD CLAUSE</button> : null}
          <p className="activity-line" role="status" aria-live="polite">{feedback ?? "Each clause is an alternative. Timelocks apply automatically to their clause."}</p>
        </section>

        <section className="sheet-section artifacts-section" aria-labelledby="artifacts-heading">
          <header className="section-title"><span>§3</span><h2 id="artifacts-heading">COMPILED ARTIFACTS</h2><i></i></header>

          {live.message ? <div className="error-sheet" role="alert"><strong>1 UNRESOLVED ITEM · NO ARTIFACTS ISSUED</strong><p>— {live.message}</p></div> : null}
          {!live.compiled && !live.message ? <div className="awaiting-sheet"><strong>AWAITING A COMPLETE CLAUSE</strong><span>Select complete keyholders in §2 to compile the policy.</span></div> : null}

          {live.compiled ? <div className="artifact-stack">
            <section className="artifact-block asm-artifact"><header><h3>BITCOIN SCRIPT · ASM</h3><CopyButton value={formattedAsm} label="Bitcoin Script ASM" /></header><pre className="asm-code" aria-label="Formatted Bitcoin Script"><code>{formattedAsm}</code></pre></section>
            <section className="artifact-block address-artifact"><header><h3>P2WSH ADDRESS</h3><label className="network-select"><span className="sr-only">Bitcoin network</span><select aria-label="Bitcoin network" value={network} onChange={(event) => {
              const value = event.currentTarget.value;
              if (isUiNetwork(value)) setNetwork(value);
            }}>{NETWORK_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><CopyButton value={live.compiled.address} label="P2WSH address" disabled={addressAndExportBlocked} /></header><p>{live.compiled.address}</p></section>
            <div className="export-row"><button type="button" onClick={downloadPolicy} disabled={addressAndExportBlocked}>↓ DOWNLOAD POLICY JSON</button></div>
          </div> : null}
        </section>

        <footer className="sheet-footer">
          <p>Generated locally from public keys only. Nothing is signed, stored, or transmitted. Reproduce the witness script and address independently, then rehearse every branch on {network} before funding.</p>
        </footer>
      </article>
    </main>
  );
}
