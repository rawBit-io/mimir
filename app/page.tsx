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
type TimelineYearTick = {
  year: number;
  ratio: number;
  edge: "start" | "middle" | "end";
};

const TIMELINE_CELLS = 34;
const SECONDS_PER_DAY = 86_400;

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

function buildTimelineYearTicks(startUnix: number, endUnix: number): TimelineYearTick[] {
  const startYear = new Date(startUnix * 1_000).getUTCFullYear();
  const endYear = new Date(endUnix * 1_000).getUTCFullYear();
  if (endUnix <= startUnix || startYear === endYear) {
    return [{ year: startYear, ratio: 0, edge: "start" }];
  }

  const rawStep = Math.ceil((endYear - startYear) / 4);
  const step = [1, 2, 5, 10, 20, 25, 50, 100].find((value) => value >= rawStep) ?? 100;
  const firstInterior = Math.ceil((startYear + 1) / step) * step;
  const candidates: TimelineYearTick[] = [];

  for (let year = firstInterior; year < endYear; year += step) {
    const unix = Date.UTC(year, 0, 1) / 1_000;
    candidates.push({
      year,
      ratio: Math.min(1, Math.max(0, (unix - startUnix) / (endUnix - startUnix))),
      edge: "middle",
    });
  }

  const interior: TimelineYearTick[] = [];
  let previousRatio = 0;
  for (const tick of candidates) {
    if (tick.ratio - previousRatio >= 0.16 && 1 - tick.ratio >= 0.16 && interior.length < 3) {
      interior.push(tick);
      previousRatio = tick.ratio;
    }
  }

  return [
    { year: startYear, ratio: 0, edge: "start" },
    ...interior,
    { year: endYear, ratio: 1, edge: "end" },
  ];
}

function branchStarted(branch: PolicyBranch): boolean {
  return branch.signingMode !== null || branch.unlockDate !== null;
}

function branchComplete(branch: PolicyBranch): boolean {
  return branch.signingMode !== null && branch.keyRowIds.length > 0 && branch.unlockDate !== "";
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
      if (branch.unlockDate !== null) unixFromDirectScriptDate(branch.unlockDate);
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
        unlock_unix: branch.unlockDate === null ? null : unixFromDirectScriptDate(branch.unlockDate),
      })),
    };
    return { compiled: compileDirectScriptPolicy(request), message: null };
  } catch (error) {
    return { compiled: null, message: error instanceof Error ? error.message : "the policy could not be compiled" };
  }
}

function CopyButton({
  value,
  label,
  disabled = false,
}: {
  value: string;
  label: string;
  disabled?: boolean;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  async function copy() {
    if (disabled) return;
    try { await navigator.clipboard.writeText(value); setState("copied"); }
    catch { setState("failed"); }
    window.setTimeout(() => setState("idle"), 1_500);
  }
  const actionLabel = state === "copied"
    ? `${label} copied`
    : state === "failed"
      ? `${label} could not be copied`
      : `Copy ${label}`;
  return <>
    <button className={`copy-button is-${state}`} type="button" onClick={copy} disabled={disabled}
      aria-label={`Copy ${label}`} title={actionLabel}>
      {state === "copied" ? <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24">
        <path d="m5 12.5 4 4L19 7" />
      </svg> : state === "failed" ? <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24">
        <path d="M6 6 18 18M18 6 6 18" />
      </svg> : <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24">
        <path d="M8 8h11v12H8zM5 16H4V4h11v1" />
      </svg>}
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
    branch.unlockDate !== null && branch.unlockDate !== "" && branch.unlockDate < futureMinimum), [branches, futureMinimum]);
  const addressAndExportBlocked = hasDemoKey || hasNonFutureDelay;
  const { timelineRows, timelineYearTicks } = useMemo(() => {
    const completeBranches = branches.filter(branchComplete);
    const todayUnix = (Date.parse(`${futureMinimum}T00:00:00Z`) / 1_000) - SECONDS_PER_DAY;
    const unlockUnix = completeBranches.map((branch) => {
      if (!branch.unlockDate) return null;
      try { return unixFromDirectScriptDate(branch.unlockDate); }
      catch { return null; }
    });
    const datedUnlocks = unlockUnix.filter((value): value is number => value !== null);
    const axisEndUnix = Math.max(todayUnix, ...datedUnlocks);
    const finalUnix = Math.max(todayUnix + SECONDS_PER_DAY, ...datedUnlocks);
    const duration = finalUnix - todayUnix;

    const lanes = completeBranches.map((branch, index) => {
      const lockUnix = unlockUnix[index];
      const waitRatio = lockUnix === null ? 0 : Math.min(1, Math.max(0, (lockUnix - todayUnix) / duration));
      const selected = new Set(branch.keyRowIds);
      const keyNames = branch.keyRowIds.map((id) => rowById.get(id)?.label.trim() || "unnamed keyholder");
      return {
        id: branch.id,
        tag: `C${index + 1}`,
        delayed: lockUnix !== null,
        unlockDate: branch.unlockDate || null,
        threshold: branch.keyRowIds.length === 1 ? 1 : branch.threshold,
        keyCount: branch.keyRowIds.length,
        keyNames,
        slots: rows.map((row, keyIndex) => selected.has(row.id) ? String(keyIndex + 1) : "·"),
        openFrom: Math.round(waitRatio * TIMELINE_CELLS),
      };
    });
    return {
      timelineRows: lanes,
      timelineYearTicks: buildTimelineYearTicks(todayUnix, axisEndUnix),
    };
  }, [branches, futureMinimum, rowById, rows]);

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
    if (rows.length === 1) {
      setFeedback("at least one keyholder row is required");
      return;
    }
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
    setFeedback("workspace reset — nothing was persisted");
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
    if (branch.unlockDate === null) return `${who.charAt(0).toUpperCase()}${who.slice(1)} may spend at any time.`;
    if (branch.unlockDate === "") return "Choose an unlock date before this clause can be compiled.";
    return `From ${readableDate(branch.unlockDate)} onward, ${who} may spend.`;
  }

  const canAddClause = branches.length < MAX_DIRECT_SCRIPT_CLAUSES && branches.every(branchComplete);
  const commandNetwork = network === "bitcoin" ? "mainnet" : network;

  return (
    <main className="console-page">
      <header className="console-commandbar">
        <div className="command-prompt">
          <strong>MIMIR</strong>
          <span>mimir compile --network={commandNetwork} --clauses={branches.length}</span>
          <i aria-hidden="true"></i>
        </div>
        <nav className="console-actions" aria-label="Workspace actions">
          <button type="button" onClick={requestDemo} onBlur={() => setArmed(null)}>{armed === "demo" ? "really load?" : "demo"}</button>
          <button type="button" onClick={() => arm("reset")} onBlur={() => setArmed(null)}>{armed === "reset" ? "really reset?" : "reset"}</button>
        </nav>
      </header>

      <div className="console-workspace">
        <section className="console-panel input-panel" aria-labelledby="input-heading">
          <header className="panel-bar"><h1 id="input-heading">INPUT</h1><span>keys and clauses</span></header>
          <div className="input-body">
            <section className="console-section keys-section" aria-labelledby="keys-heading">
              <header className="console-section-title"><h2 id="keys-heading">KEYS</h2><i></i><b>{rows.length}/{MAX_DIRECT_SCRIPT_KEYS}</b></header>
              <div className="key-console-table">{rows.map((row, index) => {
                const state = fieldState.get(row.id);
                const visibleLabelError = row.label.trim() || row.publicKey.trim() ? state?.labelError : null;
                const visiblePublicKeyError = row.publicKey.trim() ? state?.publicKeyError : null;
                const visibleErrors = [
                  visibleLabelError ? `label: ${visibleLabelError}` : null,
                  visiblePublicKeyError ? `public key: ${visiblePublicKeyError}` : null,
                ].filter((message): message is string => Boolean(message));
                const errorId = `keyholder-${index + 1}-error`;
                return <div className="key-console-row" key={row.id}>
                  <span className="row-index">{String(index + 1).padStart(2, "0")}</span>
                  <label><span className="sr-only">keyholder {index + 1} label</span><input value={row.label}
                    onChange={(event) => updateRow(row.id, { label: event.target.value })} placeholder="label"
                    maxLength={80} autoComplete="off" aria-invalid={Boolean(visibleLabelError)}
                    aria-describedby={visibleErrors.length ? errorId : undefined} /></label>
                  <label><span className="sr-only">keyholder {index + 1} compressed public key</span><input value={row.publicKey}
                    onChange={(event) => updateRow(row.id, { publicKey: event.target.value.replace(/\s+/g, "") })}
                    placeholder="02… or 03… + 64 hex" autoComplete="off" autoCapitalize="none" spellCheck={false}
                    aria-invalid={Boolean(visiblePublicKeyError)} aria-describedby={visibleErrors.length ? errorId : undefined} /></label>
                  <button type="button" className="remove-button" onClick={() => removeKeyRow(row.id)}
                    aria-label={`remove ${row.label.trim() || `keyholder ${index + 1}`}`}
                    aria-disabled={usedByBranch.has(row.id) || rows.length === 1}
                    title={usedByBranch.has(row.id) ? "Remove this keyholder from every clause first" : rows.length === 1 ? "At least one keyholder row is required" : "Remove keyholder"}>×</button>
                  {visibleErrors.length ? <p id={errorId} className="inline-error">{visibleErrors.join(" · ")}</p> : null}
                </div>;
              })}</div>
              <button className="console-outline-action" type="button" onClick={addKeyRow} disabled={rows.length >= MAX_DIRECT_SCRIPT_KEYS}>[ + {rows.length >= MAX_DIRECT_SCRIPT_KEYS ? "key limit reached" : "add key"} ]</button>
            </section>

            <section className="console-section clauses-section" aria-labelledby="clauses-heading">
              <header className="console-section-title"><h2 id="clauses-heading">CLAUSES</h2><i></i><b>{branches.length}/{MAX_DIRECT_SCRIPT_CLAUSES}</b></header>
              <div className="clause-console-list">{branches.map((branch, index) => {
                const delayed = branch.unlockDate !== null;
                const names = branch.keyRowIds.map((id) => rowById.get(id)?.label.trim() || "unnamed");
                const unlockSummary = branch.unlockDate === null ? "now" : branch.unlockDate || "select date";
                const branchSummary = `clause[${index + 1}] = ${names.length ? `${names.length === 1 ? 1 : branch.threshold} of { ${names.join(", ")} }` : "select keyholders"} @ ${unlockSummary}`;
                return <article className={`clause-console-card${delayed ? " is-delayed" : ""}`} key={branch.id}>
                  <header>
                    <strong>clause[{index + 1}]</strong>
                    <span>{branchSummary}</span>
                    <button type="button" className="remove-button" onClick={() => removeBranch(branch.id)} aria-label={`remove clause ${index + 1}`}>×</button>
                  </header>
                  <p className="clause-sentence">{clauseSentence(branch)}</p>
                  <fieldset className="clause-key-picker"><legend>Keyholders in this clause</legend><div>{rows.map((row, rowIndex) => {
                    const state = fieldState.get(row.id);
                    const selected = branch.keyRowIds.includes(row.id);
                    const invalid = Boolean(state?.labelError || state?.publicKeyError);
                    return <button type="button" key={row.id} className={selected ? "is-selected" : ""}
                      onClick={() => toggleKeyInBranch(branch.id, row.id)} disabled={invalid}
                      aria-pressed={selected} title={selected ? "remove from this clause" : "add to this clause"}>
                      <span aria-hidden="true">[{selected ? "x" : " "}]</span> {row.label.trim() || `keyholder ${rowIndex + 1}`}
                    </button>;
                  })}</div></fieldset>
                  <div className="clause-settings">
                    <fieldset className="signature-picker"><legend>k =</legend><div>{branch.keyRowIds.length
                      ? branch.keyRowIds.map((_, thresholdIndex) => {
                        const value = thresholdIndex + 1;
                        return <button type="button" key={value} className={branch.threshold === value ? "is-selected" : ""}
                          onClick={() => setThreshold(branch.id, value)} aria-pressed={branch.threshold === value}>{value}</button>;
                      })
                      : <span>—</span>}</div></fieldset>
                    <fieldset className="effective-picker"><legend>opens</legend><div className="effective-row">
                      <span className="segmented-control"><button type="button" className={!delayed ? "is-selected" : ""} onClick={() => setImmediate(branch.id)} aria-pressed={!delayed}>at once</button><button type="button" className={delayed ? "is-selected" : ""} onClick={() => setDelayed(branch.id)} aria-pressed={delayed}>from date</button></span>
                      {delayed ? <label><span className="sr-only">clause {index + 1} unlock date</span><input type="date"
                        value={branch.unlockDate ?? ""} min={futureMinimum} max="2106-02-07" aria-invalid={branch.unlockDate === ""}
                        onChange={(event) => updateBranch(branch.id, (current) => ({ ...current, unlockDate: event.target.value }))} /></label> : null}
                    </div></fieldset>
                  </div>
                </article>;
              })}</div>
              {canAddClause ? <button className="console-outline-action" type="button" onClick={addSpendingPath}>[ + add clause ]</button> : null}
              {feedback ? <p className="activity-line" role="status" aria-live="polite">{feedback}</p> : null}
            </section>
          </div>
        </section>

        <aside className="console-panel output-panel" aria-labelledby="output-heading">
          <header className="panel-bar"><h2 id="output-heading">OUTPUT</h2><span>bitcoin script and address</span></header>
          <div className="output-body">
            {hasDemoKey ? <div className="console-alert is-warning" role="alert"><strong>DEMO KEYS · DO NOT FUND</strong><span>These private keys are public knowledge. Address copy and JSON export are blocked.</span></div> : null}
            {hasNonFutureDelay ? <div className="console-alert is-error" role="alert"><strong>LOCK DATE REQUIRES REVIEW</strong><span>A clause is already active or past. Exact artifacts remain visible; address copy and export are blocked.</span></div> : null}

            {live.message ? <div className="console-error" role="alert"><strong>ARTIFACTS WITHHELD</strong><p>{live.message}</p></div> : null}
            {!live.compiled && !live.message ? <div className="console-awaiting"><strong>AWAITING POLICY</strong><span>Complete one clause to produce the Bitcoin Script and address.</span></div> : null}

            {live.compiled ? <>
              <section className="timeline" aria-labelledby="timeline-heading">
                <h3 id="timeline-heading">TIMELINE</h3>
                <div className="timeline-rows">{timelineRows.map((lane) => <div
                  className={`timeline-row${lane.delayed ? " is-delayed" : " is-immediate"}`}
                  key={lane.id}
                  aria-label={`${lane.tag}: ${lane.keyNames.join(", ")}; ${lane.unlockDate ? `from ${lane.unlockDate}` : "available now"}; ${lane.threshold} of ${lane.keyCount}`}
                >
                  <span className="timeline-tag">{lane.tag}</span>
                  <span className="timeline-keys" aria-hidden="true">{lane.slots.map((slot, slotIndex) => <span
                    className={slot === "·" ? "is-empty" : ""}
                    key={slotIndex}
                  >{slot}</span>)}</span>
                  <span className="timeline-track" aria-hidden="true">{Array.from({ length: TIMELINE_CELLS }, (_, cellIndex) => <span
                    className={`timeline-cell${cellIndex < lane.openFrom ? " is-dormant" : " is-open"}`}
                    key={cellIndex}
                  ></span>)}</span>
                  <span className="timeline-summary">
                    {lane.unlockDate ? <time dateTime={lane.unlockDate}>{lane.unlockDate}</time> : <span>now</span>}
                    <span aria-hidden="true"> · </span>
                    <b>{lane.threshold}/{lane.keyCount}</b>
                  </span>
                </div>)}</div>
                <div
                  className="timeline-axis-row"
                  role="img"
                  aria-label={`Timeline years ${timelineYearTicks[0]?.year ?? ""} through ${timelineYearTicks.at(-1)?.year ?? ""}`}
                >
                  <span className="timeline-axis-clause-space" aria-hidden="true"></span>
                  <span className="timeline-axis-key-space" aria-hidden="true">{rows.map((row) => <i key={row.id}></i>)}</span>
                  <span className="timeline-axis" aria-hidden="true">{timelineYearTicks.map((tick) => <span
                    className={`timeline-year is-${tick.edge}`}
                    key={`${tick.year}-${tick.edge}`}
                    style={{ left: `${tick.ratio * 100}%` }}
                  ><b>{tick.year}</b></span>)}</span>
                  <span className="timeline-axis-summary-space" aria-hidden="true"></span>
                </div>
                <div className="timeline-legend" aria-label="Timeline keyholder legend">{rows.map((row, index) => <span key={row.id}>
                  <b>{index + 1}</b> {row.label.trim() || `keyholder ${index + 1}`}
                </span>)}</div>
              </section>

              <div className="artifact-stack">
                <section className="artifact-block address-artifact"><header><h3>P2WSH ADDRESS</h3><label className="network-select"><span className="sr-only">Bitcoin network</span><select aria-label="Bitcoin network" value={network} onChange={(event) => {
                  const value = event.currentTarget.value;
                  if (isUiNetwork(value)) setNetwork(value);
                }}>{NETWORK_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
                  <CopyButton value={live.compiled.address} label="P2WSH address" disabled={addressAndExportBlocked} />
                </header><p>{live.compiled.address}</p></section>
                <section className="artifact-block asm-artifact"><header><h3>BITCOIN SCRIPT · ASM</h3>
                  <CopyButton value={formattedAsm} label="Bitcoin Script ASM" />
                </header><pre className="asm-code" aria-label="Formatted Bitcoin Script"><code>{formattedAsm}</code></pre></section>
              </div>
            </> : null}

            <p className="local-note">Generated locally from public keys only. Nothing is signed, stored, or transmitted. Reproduce the script independently and rehearse every branch before funding.</p>
          </div>

          <footer className="output-dock">
            <button type="button" onClick={downloadPolicy}
              disabled={!live.compiled || addressAndExportBlocked}>[ export json ]</button>
          </footer>
        </aside>
      </div>
    </main>
  );
}
