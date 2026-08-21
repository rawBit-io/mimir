"use client";

import { useEffect, useMemo, useRef, useState, type DragEvent } from "react";
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

type UiNetwork = Exclude<ReadOnceNetwork, "bitcoin">;
type KeyRow = { id: string; label: string; publicKey: string };
type SigningMode = "key" | "multisig" | null;
type PolicyBranch = {
  id: string;
  signingMode: SigningMode;
  keyRowIds: string[];
  threshold: number;
  andSlot: boolean;
  unlockDate: string | null;
};
type FieldState = {
  labelError: string | null;
  publicKeyError: string | null;
  normalizedPublicKey: string | null;
};
type LiveResult = { compiled: CompiledReadOncePolicy | null; message: string | null };
type PaletteBlock = "and" | "or" | "multisig" | "timelock";

const DRAG_MIME = "application/x-mimir-policy-block";
const DEMO_PUBLIC_KEYS = [
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
] as const;

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
  return {
    id,
    signingMode: null,
    keyRowIds: [],
    threshold: 1,
    andSlot: false,
    unlockDate: null,
  };
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
    { ...makeBranch("branch-2"), signingMode: "multisig", keyRowIds: all, threshold: 3, andSlot: true, unlockDate: dates[0] },
    { ...makeBranch("branch-3"), signingMode: "multisig", keyRowIds: all, threshold: 2, andSlot: true, unlockDate: dates[1] },
    { ...makeBranch("branch-4"), signingMode: "multisig", keyRowIds: all, threshold: 1, andSlot: true, unlockDate: dates[2] },
  ];
}

function isUiNetwork(value: string): value is UiNetwork {
  return value === "regtest" || value === "signet";
}

function shortKey(value: string): string {
  const normalized = value.trim();
  return normalized.length < 18 ? normalized : `${normalized.slice(0, 10)}…${normalized.slice(-6)}`;
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

function branchStarted(branch: PolicyBranch): boolean {
  return branch.signingMode !== null || branch.andSlot || branch.unlockDate !== null;
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
      ? row.publicKey.trim() ? "invalid compressed secp256k1 public key" : "enter a compressed public key"
      : (publicKeyCounts.get(publicKey) ?? 0) > 1 ? "public key already registered" : null;
    return [row.id, { labelError, publicKeyError, normalizedPublicKey: publicKey }];
  }));
}

function compileTree(
  rows: KeyRow[],
  branches: PolicyBranch[],
  network: UiNetwork,
): LiveResult {
  const active = branches.filter(branchStarted);
  if (active.length === 0) return { compiled: null, message: null };
  try {
    const rowById = new Map(rows.map((row) => [row.id, row]));
    active.forEach((branch, index) => {
      if (!branch.signingMode || branch.keyRowIds.length === 0) {
        throw new Error(`path P${String(index + 1).padStart(2, "0")} needs a key or multisig block`);
      }
      if (branch.threshold < 1 || branch.threshold > branch.keyRowIds.length) {
        throw new Error(`path P${String(index + 1).padStart(2, "0")} has an invalid signature threshold`);
      }
      if (branch.andSlot && !branch.unlockDate) {
        throw new Error(`path P${String(index + 1).padStart(2, "0")} has an empty AND condition`);
      }
      if (branch.unlockDate) unixFromReadOnceDate(branch.unlockDate);
    });

    const usedIds = [...new Set(active.flatMap((branch) => branch.keyRowIds))];
    for (const id of usedIds) {
      const row = rowById.get(id);
      if (!row) throw new Error("a path references a removed key");
      if (!row.label.trim()) throw new Error("every key used by a path needs a label");
      validateReadOncePublicKey(row.publicKey);
    }

    const completeRows = rows.flatMap((row) => {
      const label = row.label.trim().normalize("NFC");
      if (!label || !row.publicKey.trim()) return [];
      try {
        return [{ row, label, publicKey: validateReadOncePublicKey(row.publicKey) }];
      } catch {
        return [];
      }
    }).sort((left, right) =>
      left.publicKey.localeCompare(right.publicKey) || left.label.localeCompare(right.label));
    if (new Set(completeRows.map((entry) => entry.label.toLocaleLowerCase("en-US"))).size !== completeRows.length) {
      throw new Error("registered key labels must be unique");
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
          if (!id) throw new Error("complete every key used in the policy tree");
          return id;
        }),
        threshold: branch.keyRowIds.length === 1 ? 1 : branch.threshold,
        unlock_unix: branch.unlockDate ? unixFromReadOnceDate(branch.unlockDate) : null,
      })),
    };
    return { compiled: compileReadOncePolicy(request), message: null };
  } catch (error) {
    return {
      compiled: null,
      message: error instanceof Error ? error.message : "the policy tree could not be compiled",
    };
  }
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  async function copy() {
    try { await navigator.clipboard.writeText(value); setState("copied"); }
    catch { setState("failed"); }
    window.setTimeout(() => setState("idle"), 1_500);
  }
  return <>
    <button className="copy" type="button" onClick={copy} aria-label={`copy ${label}`}>
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

export default function Home() {
  const [rows, setRows] = useState<KeyRow[]>(initialRows);
  const [branches, setBranches] = useState<PolicyBranch[]>([makeBranch("branch-1")]);
  const [activeBranchId, setActiveBranchId] = useState("branch-1");
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
  const activeBranch = branches.find((branch) => branch.id === activeBranchId) ?? branches[0];
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
    setActiveBranchId(id);
  }

  function addKeyRow() {
    if (rows.length >= MAX_READ_ONCE_KEYS) return;
    const id = `key-row-${nextKeyId.current}`;
    nextKeyId.current += 1;
    setRows((current) => [...current, { id, label: "", publicKey: "" }]);
    setFeedback(`key ${rows.length + 1} added to the registry`);
  }

  function removeKeyRow(id: string) {
    if (usedByBranch.has(id)) {
      setFeedback("key is used in the policy tree — remove it from those paths first");
      return;
    }
    if (rows.length === 1) return;
    setRows((current) => current.filter((row) => row.id !== id));
    setFeedback("key removed from the registry");
  }

  function addOrBranch() {
    const untouched = branches.find((branch) => !branchStarted(branch));
    if (untouched) {
      setActiveBranchId(untouched.id);
      setFeedback("empty OR branch selected");
      return;
    }
    if (branches.length >= MAX_READ_ONCE_PATHS) {
      setFeedback("five spending paths is the limit");
      return;
    }
    const id = `branch-${nextBranchId.current}`;
    nextBranchId.current += 1;
    setBranches((current) => [...current, makeBranch(id)]);
    setActiveBranchId(id);
    setFeedback("OR branch added — drop a key or multisig block into it");
  }

  function removeBranch(id: string) {
    if (branches.length === 1) {
      setBranches([makeBranch("branch-1")]);
      setActiveBranchId("branch-1");
      setFeedback("branch cleared");
      return;
    }
    const remaining = branches.filter((branch) => branch.id !== id);
    setBranches(remaining);
    if (activeBranchId === id) setActiveBranchId(remaining[0].id);
    setFeedback("branch removed — policy recompiled");
  }

  function addKeyToBranch(rowId: string, branchId = activeBranch.id) {
    const state = fieldState.get(rowId);
    if (!state || state.labelError || state.publicKeyError) {
      setFeedback("complete and verify that public key before using it");
      return;
    }
    updateBranch(branchId, (branch) => {
      if (branch.keyRowIds.includes(rowId)) return branch;
      if (branch.keyRowIds.length >= MAX_READ_ONCE_KEYS) return branch;
      const keyRowIds = [...branch.keyRowIds, rowId];
      const signingMode: SigningMode = branch.signingMode === "multisig" || keyRowIds.length > 1
        ? "multisig"
        : "key";
      const threshold = branch.signingMode === null
        ? 1
        : branch.signingMode === "key" && keyRowIds.length === 2
          ? 2
          : Math.min(Math.max(1, branch.threshold), keyRowIds.length);
      return { ...branch, signingMode, keyRowIds, threshold };
    });
    setFeedback(`${rowById.get(rowId)?.label || "key"} added to the selected path`);
  }

  function removeKeyFromBranch(branchId: string, rowId: string) {
    updateBranch(branchId, (branch) => {
      const keyRowIds = branch.keyRowIds.filter((id) => id !== rowId);
      const signingMode = keyRowIds.length === 0 && branch.signingMode === "key"
        ? null
        : branch.signingMode;
      return {
        ...branch,
        signingMode,
        keyRowIds,
        threshold: Math.min(Math.max(1, branch.threshold), Math.max(1, keyRowIds.length)),
      };
    });
  }

  function applyBlock(block: PaletteBlock, branchId = activeBranch.id) {
    if (block === "or") {
      addOrBranch();
      return;
    }
    if (block === "and") {
      updateBranch(branchId, (branch) => branch.andSlot ? branch : { ...branch, andSlot: true });
      setFeedback("AND condition added — drop TIMELOCK into the empty condition slot");
      return;
    }
    if (block === "timelock") {
      updateBranch(branchId, (branch) => branch.unlockDate
        ? branch
        : { ...branch, andSlot: true, unlockDate: defaultUnlockDate() });
      setFeedback("timelock added at 00:00 UTC — adjust the date in the branch");
      return;
    }
    updateBranch(branchId, (branch) => branch.signingMode
      ? branch
      : { ...branch, signingMode: "multisig", keyRowIds: [], threshold: 1 });
    setFeedback("multisig block added — add keys and choose K");
  }

  function startDrag(event: DragEvent<HTMLElement>, payload: string) {
    event.dataTransfer.effectAllowed = "copy";
    event.dataTransfer.setData(DRAG_MIME, payload);
  }

  function dropIntoBranch(event: DragEvent<HTMLElement>, branchId: string) {
    event.preventDefault();
    setActiveBranchId(branchId);
    const payload = event.dataTransfer.getData(DRAG_MIME);
    if (payload.startsWith("key:")) addKeyToBranch(payload.slice(4), branchId);
    else if (["and", "or", "multisig", "timelock"].includes(payload)) {
      applyBlock(payload as PaletteBlock, branchId);
    }
  }

  function setThreshold(branchId: string, threshold: number) {
    updateBranch(branchId, (branch) => ({ ...branch, threshold }));
  }

  function removeSigning(branchId: string) {
    updateBranch(branchId, (branch) => ({ ...branch, signingMode: null, keyRowIds: [], threshold: 1 }));
  }

  function removeTimelock(branchId: string) {
    updateBranch(branchId, (branch) => ({ ...branch, andSlot: false, unlockDate: null }));
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
    setActiveBranchId("branch-1");
    setNetwork("regtest");
    nextKeyId.current = 5;
    nextBranchId.current = 5;
    setFeedback("demo loaded — Owner repeats visually but is emitted once after normalization");
  }

  function requestDemo() {
    if (activeBranches.length === 0 && rows.every((row) => !row.publicKey.trim())) loadDemo();
    else arm("demo");
  }

  function reset() {
    setRows(initialRows());
    setBranches([makeBranch("branch-1")]);
    setActiveBranchId("branch-1");
    setNetwork("regtest");
    setFutureMinimum(firstFutureDate());
    nextKeyId.current = 3;
    nextBranchId.current = 2;
    setFeedback("session reset — nothing was persisted");
  }

  function downloadPolicy() {
    if (!live.compiled || hasDemoKey) return;
    const currentMinimum = firstFutureDate();
    if (branches.some((branch) => branch.unlockDate && branch.unlockDate < currentMinimum)) {
      setFutureMinimum(currentMinimum);
      setFeedback("export blocked — rebuild the path whose lock date is active or past");
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

  function branchSummary(branch: PolicyBranch): string {
    if (!branch.signingMode || branch.keyRowIds.length === 0) return "incomplete — add key or multisig";
    const names = branch.keyRowIds.map((id) => rowById.get(id)?.label.trim() || "unnamed");
    const signing = names.length === 1 ? names[0] : `${branch.threshold}-of-${names.length} · ${names.join(", ")}`;
    return branch.unlockDate ? `${signing} · from ${readableDate(branch.unlockDate)}` : `${signing} · immediately`;
  }

  const stdoutState = live.compiled
    ? hasDemoKey && hasNonFutureDelay ? "DO-NOT-FUND · REVIEW DATE"
      : hasDemoKey ? "DO-NOT-FUND"
        : hasNonFutureDelay ? "REVIEW DATE" : "COMPILED"
    : activeBranches.length ? "NOT COMPILED" : "AWAITING POLICY";
  const statusTone = live.compiled
    ? addressAndExportBlocked ? "amber" : "green"
    : activeBranches.length ? "red" : "dim";
  const multisigDisabled = Boolean(activeBranch.signingMode);
  const timelockDisabled = Boolean(activeBranch.unlockDate);
  const andDisabled = activeBranch.andSlot;
  const orDisabled = branches.length >= MAX_READ_ONCE_PATHS && branches.every(branchStarted);

  return (
    <main className="terminal-shell">
      <header className="topbar">
        <div className="brand"><strong>MIMIR</strong><span>v6 · PREVIEW</span><span>template {TEMPLATE_ID_READ_ONCE}</span></div>
        <div className="top-actions">
          <span className="network-label">NETWORK</span>
          {(["regtest", "signet"] as const).map((value) => <button key={value} type="button"
            className={`network-button${network === value ? " is-active" : ""}`}
            aria-pressed={network === value} onClick={() => { if (isUiNetwork(value)) setNetwork(value); }}>{value.toUpperCase()}</button>)}
          <button className="plain-button" type="button" onClick={requestDemo} onBlur={() => setArmed(null)}>
            {armed === "demo" ? "REALLY LOAD?" : "DEMO"}
          </button>
          <button className="plain-button" type="button" onClick={() => arm("reset")} onBlur={() => setArmed(null)}>
            {armed === "reset" ? "REALLY RESET?" : "RESET"}
          </button>
        </div>
      </header>

      <div className="page-wrap">
        <section className="hero" aria-labelledby="hero-title">
          <p className="prompt">$ mimir compose</p>
          <h1 id="hero-title">Declare your keys. Compose the<br />policy. Watch the script compile.</h1>
          <p className="hero-facts"><span>public keys only</span><span>compiles on every change</span><span>no network calls</span><span>nothing persisted</span></p>
        </section>

        {hasDemoKey ? <div className="alert demo-alert" role="alert"><strong>DEMO KEYS — DO NOT FUND</strong><span>private keys are public knowledge; address copy and export are blocked.</span></div> : null}
        {hasNonFutureDelay ? <div className="alert review-alert" role="alert"><strong>REVIEW DATE</strong><span>a lock is active or past; exact script remains visible, but address copy and export are blocked.</span></div> : null}

        <section className="terminal-section keys-section" aria-labelledby="keys-heading">
          <header className="section-heading"><span>01</span><h2 id="keys-heading">KEYS</h2><p>a label and a compressed public key — nothing else</p><i></i><b>{rows.length}/{MAX_READ_ONCE_KEYS}</b></header>
          <div className="key-columns" aria-hidden="true"><span></span><span>LABEL</span><span>COMPRESSED PUBLIC KEY · secp256k1</span><span></span></div>
          <div className="key-registry">{rows.map((row, index) => {
            const state = fieldState.get(row.id);
            const usedCount = branches.filter((branch) => branch.keyRowIds.includes(row.id)).length;
            const keyVerified = Boolean(state?.normalizedPublicKey && !state.publicKeyError);
            return <article className="registry-row" key={row.id}>
              <span className="row-number" aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
              <label><span className="sr-only">key {index + 1} label</span><input value={row.label}
                onChange={(event) => updateRow(row.id, { label: event.target.value })} placeholder="Signer label"
                maxLength={80} autoComplete="off" aria-invalid={Boolean(state?.labelError)} /></label>
              <label><span className="sr-only">key {index + 1} compressed public key</span><input value={row.publicKey}
                onChange={(event) => updateRow(row.id, { publicKey: event.target.value })}
                placeholder="02… or 03… + 64 hex" autoComplete="off" autoCapitalize="none" spellCheck={false}
                aria-invalid={Boolean(state?.publicKeyError)} /></label>
              <button className="icon-remove" type="button" onClick={() => removeKeyRow(row.id)}
                aria-label={`remove ${row.label.trim() || `key ${index + 1}`}`} aria-disabled={usedByBranch.has(row.id)}>×</button>
              <p className={`key-status${keyVerified ? " is-valid" : state?.publicKeyError && row.publicKey.trim() ? " is-error" : ""}`}>
                {keyVerified ? "secp256k1 point verified" : state?.publicKeyError ?? "awaiting key"}
                <span>{usedCount ? `used in ${usedCount} ${usedCount === 1 ? "path" : "paths"}` : "unused"}</span>
              </p>
            </article>;
          })}</div>
          <button className="add-key" type="button" onClick={addKeyRow} disabled={rows.length >= MAX_READ_ONCE_KEYS}>+ {rows.length >= MAX_READ_ONCE_KEYS ? "KEY LIMIT REACHED" : "ADD KEY"}</button>
        </section>

        <div className="composer-grid">
          <div className="policy-column">
            <section className="terminal-section policy-section" aria-labelledby="policy-heading">
              <header className="section-heading"><span>02</span><h2 id="policy-heading">POLICY</h2><p>select a slot, then click a block — or drag one in</p><i></i><b>{activeBranches.length}/{MAX_READ_ONCE_PATHS}</b></header>

              <div className="palette" aria-label="policy blocks">
                <p className="palette-label">BLOCKS · click or drag into the selected path</p>
                <div className="block-palette">
                  {([
                    ["and", "AND", "both required", andDisabled],
                    ["or", "OR", "either one", orDisabled],
                    ["multisig", "MULTISIG", "k-of-n keys", multisigDisabled],
                    ["timelock", "TIMELOCK", "not before date", timelockDisabled],
                  ] as const).map(([kind, title, subtitle, disabled]) => <button key={kind} type="button"
                    className={`palette-block block-${kind}`} disabled={disabled} draggable={!disabled}
                    onDragStart={(event) => startDrag(event, kind)} onClick={() => applyBlock(kind)}>
                    <strong>{title}</strong><span>{subtitle}</span>
                  </button>)}
                </div>
                <div className="palette-divider"></div>
                <p className="palette-label">KEYS · reusable in every path</p>
                <div className="key-palette">{rows.map((row) => {
                  const state = fieldState.get(row.id);
                  const invalid = Boolean(state?.labelError || state?.publicKeyError);
                  const selected = activeBranch.keyRowIds.includes(row.id);
                  return <button key={row.id} type="button" disabled={invalid || selected}
                    className={`key-block${selected ? " is-used-here" : ""}`} draggable={!invalid && !selected}
                    onDragStart={(event) => startDrag(event, `key:${row.id}`)} onClick={() => addKeyToBranch(row.id)}>
                    <strong>{row.label.trim() || "Unnamed"}</strong><code>{state?.normalizedPublicKey ? shortKey(state.normalizedPublicKey) : "complete key first"}</code>
                  </button>;
                })}</div>
              </div>

              <div className="policy-tree">
                <div className="root-node"><span>ROOT</span><strong>OR</strong><p>either branch alone can spend</p></div>
                <div className="branches">{branches.map((branch, index) => {
                  const isActive = branch.id === activeBranch.id;
                  const branchLetter = String.fromCharCode(65 + index);
                  return <article key={branch.id} className={`policy-branch${isActive ? " is-active" : ""}`}
                    onDragOver={(event) => { event.preventDefault(); event.dataTransfer.dropEffect = "copy"; }}
                    onDrop={(event) => dropIntoBranch(event, branch.id)}>
                    <header className="branch-heading">
                      <button type="button" className="branch-select" onClick={() => setActiveBranchId(branch.id)}
                        aria-pressed={isActive}><span>{branchLetter}</span><b>{isActive ? "SELECTED PATH" : "SELECT PATH"}</b></button>
                      <button type="button" className="icon-remove" onClick={() => removeBranch(branch.id)} aria-label={`remove path ${index + 1}`}>×</button>
                    </header>

                    {branch.unlockDate ? <div className="tree-row timelock-node">
                      <span className="tree-connector">{branch.signingMode ? "WHEN" : branchLetter}</span>
                      <div className="node-title"><strong>TIMELOCK</strong><span>dormant until {readableDate(branch.unlockDate)}</span></div>
                      <label className="date-control"><span className="sr-only">path {index + 1} unlock date</span><input type="date"
                        value={branch.unlockDate} min={futureMinimum} max="2038-01-19"
                        onChange={(event) => updateBranch(branch.id, (current) => ({ ...current, unlockDate: event.target.value }))} /></label>
                      <button type="button" className="node-remove" onClick={() => removeTimelock(branch.id)} aria-label={`remove timelock from path ${index + 1}`}>×</button>
                    </div> : branch.andSlot ? <button type="button" className="empty-condition"
                      onClick={() => applyBlock("timelock", branch.id)}><span>AND</span>DROP TIMELOCK HERE</button> : null}

                    {branch.unlockDate && branch.signingMode ? <div className="then-row"><span>THEN</span></div> : null}

                    {branch.signingMode ? <div className="tree-row signing-node">
                      <span className="tree-connector">{branch.unlockDate ? "" : branchLetter}</span>
                      <div className="node-title"><strong>{branch.signingMode === "multisig" ? "MULTISIG" : "KEY"}</strong>
                        <span>{branch.keyRowIds.length > 1 ? `${branch.threshold}-of-${branch.keyRowIds.length}` : branch.keyRowIds.length ? "single signature" : "add keys"}</span></div>
                      {branch.signingMode === "multisig" && branch.keyRowIds.length ? <div className="threshold-control" role="group" aria-label={`signatures required for path ${index + 1}`}>
                        <span>REQUIRE</span>{branch.keyRowIds.map((_, thresholdIndex) => {
                          const value = thresholdIndex + 1;
                          return <button type="button" key={value} className={branch.threshold === value ? "is-active" : ""}
                            aria-pressed={branch.threshold === value} onClick={() => setThreshold(branch.id, value)}>{value}</button>;
                        })}
                      </div> : null}
                      <div className="selected-keys">{branch.keyRowIds.length
                        ? branch.keyRowIds.map((id) => <span className="key-chip" key={id}>{rowById.get(id)?.label || "missing"}<button type="button"
                          onClick={() => removeKeyFromBranch(branch.id, id)} aria-label={`remove ${rowById.get(id)?.label || "key"} from path ${index + 1}`}>×</button></span>)
                        : <span className="drop-hint">drop keys here</span>}</div>
                      <button type="button" className="node-remove" onClick={() => removeSigning(branch.id)} aria-label={`remove signing block from path ${index + 1}`}>×</button>
                    </div> : <button type="button" className="empty-branch" onClick={() => setActiveBranchId(branch.id)}>
                      <span>+</span><strong>DROP KEY OR MULTISIG HERE</strong><small>this becomes one spending path</small>
                    </button>}

                    {branch.unlockDate && branch.signingMode ? <p className="branch-logic">AND · both the timelock and signature condition are required</p> : null}
                  </article>;
                })}</div>
                <button className="add-branch" type="button" onClick={addOrBranch} disabled={orDisabled}>+ ADD OR BRANCH</button>
              </div>
              <p className="canvas-help">AND · both conditions must pass <span>OR · either branch can spend</span> <span>TIMELOCK · branch dormant until its date</span></p>
            </section>

            <section className="terminal-section paths-section" aria-labelledby="paths-heading">
              <header className="section-heading"><span>03</span><h2 id="paths-heading">SPENDING PATHS</h2><p>enumerated from the tree · any one can spend</p><i></i></header>
              {activeBranches.length ? <ol className="spending-paths">{activeBranches.map((branch, index) => <li key={branch.id}>
                <span>P{String(index + 1).padStart(2, "0")}</span><p>{branchSummary(branch)}</p>
                <b className={branch.unlockDate ? "is-delayed" : ""}>{branch.unlockDate ? `from ${readableDate(branch.unlockDate)}` : "immediately"}</b>
              </li>)}</ol> : <p className="empty-output">No spending paths yet. Select the empty slot and add a key or multisig block.</p>}
            </section>
            <p className="activity-log" role="status" aria-live="polite">{feedback ? `log ▸ ${feedback}` : ""}</p>
          </div>

          <aside className="script-column" id="live-script" aria-labelledby="script-heading">
            <header className="script-title"><span>LIVE</span><h2 id="script-heading">BITCOIN SCRIPT</h2><i></i></header>
            <div className={`compile-state tone-${statusTone}`}><strong>{stdoutState}</strong>
              {live.compiled ? <span>{live.compiled.witness_script_bytes} bytes · {opcodeCount} opcodes</span> : null}<b aria-hidden="true">■</b></div>

            <section className="script-panel policy-readout"><h3>VISUAL POLICY</h3>
              {activeBranches.length ? <ol>{activeBranches.map((branch, index) => <li key={branch.id}><span>P{String(index + 1).padStart(2, "0")}</span>{branchSummary(branch)}</li>)}</ol>
                : <p className="empty-output">awaiting first path</p>}
              {live.message ? <p className="compile-error">! {lowerFirst(live.message)}</p> : null}
            </section>

            <section className="script-panel"><h3>NORMALIZATION</h3>
              {live.compiled ? <div className="normalization">
                <p><strong>{live.compiled.manifest.normalization.authored_key_occurrences}</strong> visual uses <span>▸</span> <strong>{live.compiled.manifest.normalization.emitted_key_checks}</strong> read-once checks</p>
                <ul>{live.compiled.manifest.normalization.notes.map((note) => <li key={note}>[x] {note}</li>)}</ul>
              </div> : <p className="empty-output">no verified read-once form</p>}
            </section>

            <section className="script-panel"><div className="panel-heading"><h3>MINISCRIPT</h3>{live.compiled ? <CopyButton value={live.compiled.miniscript} label="Miniscript" /> : null}</div>
              {live.compiled ? <pre><code>{live.compiled.miniscript}</code></pre> : <p className="empty-output">—</p>}
            </section>

            <section className="script-panel"><div className="panel-heading"><h3>SCRIPT · ASM</h3>{live.compiled ? <><span>{live.compiled.witness_script_bytes} / 3600 B</span><CopyButton value={live.compiled.asm} label="Bitcoin Script ASM" /></> : null}</div>
              {live.compiled ? <pre><code>{live.compiled.asm}</code></pre> : <p className="empty-output">—</p>}
            </section>

            <section className="script-panel"><div className="panel-heading"><h3>{network.toUpperCase()} P2WSH ADDRESS</h3>
              {live.compiled && !addressAndExportBlocked ? <CopyButton value={live.compiled.address} label="P2WSH address" /> : null}</div>
              {live.compiled ? <p className="address">{live.compiled.address}</p> : <p className="empty-output">—</p>}
              {live.compiled && addressAndExportBlocked ? <p className="blocked">COPY BLOCKED · {hasDemoKey ? "DEMO KEYS" : "REVIEW DATE"}</p> : null}
            </section>

            <section className="script-panel"><div className="panel-heading"><h3>DESCRIPTOR</h3>{live.compiled ? <CopyButton value={live.compiled.descriptor} label="descriptor" /> : null}</div>
              {live.compiled ? <pre><code>{live.compiled.descriptor}</code></pre> : <p className="empty-output">—</p>}
            </section>

            <details className="technical-details"><summary>TECHNICAL DETAILS · HEX · CHECKS</summary>
              {live.compiled ? <div>
                <TechnicalItem label="witness script · hex" value={live.compiled.witness_script_hex} />
                <TechnicalItem label="scriptpubkey · hex" value={live.compiled.script_pubkey_hex} />
                <TechnicalItem label="manifest · sha-256" value={live.compiled.policy_manifest_sha256} clustered />
                <p className="checks">CHECKS ▸ {live.compiled.invariants.filter((invariant) => invariant.ok).length}/{live.compiled.invariants.length} PASSED</p>
                <ul className="warnings">{live.compiled.warnings.map((warning) => <li key={warning}>! {lowerFirst(warning)}</li>)}</ul>
                <button className="export" type="button" disabled={addressAndExportBlocked} onClick={downloadPolicy}>EXPORT POLICY.JSON</button>
              </div> : <p className="empty-output">details appear after successful compilation</p>}
            </details>
          </aside>
        </div>

        <footer className="footer">
          <p><strong>PREVIEW SOFTWARE</strong> · rehearse on Regtest or Signet and verify every artifact independently before funding.</p>
          <p><strong>CLTV / MTP</strong> · dates are absolute UTC floors; spending requires nLockTime and a non-final nSequence.</p>
          <p><strong>NO PRIVATE KEYS</strong> · compressed public keys only. Nothing leaves this page.</p>
        </footer>
      </div>

      <a className="mobile-script-link" href="#live-script">{stdoutState} <span>VIEW SCRIPT ▸</span></a>
    </main>
  );
}
