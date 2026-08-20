"use client";

import {
  Check, Clock3, Clipboard, Download, GripVertical, KeyRound,
  Plus, RotateCcw, Trash2, UsersRound, X,
} from "lucide-react";
import { type DragEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  MAX_GUARDED_KEYS,
  MAX_GUARDED_RULES,
  TEMPLATE_ID_GUARDED,
  compileGuardedRulePolicy,
  unixFromGuardedRuleDate,
  validateGuardedRulePublicKey,
  type CompiledGuardedRulePolicy,
  type GuardedNetwork,
  type GuardedRuleComposerRequest,
} from "../lib/guarded-rule-composer";

type UiNetwork = Exclude<GuardedNetwork, "bitcoin">;
type SignerMark = "owner" | "recovery";
type SignerRow = { id: string; label: string; publicKey: string; mark: SignerMark };
type LocalPath = { id: string; keyRowIds: string[]; threshold: number; unlockDate: string | null };
type FieldState = {
  labelInvalid: boolean;
  publicKeyInvalid: boolean;
  labelError: string | null;
  publicKeyError: string | null;
};
type LiveResult = { compiled: CompiledGuardedRulePolicy | null; message: string | null };
type DraftBlockToken = "multisig" | "time-delay" | `key:${string}`;

const DRAFT_BLOCK_MIME = "application/x-mimir-path-block";
const DEMO_PUBLIC_KEYS = [
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
] as const;

function firstFuturePathDate(): string {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}

function defaultPathDate(): string {
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

function initialRows(): SignerRow[] {
  return [
    { id: "signer-0", label: "Owner", publicKey: "", mark: "owner" },
    { id: "signer-1", label: "Recovery", publicKey: "", mark: "recovery" },
  ];
}

function demoRows(): SignerRow[] {
  return [
    { id: "signer-0", label: "Owner", publicKey: DEMO_PUBLIC_KEYS[0], mark: "owner" },
    { id: "signer-1", label: "Recovery A", publicKey: DEMO_PUBLIC_KEYS[1], mark: "recovery" },
    { id: "signer-2", label: "Recovery B", publicKey: DEMO_PUBLIC_KEYS[2], mark: "recovery" },
    { id: "signer-3", label: "Recovery C", publicKey: DEMO_PUBLIC_KEYS[3], mark: "recovery" },
  ];
}

function isUiNetwork(value: string): value is UiNetwork {
  return value === "regtest" || value === "signet";
}

function shortKey(value: string): string {
  const normalized = value.trim();
  return normalized.length < 20 ? normalized || "Public key missing" : `${normalized.slice(0, 12)}…${normalized.slice(-10)}`;
}

function readableDate(value: string | null): string {
  if (!value) return "immediately";
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return "the selected date";
  const [, year, month, day] = match;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${Number(day)} ${months[Number(month) - 1]} ${year}, 00:00 UTC`;
}

function normalizedThreshold(value: number, count: number): number {
  return Math.min(Math.max(1, value), Math.max(1, count));
}

function signerSetKey(ids: string[]): string {
  return [...new Set(ids)].sort().join("|");
}

function validateRows(rows: SignerRow[]): Map<string, FieldState> {
  const labels = rows.map((row) => row.label.trim().normalize("NFC"));
  const labelCounts = new Map<string, number>();
  for (const label of labels) {
    const comparable = label.toLocaleLowerCase("en-US");
    labelCounts.set(comparable, (labelCounts.get(comparable) ?? 0) + 1);
  }
  const publicKeys = rows.map((row) => {
    try { return validateGuardedRulePublicKey(row.publicKey); } catch { return null; }
  });
  const publicKeyCounts = new Map<string, number>();
  for (const publicKey of publicKeys) {
    if (publicKey) publicKeyCounts.set(publicKey, (publicKeyCounts.get(publicKey) ?? 0) + 1);
  }
  return new Map(rows.map((row, index) => {
    const label = labels[index];
    const publicKey = publicKeys[index];
    const labelError = !label ? "Enter a signer label."
      : label.length > 80 ? "Use at most 80 characters."
        : /\p{Cc}/u.test(label) ? "Remove control characters from this label."
          : (labelCounts.get(label.toLocaleLowerCase("en-US")) ?? 0) > 1 ? "Use a unique signer label." : null;
    const publicKeyError = !publicKey
      ? row.publicKey.trim() ? "Use a valid 66-character compressed key starting with 02 or 03." : "Enter a compressed public key."
      : (publicKeyCounts.get(publicKey) ?? 0) > 1 ? "This public key is already listed." : null;
    return [row.id, {
      labelInvalid: Boolean(labelError), publicKeyInvalid: Boolean(publicKeyError), labelError, publicKeyError,
    }];
  }));
}

function compilePaths(rows: SignerRow[], paths: LocalPath[], network: UiNetwork): LiveResult {
  if (paths.length === 0) return { compiled: null, message: null };
  try {
    const rowById = new Map(rows.map((row) => [row.id, row]));
    const usedRowIds = [...new Set(paths.flatMap((path) => path.keyRowIds))];
    const usedRows = usedRowIds.map((id) => {
      const row = rowById.get(id);
      if (!row) throw new Error("A saved path references a removed key.");
      const label = row.label.trim().normalize("NFC");
      if (!label) throw new Error("Name every key used by a saved path.");
      return { row, label, publicKey: validateGuardedRulePublicKey(row.publicKey) };
    });
    if (new Set(usedRows.map((entry) => entry.label.toLocaleLowerCase("en-US"))).size !== usedRows.length) {
      throw new Error("Use a unique label for every key in the saved paths.");
    }
    if (new Set(usedRows.map((entry) => entry.publicKey)).size !== usedRows.length) {
      throw new Error("Use each public key only once in the key list.");
    }
    const completeRows = rows.flatMap((row) => {
      const label = row.label.trim().normalize("NFC");
      if (!label || !row.publicKey.trim()) return [];
      try {
        return [{ row, label, publicKey: validateGuardedRulePublicKey(row.publicKey) }];
      } catch {
        return [];
      }
    });
    const sortedKeys = [...completeRows].sort((left, right) =>
      left.publicKey.localeCompare(right.publicKey) || left.label.localeCompare(right.label));
    const requestIdByRowId = new Map(sortedKeys.map((entry, index) => [
      entry.row.id, `key-${String(index + 1).padStart(2, "0")}`,
    ]));
    const request: GuardedRuleComposerRequest = {
      format: "mimir-guarded-rule-request",
      version: 5,
      network,
      template_id: TEMPLATE_ID_GUARDED,
      keys: sortedKeys.map((entry, index) => ({
        id: `key-${String(index + 1).padStart(2, "0")}`,
        label: entry.label,
        public_key: entry.publicKey,
      })),
      rules: paths.map((path) => ({
        key_ids: path.keyRowIds.map((rowId) => {
          const requestId = requestIdByRowId.get(rowId);
          if (!requestId) throw new Error("A saved path contains an unknown key.");
          return requestId;
        }),
        threshold: path.threshold,
        unlock_unix: path.unlockDate ? unixFromGuardedRuleDate(path.unlockDate) : null,
      })),
    };
    return { compiled: compileGuardedRulePolicy(request), message: null };
  } catch (error) {
    return { compiled: null, message: error instanceof Error ? error.message : "The saved paths could not be compiled." };
  }
}

function pathSummary(path: LocalPath, rowById: Map<string, SignerRow>): string {
  const names = path.keyRowIds.map((id) => rowById.get(id)?.label.trim() || "Unnamed key");
  const signing = names.length === 1 ? names[0] : `${path.threshold} of ${names.length} · ${names.join(", ")}`;
  return `${signing} can spend ${path.unlockDate ? `from ${readableDate(path.unlockDate)}` : "immediately"}.`;
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  async function copy() {
    try { await navigator.clipboard.writeText(value); setState("copied"); }
    catch { setState("failed"); }
    window.setTimeout(() => setState("idle"), 1_500);
  }
  return <>
    <button className="copy-button" type="button" onClick={copy} aria-label={`Copy ${label}`}>
      {state === "copied" ? <Check size={15} aria-hidden="true" /> : <Clipboard size={15} aria-hidden="true" />}
      <span aria-hidden="true">{state === "copied" ? "Copied" : state === "failed" ? "Failed" : "Copy"}</span>
    </button>
    <span className="sr-only" role="status" aria-live="polite">
      {state === "copied" ? `${label} copied.` : state === "failed" ? `${label} could not be copied.` : ""}
    </span>
  </>;
}

function TechnicalItem({ label, value }: { label: string; value: string }) {
  return <div className="technical-item"><div><span>{label}</span><CopyButton key={value} value={value} label={label} /></div><code>{value}</code></div>;
}

export default function Home() {
  const [rows, setRows] = useState<SignerRow[]>(initialRows);
  const [paths, setPaths] = useState<LocalPath[]>([]);
  const [network, setNetwork] = useState<UiNetwork>("regtest");
  const [selectedKeyIds, setSelectedKeyIds] = useState<string[]>([]);
  const [multisig, setMultisig] = useState(false);
  const [threshold, setThreshold] = useState(1);
  const [timeDelay, setTimeDelay] = useState(false);
  const [unlockDate, setUnlockDate] = useState(defaultPathDate);
  const [futureMinimum, setFutureMinimum] = useState(firstFuturePathDate);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [dropActive, setDropActive] = useState(false);
  const nextSignerId = useRef(2);
  const nextPathId = useRef(1);

  useEffect(() => {
    const refresh = () => setFutureMinimum(firstFuturePathDate());
    const visible = () => { if (document.visibilityState === "visible") refresh(); };
    const timer = window.setInterval(refresh, 60_000);
    document.addEventListener("visibilitychange", visible);
    return () => { window.clearInterval(timer); document.removeEventListener("visibilitychange", visible); };
  }, []);

  const rowById = useMemo(() => new Map(rows.map((row) => [row.id, row])), [rows]);
  const fieldState = useMemo(() => validateRows(rows), [rows]);
  const live = useMemo(() => compilePaths(rows, paths, network), [rows, paths, network]);
  const usedByPath = useMemo(() => new Set(paths.flatMap((path) => path.keyRowIds)), [paths]);
  const hasDemoKey = useMemo(() => rows.some((row) =>
    DEMO_PUBLIC_KEYS.some((key) => key === row.publicKey.trim().toLowerCase())), [rows]);
  const hasNonFutureDelay = useMemo(() => paths.some((path) =>
    path.unlockDate !== null && path.unlockDate < futureMinimum), [paths, futureMinimum]);
  const addressAndExportBlocked = hasDemoKey || hasNonFutureDelay;

  const compatibility = (() => {
    if (selectedKeyIds.length === 0) return { error: null, note: null };
    const draftSet = new Set(selectedKeyIds);
    const draftSetKey = signerSetKey(selectedKeyIds);
    const savedSets = new Map<string, LocalPath[]>();
    for (const path of paths) {
      const key = signerSetKey(path.keyRowIds);
      savedSets.set(key, [...(savedSets.get(key) ?? []), path]);
    }
    for (const [savedSetKey, savedPaths] of savedSets) {
      if (savedSetKey === draftSetKey) continue;
      const savedIds = savedPaths[0].keyRowIds;
      const overlap = savedIds.filter((id) => draftSet.has(id));
      if (overlap.length > 0) {
        const overlapNames = overlap.map((id) => rowById.get(id)?.label.trim() || "Unnamed").join(", ");
        const fullNames = savedIds.map((id) => rowById.get(id)?.label.trim() || "Unnamed").join(", ");
        return {
          error: `Partial overlap is not compatible: ${overlapNames} already belongs to [${fullNames}]. Reuse exactly all ${savedIds.length} keys, or choose a disjoint set.`,
          note: null,
        };
      }
    }
    const matching = savedSets.get(draftSetKey) ?? [];
    if (matching.length === 0) return { error: null, note: "New signer set. It will compile as an independent OR branch." };
    const last = matching[matching.length - 1];
    if (last.threshold <= 1) return { error: "This signer set already reached 1-of-N. Its threshold cannot decrease again.", note: null };
    if (threshold >= last.threshold) return {
      error: `Compatible reuse needs a lower threshold than the previous ${last.threshold}-of-${last.keyRowIds.length} path.`, note: null,
    };
    if (!timeDelay) return { error: "Compatible reuse needs one Delay block so its date comes after the previous path.", note: null };
    if (last.unlockDate && unlockDate <= last.unlockDate) return {
      error: `Compatible reuse needs a date after ${readableDate(last.unlockDate)}.`, note: null,
    };
    return { error: null, note: `Compatible reuse: the exact signer set returns later with ${threshold}-of-${selectedKeyIds.length}.` };
  })();

  const draftMessage = (() => {
    if (paths.length >= MAX_GUARDED_RULES) return "Five saved paths is the limit.";
    if (selectedKeyIds.length === 0) return "Add at least one key block to this path.";
    if (!multisig && selectedKeyIds.length > 1) return "Multiple keys need the Multisig block.";
    if (multisig && selectedKeyIds.length < 2) return "Multisig needs at least two key blocks.";
    if (threshold < 1 || threshold > selectedKeyIds.length) return "Choose a valid K-of-N threshold.";
    for (const id of selectedKeyIds) {
      const state = fieldState.get(id);
      if (!state || state.labelInvalid || state.publicKeyInvalid) return "Complete every selected key before adding this path.";
    }
    if (timeDelay) {
      try { unixFromGuardedRuleDate(unlockDate); }
      catch (error) { return error instanceof Error ? error.message : "Choose a valid Delay date."; }
      if (unlockDate < futureMinimum) return "Choose a future UTC date for the Delay block.";
    }
    return compatibility.error;
  })();

  function updateRow(id: string, patch: Partial<Omit<SignerRow, "id">>) {
    setRows((current) => current.map((row) => row.id === id ? { ...row, ...patch } : row));
    setFeedback(null);
  }

  function addKey() {
    if (rows.length >= MAX_GUARDED_KEYS) return;
    const id = `signer-${nextSignerId.current}`;
    nextSignerId.current += 1;
    setRows((current) => [...current, { id, label: "", publicKey: "", mark: "recovery" }]);
    setFeedback("New key added.");
  }

  function removeKey(id: string) {
    const row = rowById.get(id);
    if (usedByPath.has(id)) {
      setFeedback(`Remove every saved path containing ${row?.label.trim() || "this key"} before deleting it.`);
      return;
    }
    setRows((current) => current.filter((entry) => entry.id !== id));
    const nextSelection = selectedKeyIds.filter((keyId) => keyId !== id);
    setSelectedKeyIds(nextSelection);
    setThreshold((value) => normalizedThreshold(value, nextSelection.length));
    setFeedback("Key removed.");
  }

  function addDraftKey(id: string) {
    const state = fieldState.get(id);
    if (selectedKeyIds.includes(id) || !state || state.labelInvalid || state.publicKeyInvalid) return;
    const related = paths.find((path) => path.keyRowIds.includes(id));
    const additions = related ? related.keyRowIds : [id];
    const nextSelection = [...selectedKeyIds];
    for (const addition of additions) if (!nextSelection.includes(addition)) nextSelection.push(addition);
    setSelectedKeyIds(nextSelection);
    setThreshold((value) => normalizedThreshold(value, nextSelection.length));
    setFeedback(related && additions.length > 1
      ? `This key is part of a saved ${additions.length}-key signer set, so Mimir restored the full set for compatible reuse.`
      : `${rowById.get(id)?.label.trim() || "Key"} added to the draft path.`);
  }

  function removeDraftKey(id: string) {
    const nextSelection = selectedKeyIds.filter((keyId) => keyId !== id);
    setSelectedKeyIds(nextSelection);
    setThreshold((value) => normalizedThreshold(value, nextSelection.length));
    setFeedback(`${rowById.get(id)?.label.trim() || "Key"} returned to the palette.`);
  }

  function addDraftBlock(token: DraftBlockToken) {
    if (token.startsWith("key:")) return addDraftKey(token.slice(4));
    if (token === "multisig" && !multisig) {
      setMultisig(true);
      setThreshold((value) => normalizedThreshold(value, selectedKeyIds.length));
      setFeedback("Multisig added. Choose K inside the block.");
      return;
    }
    if (token === "time-delay" && !timeDelay) {
      setTimeDelay(true);
      setFeedback("Delay added. Choose its absolute UTC date inside the block.");
    }
  }

  function startPaletteDrag(event: DragEvent<HTMLButtonElement>, token: DraftBlockToken) {
    event.dataTransfer.setData(DRAFT_BLOCK_MIME, token);
    event.dataTransfer.setData("text/plain", token);
    event.dataTransfer.effectAllowed = "copy";
    setDropActive(false);
  }

  function dropPaletteBlock(event: DragEvent<HTMLElement>) {
    event.preventDefault();
    setDropActive(false);
    const value = event.dataTransfer.getData(DRAFT_BLOCK_MIME) || event.dataTransfer.getData("text/plain");
    if (value === "multisig" || value === "time-delay" || value.startsWith("key:")) addDraftBlock(value as DraftBlockToken);
  }

  function clearDraft() {
    setSelectedKeyIds([]);
    setMultisig(false);
    setThreshold(1);
    setTimeDelay(false);
    setUnlockDate(defaultPathDate());
    setDropActive(false);
  }

  function addPath() {
    if (draftMessage) return;
    const candidate: LocalPath = {
      id: `local-path-${nextPathId.current}`,
      keyRowIds: [...selectedKeyIds],
      threshold: selectedKeyIds.length === 1 ? 1 : threshold,
      unlockDate: timeDelay ? unlockDate : null,
    };
    const trial = compilePaths(rows, [...paths, candidate], network);
    if (!trial.compiled) {
      setFeedback(trial.message ?? "This path is outside the guarded Miniscript shape.");
      return;
    }
    nextPathId.current += 1;
    setPaths((current) => [...current, candidate]);
    clearDraft();
    setFeedback("Path added. Every key remains available for compatible reuse.");
  }

  function removePath(id: string) {
    setPaths((current) => current.filter((path) => path.id !== id));
    setFeedback("Path removed. The live script was rebuilt.");
  }

  function loadDemo() {
    if ((paths.length > 0 || rows.some((row) => row.publicKey.trim())) &&
      !window.confirm("Replace the current keys and paths with the guarded demo?")) return;
    const dates = futureYearDates(3);
    setRows(demoRows());
    setPaths([
      { id: "demo-path-1", keyRowIds: ["signer-0"], threshold: 1, unlockDate: null },
      { id: "demo-path-2", keyRowIds: ["signer-1", "signer-2", "signer-3"], threshold: 3, unlockDate: dates[0] },
      { id: "demo-path-3", keyRowIds: ["signer-1", "signer-2", "signer-3"], threshold: 2, unlockDate: dates[1] },
      { id: "demo-path-4", keyRowIds: ["signer-1", "signer-2", "signer-3"], threshold: 1, unlockDate: dates[2] },
    ]);
    setNetwork("regtest");
    clearDraft();
    nextSignerId.current = 4;
    nextPathId.current = 5;
    setFeedback("Demo loaded: Owner now, then 3-of-3, 2-of-3, and 1-of-3 Recovery on later dates.");
  }

  function reset() {
    if (!window.confirm("Reset Mimir and clear every key and saved path?")) return;
    setRows(initialRows());
    setPaths([]);
    setNetwork("regtest");
    clearDraft();
    setFutureMinimum(firstFuturePathDate());
    setFeedback(null);
    nextSignerId.current = 2;
    nextPathId.current = 1;
  }

  function downloadPolicy() {
    if (!live.compiled || hasDemoKey) return;
    const currentMinimum = firstFuturePathDate();
    const hasCurrentNonFutureDelay = paths.some((path) =>
      path.unlockDate !== null && path.unlockDate < currentMinimum);
    if (hasCurrentNonFutureDelay) {
      setFutureMinimum(currentMinimum);
      setFeedback("A saved Delay date is active or past. Review and rebuild that path before exporting.");
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

  const naturalPolicy = paths.length ? paths.map((path) => pathSummary(path, rowById)).join(" OR ")
    : "Add a path to define who can spend and when.";
  const draftBlockCount = selectedKeyIds.length + Number(multisig) + Number(timeDelay);

  return (
    <main className="page-shell">
      <header className="masthead">
        <div className="masthead-copy">
          <p className="wordmark">MIMIR // GUARDED 5×5</p>
          <h1>Build recovery paths. Keep the freedom.</h1>
          <p className="supporting-line">5 keys · 5 paths · guarded Miniscript · offline</p>
        </div>
        <div className="header-controls">
          <label><span>Network</span><select value={network} onChange={(event) => {
            if (isUiNetwork(event.target.value)) setNetwork(event.target.value);
          }} aria-label="Bitcoin test network"><option value="regtest">Regtest</option><option value="signet">Signet</option></select></label>
          <button className="secondary-button" type="button" onClick={loadDemo}><KeyRound size={16} aria-hidden="true" /> Load demo</button>
          <button className="secondary-button" type="button" onClick={reset}><RotateCcw size={16} aria-hidden="true" /> Reset</button>
        </div>
      </header>

      {hasDemoKey ? <div className="demo-warning" role="alert">
        <strong>DEMO KEYS — NEVER FUND THIS ADDRESS</strong>
        <span>The matching private keys are public. Address copy and policy export are blocked.</span>
      </div> : null}
      {hasNonFutureDelay ? <div className="date-review-warning" role="alert">
        <strong>REVIEW ACTIVE / PAST DELAY</strong>
        <span>The exact script remains visible, but address copy and policy export are blocked. Remove and rebuild the affected path before use.</span>
      </div> : null}

      <div className="workspace"><div className="builder">
        <section aria-labelledby="keys-heading">
          <div className="section-heading"><div><p className="section-number">01</p><h2 id="keys-heading">Keys</h2>
            <p>Enter each compressed public key once. Marks help you read the plan.</p></div>
            <span>{rows.length} / {MAX_GUARDED_KEYS}</span></div>
          <div className="signer-list">{rows.map((row, index) => {
            const state = fieldState.get(row.id);
            const usedCount = paths.filter((path) => path.keyRowIds.includes(row.id)).length;
            return <article className="signer-row" data-mark={row.mark} key={row.id}>
              <span className="row-number" aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
              <label className="label-field"><span>Label</span><input value={row.label}
                onChange={(event) => updateRow(row.id, { label: event.target.value })} placeholder="Signer name"
                autoComplete="off" maxLength={80} aria-invalid={state?.labelInvalid ?? false}
                aria-describedby={state?.labelError ? `${row.id}-label-error` : undefined} />
                {state?.labelError ? <small className={row.label.trim() ? "field-error" : "sr-only"} id={`${row.id}-label-error`}>{state.labelError}</small> : null}</label>
              <label className="key-field"><span>Compressed public key{usedCount ? ` · ${usedCount} saved ${usedCount === 1 ? "path" : "paths"}` : ""}</span>
                <input value={row.publicKey} onChange={(event) => updateRow(row.id, { publicKey: event.target.value })}
                  placeholder="02 or 03 + 64 hex characters" autoComplete="off" autoCapitalize="none" spellCheck={false}
                  inputMode="text" aria-invalid={state?.publicKeyInvalid ?? false}
                  aria-describedby={state?.publicKeyError ? `${row.id}-key-error` : undefined} />
                {state?.publicKeyError ? <small className={row.publicKey.trim() ? "field-error" : "sr-only"} id={`${row.id}-key-error`}>{state.publicKeyError}</small> : null}</label>
              <fieldset className="mark-toggle"><legend>Visual mark</legend><div>
                <button type="button" className={row.mark === "owner" ? "is-active" : ""}
                  onClick={() => updateRow(row.id, { mark: "owner" })} aria-pressed={row.mark === "owner"}
                  aria-label={`Visually mark ${row.label.trim() || `key ${index + 1}`} as Owner`}>Owner</button>
                <button type="button" className={row.mark === "recovery" ? "is-active" : ""}
                  onClick={() => updateRow(row.id, { mark: "recovery" })} aria-pressed={row.mark === "recovery"}
                  aria-label={`Visually mark ${row.label.trim() || `key ${index + 1}`} as Recovery`}>Recovery</button>
              </div></fieldset>
              <button className="remove-button" type="button" onClick={() => removeKey(row.id)} aria-disabled={usedByPath.has(row.id)}
                aria-label={`Remove ${row.label.trim() || `key ${index + 1}`}`}><Trash2 size={17} aria-hidden="true" /></button>
            </article>;
          })}</div>
          <button className="add-key-button" type="button" onClick={addKey} disabled={rows.length >= MAX_GUARDED_KEYS}>
            <Plus size={17} aria-hidden="true" /> Add key</button>
          <p className="role-safety"><strong>Owner / Recovery marks are visual only.</strong> Only the blocks in each saved path define spending.</p>
        </section>

        <section className="new-path" aria-labelledby="new-path-heading">
          <div className="section-heading compact"><div><p className="section-number">02</p><h2 id="new-path-heading">New path</h2>
            <p>Build one path, add it, then build the next.</p></div><span>{paths.length} / {MAX_GUARDED_RULES}</span></div>
          <section className="path-palette" aria-labelledby="palette-heading">
            <header className="palette-heading"><div><span id="palette-heading">PATH BLOCKS</span><small>Drag to the canvas, or click / tap a block.</small></div>
              <span>KEYS · MULTISIG · DELAY</span></header>
            <div className="palette-items">{rows.map((row) => {
              const state = fieldState.get(row.id);
              const selected = selectedKeyIds.includes(row.id);
              const invalid = !state || state.labelInvalid || state.publicKeyInvalid;
              const saved = usedByPath.has(row.id);
              const unavailable = selected || invalid;
              const label = row.label.trim() || "Unnamed key";
              return <button className={`palette-block palette-key${selected ? " is-in-draft" : ""}`}
                data-mark={row.mark} type="button" draggable={!unavailable} disabled={unavailable}
                onDragStart={(event) => startPaletteDrag(event, `key:${row.id}`)} onDragEnd={() => setDropActive(false)}
                onClick={() => addDraftBlock(`key:${row.id}`)} aria-label={`Add ${label} key block to this path`} key={row.id}>
                <GripVertical size={15} aria-hidden="true" /><KeyRound size={17} aria-hidden="true" />
                <span><strong>{label}</strong><small>{selected ? "Already in draft" : invalid ? "Complete key first" : saved ? "Reusable · exact set only" : `${row.mark} mark`}</small></span>
              </button>;
            })}
              <button className={`palette-block palette-tool${multisig ? " is-in-draft" : ""}`} type="button"
                draggable={!multisig} disabled={multisig} onDragStart={(event) => startPaletteDrag(event, "multisig")}
                onDragEnd={() => setDropActive(false)} onClick={() => addDraftBlock("multisig")}
                aria-label="Add one Multisig block to this path"><GripVertical size={15} aria-hidden="true" />
                <UsersRound size={18} aria-hidden="true" /><span><strong>MULTISIG</strong><small>{multisig ? "Already in draft" : "Choose K of N"}</small></span></button>
              <button className={`palette-block palette-tool${timeDelay ? " is-in-draft" : ""}`} type="button"
                draggable={!timeDelay} disabled={timeDelay} onDragStart={(event) => startPaletteDrag(event, "time-delay")}
                onDragEnd={() => setDropActive(false)} onClick={() => addDraftBlock("time-delay")}
                aria-label="Add one Delay block to this path"><GripVertical size={15} aria-hidden="true" />
                <Clock3 size={18} aria-hidden="true" /><span><strong>DELAY</strong><small>{timeDelay ? "Already in draft" : "Absolute UTC date"}</small></span></button>
            </div>
          </section>

          <section className={`path-canvas${dropActive ? " is-drop-active" : ""}`}
            aria-labelledby="canvas-heading"
            onDragEnter={(event) => { event.preventDefault(); setDropActive(true); }}
            onDragOver={(event) => { event.preventDefault(); event.dataTransfer.dropEffect = "copy"; setDropActive(true); }}
            onDragLeave={(event) => {
              if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDropActive(false);
            }} onDrop={dropPaletteBlock}>
            <header className="canvas-heading"><div><span id="canvas-heading">PATH CANVAS</span><small>One complete way to spend.</small></div>
              <span>{draftBlockCount === 0 ? "EMPTY" : `${draftBlockCount} BLOCKS`}</span></header>
            <div className="canvas-body">{draftBlockCount === 0 ? (
              <div className="canvas-empty"><Plus size={22} aria-hidden="true" /><strong>DROP BLOCKS HERE</strong>
                <small>Start with a key. Add Multisig for several keys and Delay only when needed.</small></div>
            ) : <div className="path-flow"><div className="signing-slot">
              {multisig ? <article className="canvas-block canvas-multisig">
                <header><span><UsersRound size={18} aria-hidden="true" /><strong>MULTISIG</strong></span>
                  <button className="block-remove" type="button" onClick={() => {
                    setMultisig(false); setThreshold(1); setFeedback("Multisig returned to the palette.");
                  }} aria-label="Remove Multisig block"><X size={16} aria-hidden="true" /></button></header>
                <div className="multisig-config"><label><span>Signatures required</span>
                  <select value={threshold} onChange={(event) => setThreshold(Number(event.target.value))}
                    disabled={selectedKeyIds.length === 0}>{Array.from({ length: Math.max(1, selectedKeyIds.length) }, (_, index) =>
                      <option value={index + 1} key={index + 1}>{index + 1}</option>)}</select></label>
                  <span className="multisig-count">OF <strong>{selectedKeyIds.length}</strong> KEYS</span></div>
                <div className="canvas-signers">{selectedKeyIds.length === 0 ? <p>Add at least two key blocks.</p>
                  : selectedKeyIds.map((id) => {
                    const row = rowById.get(id);
                    return <div className="canvas-signer" data-mark={row?.mark} key={id}>
                      <span className="role-mark">{row?.mark ?? "key"}</span><strong>{row?.label.trim() || "Unnamed key"}</strong>
                      <code>{shortKey(row?.publicKey ?? "")}</code><button type="button" onClick={() => removeDraftKey(id)}
                        aria-label={`Remove ${row?.label.trim() || "key"} from draft path`}><X size={14} aria-hidden="true" /></button>
                    </div>;
                  })}</div>
              </article> : selectedKeyIds.map((id) => {
                const row = rowById.get(id);
                return <article className="canvas-block canvas-key" data-mark={row?.mark} key={id}>
                  <header><span><KeyRound size={17} aria-hidden="true" /><span className="role-mark">{row?.mark ?? "key"}</span></span>
                    <button className="block-remove" type="button" onClick={() => removeDraftKey(id)}
                      aria-label={`Remove ${row?.label.trim() || "key"} from draft path`}><X size={16} aria-hidden="true" /></button></header>
                  <strong>{row?.label.trim() || "Unnamed key"}</strong><code>{shortKey(row?.publicKey ?? "")}</code>
                </article>;
              })}
              {!multisig && selectedKeyIds.length > 1 ? <p className="canvas-warning">Add Multisig to combine these keys.</p> : null}
            </div>
              {timeDelay && (multisig || selectedKeyIds.length > 0) ? <span className="canvas-connector" aria-hidden="true">AND</span> : null}
              {timeDelay ? <article className="canvas-block canvas-delay">
                <header><span><Clock3 size={18} aria-hidden="true" /><strong>DELAY</strong></span>
                  <button className="block-remove" type="button" onClick={() => {
                    setTimeDelay(false); setFeedback("Delay returned to the palette.");
                  }} aria-label="Remove Delay block"><X size={16} aria-hidden="true" /></button></header>
                <label className="canvas-date-field"><span>CLTV date · 00:00 UTC</span>
                  <input type="date" value={unlockDate} min={futureMinimum} max="2038-01-19"
                    onChange={(event) => setUnlockDate(event.target.value)} />
                  <small>Absolute date, not time since funding. MTP can make confirmation later.</small></label>
              </article> : null}
            </div>}</div>
          </section>

          <div className={`compatibility-note${compatibility.error ? " is-error" : ""}`} role="status" aria-live="polite">
            <strong>{compatibility.error ? "NOT COMPATIBLE" : "COMPATIBILITY GUARD"}</strong>
            <span>{compatibility.error ?? compatibility.note ?? "Disjoint signer sets are independent. Reusing a signer requires the exact same set, a later date, and a lower K."}</span>
          </div>
          <div className="add-path-row"><p role="status" aria-live="polite">{draftMessage ?? "Ready to add this path."}</p>
            <button className="add-path-button" type="button" onClick={addPath} disabled={Boolean(draftMessage)}>
              <Plus size={17} aria-hidden="true" /> ADD PATH</button></div>
        </section>

        <section className="your-paths" aria-labelledby="your-paths-heading">
          <div className="section-heading compact"><div><p className="section-number">03</p><h2 id="your-paths-heading">Your paths</h2>
            <p>Any one complete path can unlock the Bitcoin.</p></div><span>{paths.length} / {MAX_GUARDED_RULES}</span></div>
          {paths.length === 0 ? <p className="empty-paths">No saved paths yet.</p> : <ol className="path-list">{paths.map((path, index) => <li key={path.id}>
            <span className="path-index">PATH {String(index + 1).padStart(2, "0")}</span><p>{pathSummary(path, rowById)}</p>
            <div className="path-members" aria-label="Keys in this saved path">{path.keyRowIds.map((id) => {
              const row = rowById.get(id);
              return <span key={id}><small>{row?.mark ?? "key"}</small>{row?.label.trim() || "Unnamed"}</span>;
            })}</div>
            <button type="button" onClick={() => removePath(path.id)} aria-label={`Remove path: ${pathSummary(path, rowById)}`}>
              <Trash2 size={16} aria-hidden="true" /></button>
          </li>)}</ol>}
        </section>
        {feedback ? <p className="feedback" role="status" aria-live="polite">{feedback}</p> : null}
      </div>

        <aside className="script-pane" aria-labelledby="script-heading">
          <header><div><p>Live output</p><h2 id="script-heading">LIVE BITCOIN SCRIPT</h2></div>
            <span>{hasDemoKey && hasNonFutureDelay && live.compiled ? "DEMO · REVIEW" : hasDemoKey && live.compiled ? "DEMO · DO NOT FUND" : hasNonFutureDelay && live.compiled ? "REVIEW DATE" : live.compiled ? "VALID" : paths.length ? "CHECK PATHS" : "EMPTY"}</span></header>
          <section className="live-section policy-summary"><h3>Policy</h3><p>{naturalPolicy}</p>
            {hasNonFutureDelay ? <p className="live-error" role="alert">A saved Delay date is active or past. The output below is exact, but address copy and export stay blocked until the path is reviewed.</p> : null}
            {live.message ? <p className="live-error" role="status" aria-live="polite">{live.message}</p> : null}</section>
          <section className={`live-section${live.compiled ? "" : " is-empty"}`}>
            <div className="live-label"><h3>Miniscript</h3>{live.compiled ? <CopyButton key={live.compiled.miniscript}
              value={live.compiled.miniscript} label="Miniscript" /> : null}</div>
            <code>{live.compiled?.miniscript ?? (paths.length ? "waiting for valid saved paths" : "No paths yet")}</code>
          </section>
          <section className={`live-section${live.compiled ? "" : " is-empty"}`}>
            <div className="live-label"><h3>Bitcoin Script (ASM)</h3>{live.compiled ? <CopyButton key={live.compiled.asm}
              value={live.compiled.asm} label="Bitcoin Script ASM" /> : null}</div>
            <code>{live.compiled?.asm ?? (paths.length ? "waiting for valid saved paths" : "No paths yet")}</code>
          </section>
          {live.compiled ? <section className="address-block"><div><span>{network} P2WSH address</span>
            {addressAndExportBlocked ? <span className="copy-blocked">{hasDemoKey ? "DO NOT COPY" : "REVIEW DATE"}</span> : <CopyButton key={live.compiled.address}
              value={live.compiled.address} label="P2WSH address" />}</div><code>{live.compiled.address}</code></section> : null}
          <details className="technical-details"><summary>Technical details</summary>
            {live.compiled ? <div className="technical-content">
              <TechnicalItem label="Checksummed descriptor" value={live.compiled.descriptor} />
              <TechnicalItem label="Witness script · hex" value={live.compiled.witness_script_hex} />
              <TechnicalItem label="scriptPubKey · hex" value={live.compiled.script_pubkey_hex} />
              <TechnicalItem label="Canonical manifest · SHA256" value={live.compiled.policy_manifest_sha256} />
              <div className="checks-summary"><span>Internal checks</span><p>{live.compiled.invariants.filter((item) => item.ok).length} of {live.compiled.invariants.length} passed.</p></div>
              <div className="warnings"><span>Before funding</span><ul>{live.compiled.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></div>
              <button className="download-button" type="button" onClick={downloadPolicy} disabled={addressAndExportBlocked}>
                <Download size={16} aria-hidden="true" /> Export policy JSON</button>
              {hasDemoKey ? <small className="export-note">Replace every demo key before export.</small>
                : hasNonFutureDelay ? <small className="export-note">Review and rebuild the active or past Delay path before export.</small> : null}
            </div> : <p className="technical-waiting">Descriptor, script hex, checks, warnings, and JSON appear after valid saved paths compile.</p>}
          </details>
        </aside>
      </div>

      <footer className="site-footer">
        <div><strong>PREVIEW SOFTWARE</strong><p>Rehearse on Regtest or Signet. Independently verify the script, address, backups, and signing flow before funding.</p></div>
        <div><strong>CLTV / MTP</strong><p>Delay is an absolute UTC locktime floor, not time since funding. The spending transaction needs a non-final input sequence; miners compare time locks with the previous block median time past, so confirmation can be later.</p></div>
        <div><strong>NO PRIVATE KEYS</strong><p>Mimir accepts compressed public keys only. Private keys never belong in this page.</p></div>
      </footer>
    </main>
  );
}
