"use client";

import { useEffect, useMemo, useRef, useState } from "react";
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
type CheckState = "ok" | "fail" | "pending";
type CheckRow = { name: string; state: CheckState; value: string };
type DisplayPath = { path: LocalPath; glyph: string | null; ladder: { stage: number; size: number } | null; sameSet: boolean };

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
    { id: "signer-0", label: "owner", publicKey: "", mark: "owner" },
    { id: "signer-1", label: "recovery", publicKey: "", mark: "recovery" },
  ];
}

function demoRows(): SignerRow[] {
  return [
    { id: "signer-0", label: "owner", publicKey: DEMO_PUBLIC_KEYS[0], mark: "owner" },
    { id: "signer-1", label: "recovery-a", publicKey: DEMO_PUBLIC_KEYS[1], mark: "recovery" },
    { id: "signer-2", label: "recovery-b", publicKey: DEMO_PUBLIC_KEYS[2], mark: "recovery" },
    { id: "signer-3", label: "recovery-c", publicKey: DEMO_PUBLIC_KEYS[3], mark: "recovery" },
  ];
}

function isUiNetwork(value: string): value is UiNetwork {
  return value === "regtest" || value === "signet";
}

function shortKey(value: string): string {
  const normalized = value.trim();
  return normalized.length < 14 ? normalized : `${normalized.slice(0, 6)}…${normalized.slice(-4)}`;
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
  return `${Number(day)} ${months[Number(month) - 1]} ${year}, 00:00 UTC`;
}

function normalizedThreshold(value: number, count: number): number {
  return Math.min(Math.max(1, value), Math.max(1, count));
}

function signerSetKey(ids: string[]): string {
  return [...new Set(ids)].sort().join("|");
}

function orderedPaths(paths: LocalPath[]): DisplayPath[] {
  const groups: LocalPath[][] = [];
  const groupIndex = new Map<string, number>();
  for (const path of paths) {
    const key = signerSetKey(path.keyRowIds);
    const index = groupIndex.get(key);
    if (index === undefined) {
      groupIndex.set(key, groups.length);
      groups.push([path]);
    } else groups[index].push(path);
  }
  return groups.flatMap((group) => group.map((path, stage) => ({
    path,
    glyph: group.length === 1 ? null : stage === 0 ? "┌" : stage === group.length - 1 ? "└" : "├",
    ladder: group.length === 1 ? null : { stage: stage + 1, size: group.length },
    sameSet: group.length > 1 && stage > 0,
  })));
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
    const labelError = !label ? "enter a signer label."
      : label.length > 80 ? "use at most 80 characters."
        : /\p{Cc}/u.test(label) ? "remove control characters from this label."
          : (labelCounts.get(label.toLocaleLowerCase("en-US")) ?? 0) > 1 ? "use a unique signer label." : null;
    const publicKeyError = !publicKey
      ? row.publicKey.trim() ? "use a valid 66-character compressed key starting with 02 or 03." : "enter a compressed public key."
      : (publicKeyCounts.get(publicKey) ?? 0) > 1 ? "this public key is already listed." : null;
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
      if (!row) throw new Error("a saved path references a removed key.");
      const label = row.label.trim().normalize("NFC");
      if (!label) throw new Error("name every key used by a saved path.");
      return { row, label, publicKey: validateGuardedRulePublicKey(row.publicKey) };
    });
    if (new Set(usedRows.map((entry) => entry.label.toLocaleLowerCase("en-US"))).size !== usedRows.length) {
      throw new Error("use a unique label for every key in the saved paths.");
    }
    if (new Set(usedRows.map((entry) => entry.publicKey)).size !== usedRows.length) {
      throw new Error("use each public key only once in the keyring.");
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
          if (!requestId) throw new Error("a saved path contains an unknown key.");
          return requestId;
        }),
        threshold: path.threshold,
        unlock_unix: path.unlockDate ? unixFromGuardedRuleDate(path.unlockDate) : null,
      })),
    };
    return { compiled: compileGuardedRulePolicy(request), message: null };
  } catch (error) {
    return { compiled: null, message: error instanceof Error ? error.message : "the saved paths could not be compiled." };
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
    <button className="copy-button" type="button" onClick={copy} aria-label={`copy ${label}`}>
      [{state === "copied" ? "copied" : state === "failed" ? "failed" : "copy"}]
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
  const [rows, setRows] = useState<SignerRow[]>(initialRows);
  const [paths, setPaths] = useState<LocalPath[]>([]);
  const [network, setNetwork] = useState<UiNetwork>("regtest");
  const [selectedKeyIds, setSelectedKeyIds] = useState<string[]>([]);
  const [threshold, setThreshold] = useState(1);
  const [lockEnabled, setLockEnabled] = useState(false);
  const [unlockDate, setUnlockDate] = useState(defaultPathDate);
  const [futureMinimum, setFutureMinimum] = useState(firstFuturePathDate);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [armed, setArmed] = useState<"demo" | "reset" | null>(null);
  const nextSignerId = useRef(2);
  const nextPathId = useRef(1);
  const armTimer = useRef<number | null>(null);
  const checklistRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const refresh = () => setFutureMinimum(firstFuturePathDate());
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
  const keyIdByRowId = useMemo(() => new Map(rows.map((row, index) => [row.id, `k${index + 1}`])), [rows]);
  const fieldState = useMemo(() => validateRows(rows), [rows]);
  const live = useMemo(() => compilePaths(rows, paths, network), [rows, paths, network]);
  const display = useMemo(() => orderedPaths(paths), [paths]);
  const usedByPath = useMemo(() => new Set(paths.flatMap((path) => path.keyRowIds)), [paths]);
  const hasDemoKey = useMemo(() => rows.some((row) =>
    DEMO_PUBLIC_KEYS.some((key) => key === row.publicKey.trim().toLowerCase())), [rows]);
  const hasNonFutureDelay = useMemo(() => paths.some((path) =>
    path.unlockDate !== null && path.unlockDate < futureMinimum), [paths, futureMinimum]);
  const addressAndExportBlocked = hasDemoKey || hasNonFutureDelay;

  const selectedCount = selectedKeyIds.length;
  const effectiveThreshold = selectedCount === 1 ? 1 : threshold;

  function formatSet(ids: string[]): string {
    const names = ids.map((id) => keyIdByRowId.get(id) ?? "k?")
      .sort((left, right) => Number(left.slice(1)) - Number(right.slice(1)));
    return `{${names.join(",")}}`;
  }

  function displayIdOf(list: LocalPath[], pathId: string): string {
    const index = orderedPaths(list).findIndex((entry) => entry.path.id === pathId);
    return `p${index + 1}`;
  }

  const guard = (() => {
    if (selectedCount === 0) return { ok: null as boolean | null, line: null as string | null };
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
        return {
          ok: false,
          line: `GUARD ▸ FAIL — ${formatSet(overlap)} partially overlaps saved set ${formatSet(savedIds)}. reuse all ${savedIds.length} keys or choose a disjoint set.`,
        };
      }
    }
    const matching = savedSets.get(draftSetKey) ?? [];
    if (matching.length === 0) return { ok: true, line: "GUARD ▸ OK — new signer set. compiles as an independent branch." };
    const last = matching[matching.length - 1];
    if (last.threshold <= 1) return { ok: false, line: "GUARD ▸ FAIL — this set already reached 1-of-n. its threshold cannot decrease again." };
    if (effectiveThreshold >= last.threshold) return {
      ok: false, line: `GUARD ▸ FAIL — reuse needs a lower k than the previous ${last.threshold}-of-${last.keyRowIds.length} path.`,
    };
    if (!lockEnabled) return {
      ok: false,
      line: last.unlockDate
        ? `GUARD ▸ FAIL — reuse needs a date lock set after ${readableDate(last.unlockDate)}.`
        : "GUARD ▸ FAIL — reuse needs a future date lock so this stage comes later.",
    };
    if (last.unlockDate && unlockDate <= last.unlockDate) return {
      ok: false, line: `GUARD ▸ FAIL — reuse needs a date lock set after ${readableDate(last.unlockDate)}.`,
    };
    return { ok: true, line: `GUARD ▸ OK — exact-set ladder reuse: ${formatSet(selectedKeyIds)} returns later with ${effectiveThreshold}-of-${selectedCount}.` };
  })();

  const limitReached = paths.length >= MAX_GUARDED_RULES;
  const completeSelected = selectedKeyIds.filter((id) => {
    const state = fieldState.get(id);
    return state && !state.labelInvalid && !state.publicKeyInvalid;
  }).length;
  const timelock = (() => {
    if (!lockEnabled) return { ok: true, value: "not set (spend immediately)" };
    try { unixFromGuardedRuleDate(unlockDate); }
    catch { return { ok: false, value: "invalid date" }; }
    if (unlockDate < futureMinimum) return { ok: false, value: `${unlockDate} (not future)` };
    return { ok: true, value: `${unlockDate} (future)` };
  })();

  const checkRows: CheckRow[] = [
    selectedCount > 0
      ? { name: "signers", state: "ok", value: `${selectedCount} selected` }
      : { name: "signers", state: "pending", value: "none selected" },
    selectedCount === 0
      ? { name: "keys complete", state: "pending", value: "awaiting signers" }
      : { name: "keys complete", state: completeSelected === selectedCount ? "ok" : "fail", value: `${completeSelected}/${selectedCount}` },
    selectedCount === 0
      ? { name: "threshold", state: "pending", value: "awaiting signers" }
      : { name: "threshold", state: "ok", value: selectedCount === 1 ? "1 of 1 (single key)" : `${threshold} of ${selectedCount}` },
    { name: "timelock", state: timelock.ok ? "ok" : "fail", value: timelock.value },
    limitReached
      ? { name: "guard", state: "fail", value: "FAIL" }
      : guard.ok === null
        ? { name: "guard", state: "pending", value: "awaiting signers" }
        : { name: "guard", state: guard.ok ? "ok" : "fail", value: guard.ok ? "OK" : "FAIL" },
  ];
  const guardLine = limitReached ? "GUARD ▸ FAIL — five saved paths is the limit." : guard.line;

  const draftBlocked = limitReached ? "five saved paths is the limit."
    : selectedCount === 0 ? "select at least one signer."
      : completeSelected < selectedCount ? "complete every selected key first."
        : effectiveThreshold < 1 || effectiveThreshold > selectedCount ? "choose a valid k-of-n threshold."
          : !timelock.ok ? "set a future utc date or disable the lock."
            : guard.ok === false ? "resolve the guard failure." : null;

  function updateRow(id: string, patch: Partial<Omit<SignerRow, "id">>) {
    setRows((current) => current.map((row) => row.id === id ? { ...row, ...patch } : row));
    setFeedback(null);
  }

  function addKey() {
    if (rows.length >= MAX_GUARDED_KEYS) return;
    const id = `signer-${nextSignerId.current}`;
    nextSignerId.current += 1;
    setRows((current) => [...current, { id, label: "", publicKey: "", mark: "recovery" }]);
    setFeedback(`k${rows.length + 1} registered.`);
  }

  function removeKey(id: string) {
    if (usedByPath.has(id)) {
      const holders = display.filter((entry) => entry.path.keyRowIds.includes(id))
        .map((entry) => displayIdOf(paths, entry.path.id));
      setFeedback(`! locked: remove ${holders.join(", ")} first.`);
      return;
    }
    const keyId = keyIdByRowId.get(id) ?? "key";
    setRows((current) => current.filter((entry) => entry.id !== id));
    const nextSelection = selectedKeyIds.filter((keyRowId) => keyRowId !== id);
    setSelectedKeyIds(nextSelection);
    setThreshold((value) => normalizedThreshold(value, nextSelection.length));
    setFeedback(`${keyId} removed.`);
  }

  function toggleDraftKey(id: string) {
    if (selectedKeyIds.includes(id)) {
      const nextSelection = selectedKeyIds.filter((keyId) => keyId !== id);
      setSelectedKeyIds(nextSelection);
      setThreshold((value) => normalizedThreshold(value, nextSelection.length));
      return;
    }
    const state = fieldState.get(id);
    if (!state || state.labelInvalid || state.publicKeyInvalid) return;
    const related = paths.find((path) => path.keyRowIds.includes(id));
    const additions = related ? related.keyRowIds : [id];
    const nextSelection = [...selectedKeyIds];
    for (const addition of additions) if (!nextSelection.includes(addition)) nextSelection.push(addition);
    setSelectedKeyIds(nextSelection);
    setThreshold((value) => normalizedThreshold(value, nextSelection.length));
    if (related && additions.length > 1) {
      setFeedback(`note: ${keyIdByRowId.get(id)} is bound to saved set ${formatSet(related.keyRowIds)} — full set selected for a ladder stage.`);
    }
  }

  function clearDraft() {
    setSelectedKeyIds([]);
    setThreshold(1);
    setLockEnabled(false);
    setUnlockDate(defaultPathDate());
  }

  function addPath() {
    if (draftBlocked) return;
    const candidate: LocalPath = {
      id: `local-path-${nextPathId.current}`,
      keyRowIds: [...selectedKeyIds],
      threshold: effectiveThreshold,
      unlockDate: lockEnabled ? unlockDate : null,
    };
    const trial = compilePaths(rows, [...paths, candidate], network);
    if (!trial.compiled) {
      setFeedback(`! err: ${lowerFirst(trial.message ?? "this path is outside the guarded miniscript shape.")}`);
      return;
    }
    nextPathId.current += 1;
    setPaths((current) => [...current, candidate]);
    clearDraft();
    setFeedback(`${displayIdOf([...paths, candidate], candidate.id)} saved. keys remain reusable under the guard.`);
    checklistRef.current?.querySelector<HTMLInputElement>("input:not(:disabled)")?.focus();
  }

  function removePath(id: string) {
    const displayId = displayIdOf(paths, id);
    setPaths((current) => current.filter((path) => path.id !== id));
    setFeedback(`${displayId} removed — script rebuilt.`);
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
    setFeedback("demo loaded: owner now, then 3-of-3, 2-of-3, and 1-of-3 recovery on later dates.");
  }

  function requestDemo() {
    if (paths.length === 0 && rows.every((row) => !row.publicKey.trim())) {
      loadDemo();
      return;
    }
    arm("demo");
  }

  function reset() {
    setRows(initialRows());
    setPaths([]);
    setNetwork("regtest");
    clearDraft();
    setFutureMinimum(firstFuturePathDate());
    nextSignerId.current = 2;
    nextPathId.current = 1;
    setFeedback("session reset. nothing was ever saved anywhere.");
  }

  function downloadPolicy() {
    if (!live.compiled || hasDemoKey) return;
    const currentMinimum = firstFuturePathDate();
    const hasCurrentNonFutureDelay = paths.some((path) =>
      path.unlockDate !== null && path.unlockDate < currentMinimum);
    if (hasCurrentNonFutureDelay) {
      setFutureMinimum(currentMinimum);
      setFeedback("! export BLOCKED — a saved lock date is active or past. rebuild that path first.");
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

  function stdinSummary(entry: DisplayPath): string {
    const { path } = entry;
    const timing = path.unlockDate ? `from ${path.unlockDate} 00:00 UTC` : "spends immediately";
    if (path.keyRowIds.length === 1) {
      const id = path.keyRowIds[0];
      const label = rowById.get(id)?.label.trim() || "unnamed key";
      return `${keyIdByRowId.get(id) ?? "k?"} ${label} · ${timing}`;
    }
    const set = entry.sameSet ? "same set" : formatSet(path.keyRowIds);
    return `${path.threshold}-of-${path.keyRowIds.length} ${set} · ${timing}`;
  }

  function stdoutSummary(entry: DisplayPath): string {
    const { path } = entry;
    const names = path.keyRowIds.map((id) => rowById.get(id)?.label.trim() || "unnamed key");
    const timing = path.unlockDate ? `from ${readableDate(path.unlockDate)}` : "immediately";
    if (names.length === 1) return `${names[0]} spends ${timing}.`;
    return `${path.threshold}-of-${names.length} {${names.join(", ")}} spends ${timing}.`;
  }

  const checkGlyph: Record<CheckState, string> = { ok: "[x]", fail: "[!]", pending: "[ ]" };
  const checkSpoken: Record<CheckState, string> = { ok: "passed:", fail: "failing:", pending: "pending:" };
  const stdoutState = live.compiled
    ? hasDemoKey && hasNonFutureDelay ? "DO-NOT-FUND · REVIEW DATE"
      : hasDemoKey ? "DO-NOT-FUND"
        : hasNonFutureDelay ? "REVIEW DATE" : "VALID"
    : paths.length ? "CHECK PATHS" : "EMPTY";
  const stateTone = live.compiled
    ? addressAndExportBlocked ? "amber" : "green"
    : paths.length ? "red" : "dim";

  return (
    <main className="shell">
      <header className="statusbar">
        <h1 className="wordmark">mimir v5 <span className="cursor" aria-hidden="true">▮</span></h1>
        <p className="tagline">guarded p2wsh · 5 keys · 5 paths · offline</p>
        <div className="session-controls">
          <label className="net-field"><span>net</span>
            <select value={network} aria-label="bitcoin test network" onChange={(event) => {
              if (isUiNetwork(event.target.value)) setNetwork(event.target.value);
            }}><option value="regtest">regtest</option><option value="signet">signet</option></select>
          </label>
          <button className="session-button" type="button" onClick={requestDemo} onBlur={() => setArmed(null)}>
            {armed === "demo" ? "[really load? overwrites]" : "[load demo]"}
          </button>
          <button className="session-button" type="button" onClick={() => arm("reset")} onBlur={() => setArmed(null)}>
            {armed === "reset" ? "[really reset?]" : "[reset]"}
          </button>
        </div>
      </header>

      {hasDemoKey ? <div className="alert alert-demo" role="alert">
        <strong><span aria-hidden="true">▲ </span>DEMO KEYS — DO NOT FUND.</strong>
        <span>these private keys are public knowledge. address copy and export stay blocked until every demo key is replaced.</span>
      </div> : null}
      {hasNonFutureDelay ? <div className="alert alert-review" role="alert">
        <strong><span aria-hidden="true">▲ </span>REVIEW</strong>
        <span>a saved lock date is active or past. the script stays visible; address copy and export are blocked until the path is rebuilt.</span>
      </div> : null}

      <div className="workspace">
        <div className="stdin">
          <section className="frame" aria-labelledby="keyring-heading">
            <header className="frame-heading"><h2 id="keyring-heading">[1] KEYRING</h2><span className="counter">{rows.length}/{MAX_GUARDED_KEYS}</span></header>
            <div className="keyring">{rows.map((row, index) => {
              const state = fieldState.get(row.id);
              const inUseCount = paths.filter((path) => path.keyRowIds.includes(row.id)).length;
              const locked = usedByPath.has(row.id);
              return <article className="key-row" key={row.id}>
                <span className="key-index" aria-hidden="true">k{index + 1}</span>
                <label className="field label-field"><span>label</span>
                  <input value={row.label} onChange={(event) => updateRow(row.id, { label: event.target.value })}
                    placeholder="signer name" autoComplete="off" maxLength={80}
                    aria-invalid={state?.labelInvalid ?? false}
                    aria-describedby={state?.labelError ? `${row.id}-label-error` : undefined} />
                  {state?.labelError ? <small className={row.label.trim() ? "field-error" : "sr-only"} id={`${row.id}-label-error`}>! err: {state.labelError}</small> : null}
                </label>
                <label className="field key-field"><span>public key{inUseCount ? <em className="in-use"> · in use ×{inUseCount}</em> : null}</span>
                  <input value={row.publicKey} onChange={(event) => updateRow(row.id, { publicKey: event.target.value })}
                    placeholder="02… or 03… + 64 hex" autoComplete="off" autoCapitalize="none" spellCheck={false}
                    inputMode="text" aria-invalid={state?.publicKeyInvalid ?? false}
                    aria-describedby={state?.publicKeyError ? `${row.id}-key-error` : undefined} />
                  {state?.publicKeyError ? <small className={row.publicKey.trim() ? "field-error" : "sr-only"} id={`${row.id}-key-error`}>! err: {state.publicKeyError}</small> : null}
                </label>
                <fieldset className="mark-toggle"><legend>mark · visual only</legend><div>
                  <button type="button" className={row.mark === "owner" ? "is-active" : ""}
                    onClick={() => updateRow(row.id, { mark: "owner" })} aria-pressed={row.mark === "owner"}
                    aria-label={`mark ${row.label.trim() || `key ${index + 1}`} as owner (visual only)`}>owner</button>
                  <button type="button" className={row.mark === "recovery" ? "is-active" : ""}
                    onClick={() => updateRow(row.id, { mark: "recovery" })} aria-pressed={row.mark === "recovery"}
                    aria-label={`mark ${row.label.trim() || `key ${index + 1}`} as recovery (visual only)`}>recovery</button>
                </div></fieldset>
                <button className="rm-button" type="button" onClick={() => removeKey(row.id)} aria-disabled={locked}
                  aria-label={`remove ${row.label.trim() || `key ${index + 1}`}`}>[rm]</button>
              </article>;
            })}</div>
            <button className="wide-button" type="button" onClick={addKey} disabled={rows.length >= MAX_GUARDED_KEYS}>
              {rows.length >= MAX_GUARDED_KEYS ? `[ keyring full ${rows.length}/${MAX_GUARDED_KEYS} ]` : `[ + register key ${rows.length + 1}/${MAX_GUARDED_KEYS} ]`}
            </button>
            <p className="footnote">marks are visual only. saved paths alone define who can spend.</p>
          </section>

          <section className="frame" aria-labelledby="compose-heading">
            <header className="frame-heading"><h2 id="compose-heading">[2] COMPOSE PATH</h2><span className="counter">{paths.length}/{MAX_GUARDED_RULES}</span></header>
            <div className="checklist" role="group" aria-label="signers for this path" ref={checklistRef}>
              {rows.map((row, index) => {
                const state = fieldState.get(row.id);
                const invalid = !state || state.labelInvalid || state.publicKeyInvalid;
                const checked = selectedKeyIds.includes(row.id);
                const label = row.label.trim() || "unnamed key";
                return <label className={`checkrow${invalid && !checked ? " is-disabled" : ""}`} key={row.id}>
                  <input type="checkbox" className="sr-only" checked={checked} disabled={invalid && !checked}
                    onChange={() => toggleDraftKey(row.id)}
                    aria-label={`${label} signs this path`} />
                  <span className="checkmark" aria-hidden="true">{checked ? "[x]" : "[ ]"}</span>
                  <span className="check-id" aria-hidden="true">k{index + 1}</span>
                  <span className="check-label">{label}</span>
                  <code className="check-key">{invalid ? "— complete key first" : shortKey(row.publicKey)}</code>
                </label>;
              })}
            </div>
            <div className={`k-row${selectedCount < 2 ? " is-dim" : ""}`} role="group" aria-label="signatures required">
              <span className="k-label" aria-hidden="true">K =</span>
              {selectedCount === 1
                ? <span className="k-static">1 of 1 (single key)</span>
                : <>
                  {Array.from({ length: MAX_GUARDED_KEYS }, (_, index) => {
                    const value = index + 1;
                    return <button type="button" key={value} className={`k-segment${threshold === value ? " is-active" : ""}`}
                      disabled={selectedCount < 2 || value > selectedCount}
                      aria-pressed={threshold === value}
                      aria-label={`require ${value} signatures`}
                      onClick={() => setThreshold(value)}>({value})</button>;
                  })}
                  <span className="k-static">{selectedCount < 2 ? "— select 2+ keys" : `of ${selectedCount}`}</span>
                </>}
            </div>
            <label className="checkrow timelock-toggle">
              <input type="checkbox" className="sr-only" checked={lockEnabled}
                onChange={() => setLockEnabled((value) => !value)} aria-label="lock this path until a utc date" />
              <span className="checkmark" aria-hidden="true">{lockEnabled ? "[x]" : "[ ]"}</span>
              <span className="check-label">lock until date (UTC)</span>
            </label>
            {lockEnabled ? <div className="timelock-config">
              <input type="date" value={unlockDate} min={futureMinimum} max="2038-01-19"
                aria-label="unlock date, 00:00 utc" onChange={(event) => setUnlockDate(event.target.value)} />
              <small>absolute date · 00:00 UTC · CLTV — median-time-past can confirm later.</small>
            </div> : null}

            <div className="precommit" role="status" aria-live="polite">
              <p className="precommit-title">pre-commit <span aria-hidden="true">▸</span> next path</p>
              {checkRows.map((row) => <p className={`check-line is-${row.state}`} key={row.name}>
                <span className="check-glyph" aria-hidden="true">{checkGlyph[row.state]}</span>
                <span className="sr-only">{checkSpoken[row.state]}</span>
                <span className="check-name">{row.name}</span>
                <span className="leader" aria-hidden="true"></span>
                <span className="check-value">{row.value}</span>
              </p>)}
              {guardLine && (selectedCount > 0 || limitReached) ? <p className={`guard-line${guard.ok === false || limitReached ? " is-fail" : ""}`}>{guardLine}</p> : null}
            </div>
            <button className="add-path" type="button" onClick={addPath} disabled={Boolean(draftBlocked)}>[ ADD PATH ]</button>
          </section>

          <section className="frame" aria-labelledby="paths-heading">
            <header className="frame-heading"><h2 id="paths-heading">[3] PATHS</h2><span className="counter">{paths.length}/{MAX_GUARDED_RULES}</span></header>
            {paths.length === 0
              ? <p className="empty-paths">no paths. stdout is empty until the first path is saved.</p>
              : <ol className="path-list">{display.map((entry, index) => {
                const review = entry.path.unlockDate !== null && entry.path.unlockDate < futureMinimum;
                return <li key={entry.path.id}>
                  <span className="ladder-glyph" aria-hidden="true">{entry.glyph ?? " "}</span>
                  <p>
                    {entry.ladder ? <span className="sr-only">ladder group stage {entry.ladder.stage} of {entry.ladder.size}. </span> : null}
                    <span className="path-id">p{index + 1}</span>
                    <span aria-hidden="true"> ▸ </span>
                    {stdinSummary(entry)}
                    {review ? <span className="review-token"> REVIEW</span> : null}
                  </p>
                  <button className="rm-button" type="button" onClick={() => removePath(entry.path.id)}
                    aria-label={`remove p${index + 1}: ${stdoutSummary(entry)}`}>[rm]</button>
                </li>;
              })}</ol>}
          </section>

          <p className="log" role="status" aria-live="polite">{feedback ? <><span aria-hidden="true">log ▸ </span>{feedback}</> : null}</p>
        </div>

        <aside className="stdout" id="stdout" aria-labelledby="stdout-heading">
          <header className="stdout-heading">
            <h2 id="stdout-heading">STDOUT</h2>
            <span className={`state-token tone-${stateTone}`} role="status" aria-live="polite"><span aria-hidden="true">▸ </span>{stdoutState}</span>
          </header>

          <section className="out-section">
            <h3>policy</h3>
            {paths.length === 0
              ? <p className="waiting">no paths. stdout is empty until the first path is saved.</p>
              : <>
                <ol className="readout">{display.map((entry, index) => <li key={entry.path.id}>
                  <span className="path-id" aria-hidden="true">p{index + 1} ▸ </span>{stdoutSummary(entry)}
                </li>)}</ol>
                <p className="policy-close">any one satisfied path spends. there is no other door.</p>
              </>}
            {live.message ? <p className="err-line" role="status" aria-live="polite">! err: {lowerFirst(live.message)}</p> : null}
          </section>

          <section className="out-section">
            <div className="out-label"><h3>miniscript</h3>{live.compiled ? <CopyButton key={live.compiled.miniscript} value={live.compiled.miniscript} label="miniscript" /> : null}</div>
            {live.compiled ? <pre className="out-code"><code>{live.compiled.miniscript}</code></pre>
              : <p className="waiting">{paths.length ? "waiting for valid saved paths." : "—"}</p>}
          </section>

          <section className="out-section">
            <div className="out-label"><h3>script asm</h3>{live.compiled ? <CopyButton key={live.compiled.asm} value={live.compiled.asm} label="bitcoin script asm" /> : null}</div>
            {live.compiled ? <pre className="out-code"><code>{live.compiled.asm}</code></pre>
              : <p className="waiting">{paths.length ? "waiting for valid saved paths." : "—"}</p>}
          </section>

          <section className="out-section">
            <div className="out-label"><h3>address</h3>
              {live.compiled
                ? addressAndExportBlocked
                  ? <span className="blocked-token">{hasDemoKey ? "[blocked — demo]" : "[blocked — review]"}</span>
                  : <CopyButton key={live.compiled.address} value={live.compiled.address} label="p2wsh address" />
                : null}
            </div>
            {live.compiled ? <>
              <p className="address-value">{cluster4(live.compiled.address)}</p>
              <p className="caption">{network} · p2wsh · copy delivers the unspaced address</p>
            </> : <p className="waiting">—</p>}
          </section>

          <details className="details">
            <summary>details <span aria-hidden="true">▸</span> descriptor · hex · checks</summary>
            {live.compiled ? <div className="details-body">
              <TechnicalItem label="checksummed descriptor" value={live.compiled.descriptor} />
              <TechnicalItem label="witness script · hex" value={live.compiled.witness_script_hex} />
              <TechnicalItem label="scriptpubkey · hex" value={live.compiled.script_pubkey_hex} />
              <TechnicalItem label="manifest · sha-256" value={live.compiled.policy_manifest_sha256} clustered />
              <p className="checks-line">checks <span aria-hidden="true">▸</span> {live.compiled.invariants.filter((item) => item.ok).length}/{live.compiled.invariants.length} passed</p>
              <div className="warnings"><h4>before funding</h4>
                <ul>{live.compiled.warnings.map((warning) => <li key={warning}>! {lowerFirst(warning)}</li>)}</ul>
              </div>
              <button className="export-button" type="button" onClick={downloadPolicy} disabled={addressAndExportBlocked}>[ export policy.json ]</button>
              {hasDemoKey ? <p className="export-note">! export BLOCKED — replace every demo key first.</p>
                : hasNonFutureDelay ? <p className="export-note">! export BLOCKED — a saved lock date is active or past. rebuild that path first.</p> : null}
            </div> : <p className="waiting details-waiting">descriptor, script hex, checks, warnings, and json export print after valid saved paths compile.</p>}
          </details>

          <p className="stdout-foot">compile <span aria-hidden="true">▸</span> live. every change rebuilds the script. nothing leaves this page.</p>
        </aside>
      </div>

      <footer className="site-footer">
        <p><strong>preview software</strong> <span aria-hidden="true">▸</span> rehearse on regtest or signet. verify script, address, backups, and signing with independent tooling before funding.</p>
        <p><strong>cltv / mtp</strong> <span aria-hidden="true">▸</span> locks are absolute utc floors, not timers. median-time-past can confirm later; spending needs nLockTime + a non-final nSequence.</p>
        <p><strong>no private keys</strong> <span aria-hidden="true">▸</span> compressed public keys only. private keys never belong in this page.</p>
      </footer>

      <a className="stdout-rail" href="#stdout">
        <span className="rail-long">stdout </span><span aria-hidden="true">▸ </span>{stdoutState}
        {live.compiled ? <span className="rail-address"> · {live.compiled.address.slice(0, 10)}…</span> : null}
        <span className="rail-view">[view]</span>
      </a>
    </main>
  );
}
