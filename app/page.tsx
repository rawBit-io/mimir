"use client";

import {
  Check,
  Clock3,
  Clipboard,
  Download,
  KeyRound,
  Plus,
  RotateCcw,
  Trash2,
  UsersRound,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  TEMPLATE_ID_RECOVERY,
  compileRecoveryTemplate,
  unixFromRecoveryDate,
  validateRecoveryPublicKey,
  type CompiledRecoveryTemplate,
  type RecoveryNetwork,
  type RecoverySigner,
  type RecoveryTemplateRequest,
} from "../lib/recovery-template";

type UiNetwork = Exclude<RecoveryNetwork, "bitcoin">;
type SignerGroup = RecoverySigner["group"];
type SignerRow = { id: string; label: string; publicKey: string; group: SignerGroup };
type FieldState = { labelError: string | null; publicKeyError: string | null };
type DateState = { error: string | null };
type LiveResult = { compiled: CompiledRecoveryTemplate | null; message: string };

const MAX_SIGNERS = 5;
const DEMO_PUBLIC_KEYS = [
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
  "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
] as const;

function initialRows(withDemoKeys = false): SignerRow[] {
  return [
    {
      id: "signer-0",
      label: "Owner",
      publicKey: withDemoKeys ? DEMO_PUBLIC_KEYS[0] : "",
      group: "primary",
    },
    ...Array.from({ length: 4 }, (_, index) => ({
      id: `signer-${index + 1}`,
      label: `Recovery ${index + 1}`,
      publicKey: withDemoKeys ? DEMO_PUBLIC_KEYS[index + 1] : "",
      group: "recovery" as const,
    })),
  ];
}

function tomorrowDate(): string {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}

function initialRecoveryDates(): string[] {
  return Array.from({ length: 4 }, (_, index) => {
    const date = new Date();
    date.setUTCFullYear(date.getUTCFullYear() + index + 1);
    return date.toISOString().slice(0, 10);
  });
}

function readableDate(value: string): string {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return "date missing";
  const [, year, month, day] = match;
  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  return `${Number(day)} ${months[Number(month) - 1]} ${year}, 00:00 UTC`;
}

function isUiNetwork(value: string): value is UiNetwork {
  return value === "regtest" || value === "signet";
}

function validateRows(rows: SignerRow[]): Map<string, FieldState> {
  const normalizedLabels = rows.map((row) => row.label.trim().normalize("NFC"));
  const labelCounts = new Map<string, number>();
  for (const label of normalizedLabels) {
    const key = label.toLocaleLowerCase("en-US");
    labelCounts.set(key, (labelCounts.get(key) ?? 0) + 1);
  }
  const normalizedKeys = rows.map((row) => {
    try { return validateRecoveryPublicKey(row.publicKey); } catch { return null; }
  });
  const keyCounts = new Map<string, number>();
  for (const publicKey of normalizedKeys) {
    if (publicKey) keyCounts.set(publicKey, (keyCounts.get(publicKey) ?? 0) + 1);
  }

  return new Map(rows.map((row, index) => {
    const label = normalizedLabels[index];
    const publicKey = normalizedKeys[index];
    const labelError = !label
      ? "Enter a signer label."
      : label.length > 80
        ? "Use at most 80 characters."
        : /\p{Cc}/u.test(label)
          ? "Remove control characters from this label."
          : (labelCounts.get(label.toLocaleLowerCase("en-US")) ?? 0) > 1
            ? "Use a unique signer label."
            : null;
    const publicKeyError = !publicKey
      ? row.publicKey.trim()
        ? "Use a 66-character compressed key beginning with 02 or 03."
        : "Enter a compressed public key."
      : (keyCounts.get(publicKey) ?? 0) > 1
        ? "This public key is already listed."
        : null;
    return [row.id, { labelError, publicKeyError }];
  }));
}

function validateDates(
  values: string[],
  count: number,
  futureMinimum = tomorrowDate(),
): DateState[] {
  return values.slice(0, count).map((value, index) => {
    let error: string | null = null;
    try { unixFromRecoveryDate(value); } catch (caught) {
      error = caught instanceof Error ? caught.message : "Choose a valid calendar date.";
    }
    if (!error && value < futureMinimum) error = "Choose a future calendar date.";
    if (!error && index > 0 && value <= values[index - 1]) {
      error = "This date must be later than the previous stage.";
    }
    return { error };
  });
}

function compileLive(
  rows: SignerRow[],
  primaryThreshold: number,
  recoveryDates: string[],
  network: UiNetwork,
  fields: Map<string, FieldState>,
  dates: DateState[],
): LiveResult {
  const primaryCount = rows.filter((row) => row.group === "primary").length;
  const recoveryCount = rows.filter((row) => row.group === "recovery").length;
  if (rows.some((row) => fields.get(row.id)?.labelError || fields.get(row.id)?.publicKeyError)) {
    const emptyKeys = rows.filter((row) => !row.publicKey.trim()).length;
    return {
      compiled: null,
      message: emptyKeys
        ? `Enter ${emptyKeys} remaining public ${emptyKeys === 1 ? "key" : "keys"} to compile.`
        : "Fix the signer fields to compile a fresh script.",
    };
  }
  if (primaryCount < 1 || recoveryCount < 1) {
    return { compiled: null, message: "Keep at least one Primary and one Recovery signer." };
  }
  if (primaryThreshold < 1 || primaryThreshold > primaryCount) {
    return { compiled: null, message: "Choose a valid Primary signature threshold." };
  }
  if (dates.some((date) => date.error)) {
    return { compiled: null, message: "Fix the Recovery stage dates to compile a fresh script." };
  }
  try {
    const request: RecoveryTemplateRequest = {
      format: "mimir-recovery-request",
      version: 4,
      network,
      template_id: TEMPLATE_ID_RECOVERY,
      signers: rows.map((row) => ({
        id: row.id,
        label: row.label.trim().normalize("NFC"),
        public_key: validateRecoveryPublicKey(row.publicKey),
        group: row.group,
      })),
      primary_threshold: primaryThreshold,
      recovery_dates: recoveryDates.slice(0, recoveryCount).map(unixFromRecoveryDate),
    };
    return {
      compiled: compileRecoveryTemplate(request),
      message: "Compiled locally from this fixed template.",
    };
  } catch (error) {
    return {
      compiled: null,
      message: error instanceof Error ? error.message : "This template could not be compiled.",
    };
  }
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
    window.setTimeout(() => setCopyState("idle"), 1_500);
  }
  const copied = copyState === "copied";
  const visibleLabel = copied ? "Copied" : copyState === "failed" ? "Failed" : "Copy";
  return (
    <button className="copy-button" type="button" onClick={copy}
      aria-label={copied ? `${label} copied` : copyState === "failed" ? `Copy ${label} failed` : `Copy ${label}`}>
      {copied ? <Check size={15} aria-hidden="true" /> : <Clipboard size={15} aria-hidden="true" />}
      <span>{visibleLabel}</span>
    </button>
  );
}

function OutputBlock({ label, value, placeholder, copyDisabled = false }: {
  label: string;
  value: string | null;
  placeholder: string;
  copyDisabled?: boolean;
}) {
  return (
    <section className="output-block">
      <header>
        <span>{label}</span>
        {value ? (
          copyDisabled
            ? <span className="copy-blocked">DO NOT COPY</span>
            : <CopyButton key={value} value={value} label={label} />
        ) : null}
      </header>
      <code className={!value ? "is-placeholder" : undefined}>{value ?? placeholder}</code>
    </section>
  );
}

function TechnicalItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="technical-item">
      <div><span>{label}</span><CopyButton key={value} value={value} label={label} /></div>
      <code>{value}</code>
    </div>
  );
}

export default function Home() {
  const [rows, setRows] = useState<SignerRow[]>(() => initialRows());
  const [network, setNetwork] = useState<UiNetwork>("regtest");
  const [primaryThreshold, setPrimaryThreshold] = useState(1);
  const [recoveryDates, setRecoveryDates] = useState<string[]>(initialRecoveryDates);
  const [futureMinimum, setFutureMinimum] = useState(tomorrowDate);
  const [feedback, setFeedback] = useState<string | null>(null);
  const nextSignerId = useRef(5);

  useEffect(() => {
    const refreshDateBoundary = () => setFutureMinimum(tomorrowDate());
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") refreshDateBoundary();
    };
    const timer = window.setInterval(refreshDateBoundary, 60_000);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, []);

  const primaryRows = useMemo(() => rows.filter((row) => row.group === "primary"), [rows]);
  const recoveryRows = useMemo(() => rows.filter((row) => row.group === "recovery"), [rows]);
  const fieldState = useMemo(() => validateRows(rows), [rows]);
  const dateState = useMemo(
    () => validateDates(recoveryDates, recoveryRows.length, futureMinimum),
    [recoveryDates, recoveryRows.length, futureMinimum],
  );
  const live = useMemo(
    () => compileLive(rows, primaryThreshold, recoveryDates, network, fieldState, dateState),
    [rows, primaryThreshold, recoveryDates, network, fieldState, dateState],
  );
  const hasDemoKey = useMemo(
    () => rows.some((row) => DEMO_PUBLIC_KEYS.some((key) => key === row.publicKey.trim().toLowerCase())),
    [rows],
  );

  const logicalPathCount = 1 + recoveryRows.length;
  const primaryNames = primaryRows.map((row) => row.label.trim() || "Unnamed").join(", ");
  const recoveryNames = recoveryRows.map((row) => row.label.trim() || "Unnamed").join(", ");
  const naturalPolicy = [
    `${primaryThreshold} of ${primaryRows.length} Primary (${primaryNames}) can spend immediately.`,
    ...recoveryRows.map((_, index) => {
      const threshold = recoveryRows.length - index;
      return `${threshold} of ${recoveryRows.length} Recovery (${recoveryNames}) · CLTV ${readableDate(recoveryDates[index])}; block eligibility follows network median time.`;
    }),
  ].join(" OR ");

  function updateRow(id: string, patch: Partial<Omit<SignerRow, "id">>) {
    setRows((current) => current.map((row) => row.id === id ? { ...row, ...patch } : row));
    setFeedback(null);
  }

  function setGroup(id: string, group: SignerGroup) {
    const currentRow = rows.find((row) => row.id === id);
    if (!currentRow || currentRow.group === group) return;
    const sourceCount = rows.filter((row) => row.group === currentRow.group).length;
    if (sourceCount <= 1) {
      setFeedback(`Keep at least one ${currentRow.group === "primary" ? "Primary" : "Recovery"} signer.`);
      return;
    }
    const nextPrimaryCount = rows.filter((row) => (row.id === id ? group : row.group) === "primary").length;
    setRows((current) => current.map((row) => row.id === id ? { ...row, group } : row));
    setPrimaryThreshold((value) => Math.min(value, nextPrimaryCount));
    setFeedback(`${currentRow.label.trim() || "Signer"} now belongs to the ${group === "primary" ? "Primary" : "Recovery"} path.`);
  }

  function canRemove(row: SignerRow): boolean {
    return rows.length > 2 && rows.filter((candidate) => candidate.group === row.group).length > 1;
  }

  function removeSigner(row: SignerRow) {
    if (!canRemove(row)) {
      setFeedback("Keep at least one Primary signer, one Recovery signer, and two signers total.");
      return;
    }
    const nextRows = rows.filter((candidate) => candidate.id !== row.id);
    const nextPrimaryCount = nextRows.filter((candidate) => candidate.group === "primary").length;
    setRows(nextRows);
    setPrimaryThreshold((value) => Math.min(value, nextPrimaryCount));
    setFeedback(`${row.label.trim() || "Signer"} removed.`);
  }

  function addSigner() {
    if (rows.length >= MAX_SIGNERS) return;
    const id = `signer-${nextSignerId.current}`;
    nextSignerId.current += 1;
    const group: SignerGroup = recoveryRows.length < 4 ? "recovery" : "primary";
    setRows((current) => [...current, {
      id,
      label: group === "recovery" ? `Recovery ${recoveryRows.length + 1}` : `Primary ${primaryRows.length + 1}`,
      publicKey: "",
      group,
    }]);
    setFeedback("Signer added.");
  }

  function loadDemoKeys() {
    if (rows.some((row) => row.publicKey.trim()) &&
      !window.confirm("Replace the current signers with five public demo keys?")) return;
    setRows(initialRows(true));
    setPrimaryThreshold(1);
    setRecoveryDates(initialRecoveryDates());
    nextSignerId.current = 5;
    setFeedback("Demo compiled. These public keys are intentionally unsafe for real funds.");
  }

  function reset() {
    if (!window.confirm("Reset Mimir and clear every signer and date change?")) return;
    setRows(initialRows());
    setNetwork("regtest");
    setPrimaryThreshold(1);
    setRecoveryDates(initialRecoveryDates());
    setFutureMinimum(tomorrowDate());
    setFeedback(null);
    nextSignerId.current = 5;
  }

  function updateRecoveryDate(index: number, value: string) {
    setRecoveryDates((current) => current.map((date, dateIndex) => dateIndex === index ? value : date));
    setFeedback(null);
  }

  function downloadPolicy() {
    if (!live.compiled || hasDemoKey) return;
    const currentMinimum = tomorrowDate();
    if (validateDates(recoveryDates, recoveryRows.length, currentMinimum).some((date) => date.error)) {
      setFutureMinimum(currentMinimum);
      setFeedback("A Recovery date is no longer in the future. Update the schedule before export.");
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

  return (
    <main className="page-shell">
      <header className="masthead">
        <div className="masthead-copy">
          <p className="wordmark">MIMIR // 5×5 RECOVERY</p>
          <h1>One primary path. Up to four recovery stages.</h1>
          <p className="supporting-line">Up to five public keys · up to five fixed spending paths · compiled locally</p>
        </div>
        <div className="header-controls">
          <label>
            <span>Network</span>
            <select value={network} onChange={(event) => {
              if (isUiNetwork(event.target.value)) setNetwork(event.target.value);
            }} aria-label="Bitcoin test network">
              <option value="regtest">Regtest</option>
              <option value="signet">Signet</option>
            </select>
          </label>
          <button className="secondary-button" type="button" onClick={loadDemoKeys}>
            <KeyRound size={16} aria-hidden="true" /> Load demo keys
          </button>
          <button className="secondary-button" type="button" onClick={reset}>
            <RotateCcw size={16} aria-hidden="true" /> Reset
          </button>
        </div>
      </header>

      {hasDemoKey ? (
        <div className="demo-warning" role="alert">
          <strong>DEMO KEYS — never fund this address</strong>
          <span>The matching private keys are public knowledge. Replace every demo key before export.</span>
        </div>
      ) : null}

      <div className="workspace">
        <div className="builder">
          <section aria-labelledby="signers-heading">
            <div className="section-heading">
              <div>
                <p className="section-number">01</p>
                <h2 id="signers-heading">Signers</h2>
                <p>Enter compressed public keys, then assign each signer to one side.</p>
              </div>
              <span>{rows.length} / {MAX_SIGNERS}</span>
            </div>

            <div className="signer-list">
              {rows.map((row, index) => {
                const state = fieldState.get(row.id);
                return (
                  <article className="signer-row" data-group={row.group} key={row.id}>
                    <span className="row-number" aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
                    <label className="label-field">
                      <span>Label</span>
                      <input value={row.label} onChange={(event) => updateRow(row.id, { label: event.target.value })}
                        placeholder="Signer name" autoComplete="off" maxLength={80}
                        aria-invalid={Boolean(state?.labelError)}
                        aria-describedby={state?.labelError ? `${row.id}-label-error` : undefined} />
                      {state?.labelError ? (
                        <small className={row.label.trim() ? "field-error" : "sr-only"} id={`${row.id}-label-error`}>{state.labelError}</small>
                      ) : null}
                    </label>
                    <label className="key-field">
                      <span>Compressed public key</span>
                      <input value={row.publicKey} onChange={(event) => updateRow(row.id, { publicKey: event.target.value })}
                        placeholder="02 or 03 + 64 hex characters" autoComplete="off" autoCapitalize="none"
                        spellCheck={false} aria-invalid={Boolean(state?.publicKeyError)}
                        aria-describedby={state?.publicKeyError ? `${row.id}-key-error` : undefined} />
                      {state?.publicKeyError ? (
                        <small className={row.publicKey.trim() ? "field-error" : "sr-only"} id={`${row.id}-key-error`}>{state.publicKeyError}</small>
                      ) : null}
                    </label>
                    <fieldset className="group-toggle">
                      <legend>Spending side</legend>
                      <div>
                        <button type="button" className={row.group === "primary" ? "is-active" : ""}
                          onClick={() => setGroup(row.id, "primary")} aria-pressed={row.group === "primary"}
                          aria-describedby="signer-group-rule"
                          aria-label={`Assign ${row.label.trim() || `signer ${index + 1}`} to the Primary path`}>Primary</button>
                        <button type="button" className={row.group === "recovery" ? "is-active" : ""}
                          onClick={() => setGroup(row.id, "recovery")} aria-pressed={row.group === "recovery"}
                          aria-describedby="signer-group-rule"
                          aria-label={`Assign ${row.label.trim() || `signer ${index + 1}`} to the Recovery ladder`}>Recovery</button>
                      </div>
                    </fieldset>
                    <button className="remove-button" type="button" onClick={() => removeSigner(row)}
                      aria-disabled={!canRemove(row)} aria-describedby="signer-group-rule"
                      aria-label={`Remove ${row.label.trim() || `signer ${index + 1}`}`}>
                      <Trash2 size={17} aria-hidden="true" />
                    </button>
                  </article>
                );
              })}
            </div>

            <button className="add-signer-button" type="button" onClick={addSigner} disabled={rows.length >= MAX_SIGNERS}>
              <Plus size={17} aria-hidden="true" /> Add signer
            </button>
            <p className="functional-note" id="signer-group-rule">
              <strong>Primary and Recovery are functional.</strong> A key belongs to exactly one side. At least one signer must remain on each side.
            </p>
            {feedback ? <p className="feedback" role="status">{feedback}</p> : null}
          </section>

          <section className="primary-section" aria-labelledby="primary-heading">
            <div className="section-heading compact">
              <div>
                <p className="section-number">02</p>
                <h2 id="primary-heading">Primary path</h2>
                <p>Available immediately. Choose how many Primary signatures are required.</p>
              </div>
              <span>PATH 01</span>
            </div>
            <div className="primary-card">
              <div className="path-icon" aria-hidden="true"><UsersRound size={22} /></div>
              <div className="path-copy">
                <span>Immediate control</span>
                <strong>{primaryThreshold} of {primaryRows.length} Primary</strong>
                <small>{primaryNames || "No Primary signer"}</small>
              </div>
              <label className="threshold-field">
                <span>Signatures</span>
                <select value={primaryThreshold} onChange={(event) => setPrimaryThreshold(Number(event.target.value))}
                  aria-label="Required Primary signatures">
                  {primaryRows.map((_, index) => (
                    <option value={index + 1} key={index + 1}>{index + 1} of {primaryRows.length}</option>
                  ))}
                </select>
              </label>
            </div>
          </section>

          <section className="recovery-section" aria-labelledby="recovery-heading">
            <div className="section-heading compact">
              <div>
                <p className="section-number">03</p>
                <h2 id="recovery-heading">Recovery ladder</h2>
                <p>Each later CLTV date needs one fewer signature. Block eligibility follows Bitcoin median time.</p>
              </div>
              <span>{recoveryRows.length} STAGES</span>
            </div>
            <div className="ladder" aria-label="Recovery spending stages">
              {recoveryRows.map((_, index) => {
                const threshold = recoveryRows.length - index;
                const dateError = dateState[index]?.error;
                return (
                  <article className="stage-row" key={`stage-${index + 1}`}>
                    <div className="stage-index"><span>PATH</span><strong>{String(index + 2).padStart(2, "0")}</strong></div>
                    <div className="stage-threshold"><span>Required</span><strong>{threshold} of {recoveryRows.length}</strong><small>Recovery signatures</small></div>
                    <div className="stage-connector" aria-hidden="true"><Clock3 size={18} /></div>
                    <label className="date-field">
                      <span>CLTV locktime · 00:00 UTC</span>
                      <input type="date" value={recoveryDates[index]} min={tomorrowDate()} max="2038-01-19"
                        onChange={(event) => updateRecoveryDate(index, event.target.value)}
                        aria-invalid={Boolean(dateError)} aria-describedby={dateError ? `stage-${index + 1}-date-error` : undefined} />
                      {dateError ? <small className="field-error" id={`stage-${index + 1}-date-error`}>{dateError}</small> : null}
                    </label>
                  </article>
                );
              })}
            </div>
            <div className="template-rule">
              <strong>The shape is fixed.</strong>
              <span>With {recoveryRows.length} Recovery {recoveryRows.length === 1 ? "signer" : "signers"}, Mimir creates {recoveryRows.length} {recoveryRows.length === 1 ? "stage" : "stages"}: {recoveryRows.map((_, index) => `${recoveryRows.length - index}/${recoveryRows.length}`).join(" → ")}.</span>
            </div>
          </section>

          <section className="path-review" aria-labelledby="review-heading">
            <div className="section-heading compact">
              <div>
                <p className="section-number">04</p>
                <h2 id="review-heading">Path review</h2>
                <p>Any one complete path unlocks the same P2WSH output.</p>
              </div>
              <span>{logicalPathCount} / 5</span>
            </div>
            <ol className="path-list">
              <li><span>01</span><strong>PRIMARY</strong><p>{primaryThreshold} of {primaryRows.length} · immediately</p></li>
              {recoveryRows.map((_, index) => (
                <li key={`review-${index + 1}`}>
                  <span>{String(index + 2).padStart(2, "0")}</span><strong>RECOVERY</strong>
                  <p>{recoveryRows.length - index} of {recoveryRows.length} · CLTV {readableDate(recoveryDates[index])}</p>
                </li>
              ))}
            </ol>
          </section>
        </div>

        <aside className="live-panel" aria-labelledby="live-heading">
          <header className="live-header">
            <div><span>LIVE OUTPUT</span><h2 id="live-heading">LIVE BITCOIN SCRIPT</h2></div>
            <span className={`status-badge ${live.compiled ? "is-valid" : ""} ${hasDemoKey && live.compiled ? "is-demo" : ""}`}>
              {hasDemoKey && live.compiled ? "DEMO · DO NOT FUND" : live.compiled ? "VALID" : "WAITING"}
            </span>
          </header>
          <section className={`policy-output ${live.compiled ? "" : "is-draft"}`}>
            <span>{live.compiled ? "COMPILED POLICY" : "DRAFT POLICY"} · {logicalPathCount} PATHS</span><p>{naturalPolicy}</p>
          </section>
          <div className={`compile-status ${live.compiled ? "is-valid" : ""}`} role="status">
            <span aria-hidden="true">{live.compiled ? "●" : "○"}</span><p>{live.message}</p>
          </div>
          <OutputBlock label="MINISCRIPT" value={live.compiled?.miniscript ?? null}
            placeholder="Exact Miniscript appears after every signer and date is valid." />
          <OutputBlock label="BITCOIN SCRIPT (ASM)" value={live.compiled?.asm ?? null}
            placeholder="The compiled witness script will appear here." />
          <OutputBlock label={`${network.toUpperCase()} P2WSH ADDRESS`} value={live.compiled?.address ?? null}
            placeholder="No address until compilation succeeds." copyDisabled={hasDemoKey} />

          <details className="technical-details">
            <summary>Technical details</summary>
            {live.compiled ? (
              <div className="technical-list">
                <TechnicalItem label="Descriptor" value={live.compiled.descriptor} />
                <TechnicalItem label="Witness script hex" value={live.compiled.witness_script_hex} />
                <TechnicalItem label="Witness program SHA-256" value={live.compiled.witness_program_sha256} />
                <TechnicalItem label="ScriptPubKey" value={live.compiled.script_pubkey_hex} />
                <TechnicalItem label="Policy manifest SHA-256" value={live.compiled.policy_manifest_sha256} />
                <div className="verification-list">
                  <span>Compiler checks</span>
                  <ul>{live.compiled.invariants.map((invariant) => (
                    <li key={invariant.id}><strong>{invariant.ok ? "PASS" : "FAIL"}</strong><span>{invariant.label}</span></li>
                  ))}</ul>
                </div>
                <div className="warning-list">
                  <span>Operational warnings</span>
                  <ul>{live.compiled.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
                </div>
              </div>
            ) : <p className="details-placeholder">Complete the template to inspect its descriptor, hashes, and compiler checks.</p>}
          </details>

          <button className="export-button" type="button" onClick={downloadPolicy}
            disabled={!live.compiled || hasDemoKey}>
            <Download size={17} aria-hidden="true" /> Export policy JSON
          </button>
          {hasDemoKey ? <small className="export-note">Replace all demo keys before export.</small> : null}
        </aside>
      </div>

      <footer className="site-footer">
        <div><strong>PREVIEW SOFTWARE</strong><p>Use Regtest first. Independently verify the script, address, backups, and signing flow before risking funds.</p></div>
        <div><strong>ABSOLUTE DATES</strong><p>The displayed UTC date is the CLTV transaction locktime floor. Block inclusion requires the previous block median time past to exceed it; dates are not relative to funding.</p></div>
        <div><strong>NO PRIVATE KEYS</strong><p>Mimir accepts public keys only and makes no network requests. Private keys never belong in this page.</p></div>
      </footer>
    </main>
  );
}
