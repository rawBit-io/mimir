"use client";

import {
  Check,
  Clipboard,
  Download,
  Plus,
  RotateCcw,
  Trash2,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";
import {
  TEMPLATE_ID_V3,
  compileRulePolicy,
  unixFromRuleDate,
  validateRulePublicKey,
  type CompiledRulePolicy,
  type RuleComposerRequest,
  type RuleNetwork,
} from "../lib/rule-composer";

type UiNetwork = Exclude<RuleNetwork, "bitcoin">;
type SignerRole = "owner" | "heir";

type SignerRow = {
  id: string;
  label: string;
  publicKey: string;
  role: SignerRole;
};

type LocalRule = {
  id: string;
  keyRowIds: string[];
  threshold: number;
  unlockDate: string | null;
};

type FieldState = {
  labelInvalid: boolean;
  publicKeyInvalid: boolean;
  labelError: string | null;
  publicKeyError: string | null;
};

type LiveResult = {
  compiled: CompiledRulePolicy | null;
  message: string | null;
};

const MAX_KEYS = 20;
const MAX_RULE_KEYS = 10;
const MAX_RULES = 10;

function firstFutureRuleDate(): string {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}

function defaultRuleDate(): string {
  const date = new Date();
  date.setUTCFullYear(date.getUTCFullYear() + 1);
  return date.toISOString().slice(0, 10);
}

function initialRows(): SignerRow[] {
  return [
    { id: "signer-0", label: "Owner", publicKey: "", role: "owner" },
    { id: "signer-1", label: "Heir", publicKey: "", role: "heir" },
  ];
}

function isUiNetwork(value: string): value is UiNetwork {
  return value === "regtest" || value === "signet";
}

function shortKey(value: string): string {
  const normalized = value.trim();
  if (normalized.length < 20) return normalized || "Public key missing";
  return `${normalized.slice(0, 12)}…${normalized.slice(-10)}`;
}

function readableDate(value: string): string {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return "the selected date";
  const [, year, month, day] = match;
  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  return `${Number(day)} ${months[Number(month) - 1]} ${year}, 00:00 UTC`;
}

function normalizedThreshold(value: number, count: number): number {
  return Math.min(Math.max(1, value), Math.max(1, count));
}

function validateRows(rows: SignerRow[]): Map<string, FieldState> {
  const labels = rows.map((row) => row.label.trim().normalize("NFC"));
  const labelCounts = new Map<string, number>();
  for (const label of labels) {
    const comparable = label.toLocaleLowerCase("en-US");
    labelCounts.set(comparable, (labelCounts.get(comparable) ?? 0) + 1);
  }

  const publicKeys = rows.map((row) => {
    try {
      return validateRulePublicKey(row.publicKey);
    } catch {
      return null;
    }
  });
  const publicKeyCounts = new Map<string, number>();
  for (const publicKey of publicKeys) {
    if (publicKey) {
      publicKeyCounts.set(publicKey, (publicKeyCounts.get(publicKey) ?? 0) + 1);
    }
  }

  return new Map(
    rows.map((row, index) => {
      const label = labels[index];
      const publicKey = publicKeys[index];
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
          ? "Use a valid 66-character compressed key starting with 02 or 03."
          : "Enter a compressed public key."
        : (publicKeyCounts.get(publicKey) ?? 0) > 1
          ? "This public key is already listed."
          : null;
      return [
        row.id,
        {
          labelInvalid: Boolean(labelError),
          publicKeyInvalid: Boolean(publicKeyError),
          labelError,
          publicKeyError,
        },
      ];
    }),
  );
}

function compileRules(
  rows: SignerRow[],
  rules: LocalRule[],
  network: UiNetwork,
): LiveResult {
  if (rules.length === 0) return { compiled: null, message: null };

  try {
    const rowById = new Map(rows.map((row) => [row.id, row]));
    const usedRowIds = [...new Set(rules.flatMap((rule) => rule.keyRowIds))];
    const usedRows = usedRowIds.map((id) => {
      const row = rowById.get(id);
      if (!row) throw new Error("A rule references a removed key. Remove that rule and add it again.");
      return {
        row,
        label: row.label.trim().normalize("NFC"),
        publicKey: validateRulePublicKey(row.publicKey),
      };
    });

    if (usedRows.some((entry) => !entry.label)) {
      throw new Error("Name every key used by a rule.");
    }
    if (
      new Set(usedRows.map((entry) => entry.label.toLocaleLowerCase("en-US"))).size !==
      usedRows.length
    ) {
      throw new Error("Use a unique label for every key in the rules.");
    }
    if (new Set(usedRows.map((entry) => entry.publicKey)).size !== usedRows.length) {
      throw new Error("Each public key can be used only once.");
    }

    const completeRows = rows.flatMap((row) => {
      const label = row.label.trim().normalize("NFC");
      if (!label || !row.publicKey.trim()) return [];
      try {
        return [{ row, label, publicKey: validateRulePublicKey(row.publicKey) }];
      } catch {
        return [];
      }
    });
    const sortedKeys = completeRows.sort(
      (left, right) =>
        left.publicKey.localeCompare(right.publicKey) ||
        left.label.localeCompare(right.label),
    );
    const requestIdByRowId = new Map(
      sortedKeys.map((entry, index) => [
        entry.row.id,
        `key-${String(index + 1).padStart(2, "0")}`,
      ]),
    );

    const request: RuleComposerRequest = {
      format: "mimir-rule-request",
      version: 3,
      network,
      template_id: TEMPLATE_ID_V3,
      keys: sortedKeys.map((entry, index) => ({
        id: `key-${String(index + 1).padStart(2, "0")}`,
        label: entry.label,
        public_key: entry.publicKey,
      })),
      rules: rules.map((rule) => ({
        key_ids: rule.keyRowIds.map((rowId) => {
          const requestId = requestIdByRowId.get(rowId);
          if (!requestId) throw new Error("A rule contains an unknown key.");
          return requestId;
        }),
        threshold: rule.threshold,
        unlock_unix: rule.unlockDate ? unixFromRuleDate(rule.unlockDate) : null,
      })),
    };

    return { compiled: compileRulePolicy(request), message: null };
  } catch (error) {
    return {
      compiled: null,
      message: error instanceof Error ? error.message : "The rules could not be compiled.",
    };
  }
}

function ruleSummary(rule: LocalRule, rowById: Map<string, SignerRow>): string {
  const names = rule.keyRowIds.map((id) => rowById.get(id)?.label.trim() || "Unnamed key");
  const signers = names.length === 1
    ? names[0]
    : `${rule.threshold} of ${names.length} · ${names.join(", ")}`;
  const timing = rule.unlockDate
    ? `from ${readableDate(rule.unlockDate)}`
    : "immediately";
  return `${signers} can spend ${timing}.`;
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1_500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <button className="copy-button" type="button" onClick={copy} aria-label={`Copy ${label}`}>
      {copied ? <Check size={15} aria-hidden="true" /> : <Clipboard size={15} aria-hidden="true" />}
      <span>{copied ? "Copied" : "Copy"}</span>
    </button>
  );
}

function TechnicalItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="technical-item">
      <div>
        <span>{label}</span>
        <CopyButton key={value} value={value} label={label} />
      </div>
      <code>{value}</code>
    </div>
  );
}

export default function Home() {
  const [rows, setRows] = useState<SignerRow[]>(initialRows);
  const [rules, setRules] = useState<LocalRule[]>([]);
  const [network, setNetwork] = useState<UiNetwork>("regtest");
  const [selectedKeyIds, setSelectedKeyIds] = useState<string[]>([]);
  const [multisig, setMultisig] = useState(false);
  const [threshold, setThreshold] = useState(1);
  const [timeDelay, setTimeDelay] = useState(false);
  const [unlockDate, setUnlockDate] = useState(defaultRuleDate);
  const [feedback, setFeedback] = useState<string | null>(null);
  const nextSignerId = useRef(2);
  const nextRuleId = useRef(1);

  const rowById = useMemo(() => new Map(rows.map((row) => [row.id, row])), [rows]);
  const fieldState = useMemo(() => validateRows(rows), [rows]);
  const usedByRule = useMemo(() => {
    return new Set(rules.flatMap((rule) => rule.keyRowIds));
  }, [rules]);
  const live = useMemo(() => compileRules(rows, rules, network), [rows, rules, network]);

  const draftMessage = useMemo(() => {
    if (rules.length >= MAX_RULES) return "Remove a rule before adding another.";
    if (selectedKeyIds.length === 0) return "Choose a key for this rule.";
    if (!multisig && selectedKeyIds.length !== 1) return "Choose exactly one key.";
    if (multisig && selectedKeyIds.length < 2) return "Choose at least two keys for multisig.";
    if (selectedKeyIds.length > MAX_RULE_KEYS) return "A rule can use at most 10 keys.";
    if (threshold < 1 || threshold > selectedKeyIds.length) return "Choose a valid signature threshold.";
    for (const id of selectedKeyIds) {
      const state = fieldState.get(id);
      if (!state || state.labelInvalid || state.publicKeyInvalid) {
        return "Complete every selected key before adding the rule.";
      }
      if (usedByRule.has(id)) return "A key can appear in only one rule.";
    }
    if (timeDelay) {
      try {
        unixFromRuleDate(unlockDate);
      } catch (error) {
        return error instanceof Error ? error.message : "Choose a valid delay date.";
      }
      if (unlockDate < firstFutureRuleDate()) {
        return "Choose a future unlock date for a real time delay.";
      }
    }
    return null;
  }, [
    rules.length,
    selectedKeyIds,
    multisig,
    threshold,
    fieldState,
    usedByRule,
    timeDelay,
    unlockDate,
  ]);

  function updateRow(id: string, patch: Partial<Omit<SignerRow, "id">>) {
    setRows((current) =>
      current.map((row) => (row.id === id ? { ...row, ...patch } : row)),
    );
    setFeedback(null);
  }

  function addKey() {
    if (rows.length >= MAX_KEYS) return;
    const id = `signer-${nextSignerId.current}`;
    nextSignerId.current += 1;
    setRows((current) => [
      ...current,
      { id, label: "", publicKey: "", role: "heir" },
    ]);
    setFeedback("New key added.");
  }

  function removeKey(id: string) {
    const used = usedByRule.has(id);
    const row = rowById.get(id);
    if (used) {
      setFeedback(
        `Remove the saved rule before deleting ${row?.label.trim() || "this key"}.`,
      );
      return;
    }
    setRows((current) => current.filter((entry) => entry.id !== id));
    const nextSelection = selectedKeyIds.filter((keyId) => keyId !== id);
    setSelectedKeyIds(nextSelection);
    setThreshold((value) => normalizedThreshold(value, nextSelection.length));
    setFeedback("Key removed.");
  }

  function chooseDraftKey(id: string) {
    if (usedByRule.has(id)) return;
    const alreadySelected = selectedKeyIds.includes(id);
    if (multisig && alreadySelected) {
      const nextSelection = selectedKeyIds.filter((keyId) => keyId !== id);
      setSelectedKeyIds(nextSelection);
      setThreshold((value) => normalizedThreshold(value, nextSelection.length));
      return;
    }
    const state = fieldState.get(id);
    if (!state || state.labelInvalid || state.publicKeyInvalid) return;

    if (!multisig) {
      setSelectedKeyIds([id]);
      setThreshold(1);
      return;
    }

    const nextSelection = selectedKeyIds.length < MAX_RULE_KEYS
      ? [...selectedKeyIds, id]
      : selectedKeyIds;
    setSelectedKeyIds(nextSelection);
    setThreshold((value) => normalizedThreshold(value, nextSelection.length));
  }

  function toggleMultisig(enabled: boolean) {
    setMultisig(enabled);
    if (!enabled) {
      setSelectedKeyIds((current) => current.slice(0, 1));
      setThreshold(1);
    } else {
      setThreshold((value) => normalizedThreshold(value, selectedKeyIds.length));
    }
  }

  function clearDraft() {
    setSelectedKeyIds([]);
    setMultisig(false);
    setThreshold(1);
    setTimeDelay(false);
    setUnlockDate(defaultRuleDate());
  }

  function addRule() {
    if (draftMessage) return;
    const candidate: LocalRule = {
      id: `local-rule-${nextRuleId.current}`,
      keyRowIds: [...selectedKeyIds],
      threshold,
      unlockDate: timeDelay ? unlockDate : null,
    };
    const trial = compileRules(rows, [...rules, candidate], network);
    if (!trial.compiled) {
      setFeedback(trial.message ?? "This rule could not be added.");
      return;
    }
    nextRuleId.current += 1;
    setRules((current) => [...current, candidate]);
    clearDraft();
    setFeedback("Rule added. The Bitcoin script is updated.");
  }

  function removeRule(id: string) {
    setRules((current) => current.filter((rule) => rule.id !== id));
    setFeedback("Rule removed. Its keys are available again.");
  }

  function reset() {
    if (!window.confirm("Reset Mimir and clear every key and rule?")) {
      return;
    }
    setRows(initialRows());
    setRules([]);
    setNetwork("regtest");
    clearDraft();
    setFeedback(null);
    nextSignerId.current = 2;
    nextRuleId.current = 1;
  }

  function downloadPolicy() {
    if (!live.compiled) return;
    const blob = new Blob([live.compiled.canonical_manifest], {
      type: "application/json;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `mimir-${live.compiled.request.network}-${live.compiled.policy_manifest_sha256.slice(0, 12)}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  const naturalPolicy = rules.length
    ? rules.map((rule) => ruleSummary(rule, rowById)).join(" OR ")
    : "Add a rule to define who can spend and when.";

  return (
    <main className="page-shell">
      <header className="masthead">
        <div>
          <p className="wordmark">MIMIR</p>
          <h1>Build a Bitcoin recovery script.</h1>
          <p className="supporting-line">Public keys only · updates live · offline</p>
        </div>
        <div className="header-controls">
          <label>
            <span>Network</span>
            <select
              value={network}
              onChange={(event) => {
                if (isUiNetwork(event.target.value)) setNetwork(event.target.value);
              }}
            >
              <option value="regtest">Regtest</option>
              <option value="signet">Signet</option>
            </select>
          </label>
          <button className="reset-button" type="button" onClick={reset}>
            <RotateCcw size={16} aria-hidden="true" />
            Reset
          </button>
        </div>
      </header>

      <div className="workspace">
        <div className="builder">
          <section aria-labelledby="keys-heading">
            <div className="section-heading">
              <div>
                <p className="section-number">01</p>
                <h2 id="keys-heading">Keys</h2>
                <p>Enter each signer once. Owner and Heir marks are visual labels.</p>
              </div>
              <span>{rows.length} / {MAX_KEYS}</span>
            </div>

            <div className="signer-list">
              {rows.map((row, index) => {
                const state = fieldState.get(row.id);
                const used = usedByRule.has(row.id);
                return (
                  <article className="signer-row" data-role={row.role} key={row.id}>
                    <span className="row-number" aria-hidden="true">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <label className="label-field">
                      <span>Label</span>
                      <input
                        value={row.label}
                        onChange={(event) => updateRow(row.id, { label: event.target.value })}
                        placeholder="Signer name"
                        autoComplete="off"
                        maxLength={80}
                        aria-invalid={state?.labelInvalid ?? false}
                        aria-describedby={
                          state?.labelError ? `${row.id}-label-error` : undefined
                        }
                      />
                      {state?.labelError ? (
                        <small
                          className={row.label.trim() ? "field-error" : "sr-only"}
                          id={`${row.id}-label-error`}
                        >
                          {state.labelError}
                        </small>
                      ) : null}
                    </label>
                    <label className="key-field">
                      <span>
                        Compressed public key{used ? " · locked by rule" : ""}
                      </span>
                      <input
                        value={row.publicKey}
                        onChange={(event) => updateRow(row.id, { publicKey: event.target.value })}
                        placeholder="02 or 03 + 64 hex characters"
                        autoComplete="off"
                        autoCapitalize="none"
                        spellCheck={false}
                        inputMode="text"
                        aria-invalid={state?.publicKeyInvalid ?? false}
                        aria-describedby={
                          state?.publicKeyError ? `${row.id}-key-error` : undefined
                        }
                        disabled={used}
                        title={used ? "Remove its saved rule before editing this key." : undefined}
                      />
                      {state?.publicKeyError ? (
                        <small
                          className={row.publicKey.trim() ? "field-error" : "sr-only"}
                          id={`${row.id}-key-error`}
                        >
                          {state.publicKeyError}
                        </small>
                      ) : null}
                    </label>
                    <fieldset className="role-toggle">
                      <legend>Mark</legend>
                      <div>
                        <button
                          type="button"
                          className={row.role === "owner" ? "is-active" : ""}
                          onClick={() => updateRow(row.id, { role: "owner" })}
                          aria-pressed={row.role === "owner"}
                          aria-label={`Mark ${row.label.trim() || `key ${index + 1}`} as Owner`}
                        >
                          Owner
                        </button>
                        <button
                          type="button"
                          className={row.role === "heir" ? "is-active" : ""}
                          onClick={() => updateRow(row.id, { role: "heir" })}
                          aria-pressed={row.role === "heir"}
                          aria-label={`Mark ${row.label.trim() || `key ${index + 1}`} as Heir`}
                        >
                          Heir
                        </button>
                      </div>
                    </fieldset>
                    <button
                      className="remove-button"
                      type="button"
                      onClick={() => removeKey(row.id)}
                      aria-label={`Remove ${row.label.trim() || `key ${index + 1}`}`}
                    >
                      <Trash2 size={17} aria-hidden="true" />
                    </button>
                  </article>
                );
              })}
            </div>

            <button
              className="add-key-button"
              type="button"
              onClick={addKey}
              disabled={rows.length >= MAX_KEYS}
            >
              <Plus size={17} aria-hidden="true" />
              Add key
            </button>
          </section>

          <section className="new-rule" aria-labelledby="new-rule-heading">
            <div className="section-heading compact">
              <div>
                <p className="section-number">02</p>
                <h2 id="new-rule-heading">NEW RULE</h2>
                <p>Choose who can spend, how many signatures are needed, and when.</p>
              </div>
            </div>

            <p className="role-safety">
              <strong>Owner / Heir marks do not enforce spending.</strong> The selected keys,
              multisig threshold, and time delay do. An Heir-marked key without a delay can
              spend immediately.
            </p>

            <fieldset className="key-picker">
              <legend>Choose keys</legend>
              <div className="key-tiles">
                {rows.map((row) => {
                  const state = fieldState.get(row.id);
                  const used = usedByRule.has(row.id);
                  const selected = selectedKeyIds.includes(row.id);
                  const selectionLimitReached =
                    multisig && selectedKeyIds.length >= MAX_RULE_KEYS && !selected;
                  const unavailable =
                    used ||
                    selectionLimitReached ||
                    !state ||
                    state.labelInvalid ||
                    state.publicKeyInvalid;
                  return (
                    <label
                      className={`key-tile${selected ? " is-selected" : ""}`}
                      data-role={row.role}
                      key={row.id}
                    >
                      <input
                        type={multisig ? "checkbox" : "radio"}
                        name={multisig ? undefined : "single-rule-key"}
                        checked={selected}
                        disabled={unavailable && !selected}
                        onChange={() => chooseDraftKey(row.id)}
                      />
                      <span className="role-mark">{row.role}</span>
                      <strong>{row.label.trim() || "Unnamed key"}</strong>
                      <code>{shortKey(row.publicKey)}</code>
                      <small>
                        {used
                          ? "Used in a saved rule"
                          : selectionLimitReached
                            ? "10-key limit reached"
                          : unavailable
                            ? "Complete this key first"
                            : selected
                              ? "Selected"
                              : "Available"}
                      </small>
                    </label>
                  );
                })}
              </div>
            </fieldset>

            <div className="rule-options">
              <div className="option-block">
                <label className="option-switch">
                  <input
                    type="checkbox"
                    checked={multisig}
                    onChange={(event) => toggleMultisig(event.target.checked)}
                  />
                  <span>
                    <strong>Multisig</strong>
                    <small>Choose how many selected keys must sign.</small>
                  </span>
                </label>
                {multisig ? (
                  <label className="threshold-field">
                    <span>Signatures required</span>
                    <select
                      value={threshold}
                      onChange={(event) => setThreshold(Number(event.target.value))}
                      disabled={selectedKeyIds.length === 0}
                    >
                      {Array.from(
                        { length: Math.max(1, selectedKeyIds.length) },
                        (_, index) => (
                          <option value={index + 1} key={index + 1}>{index + 1}</option>
                        ),
                      )}
                    </select>
                    <small>of {selectedKeyIds.length} selected</small>
                  </label>
                ) : (
                  <p className="option-note">One selected key can sign.</p>
                )}
              </div>

              <div className="option-block">
                <label className="option-switch">
                  <input
                    type="checkbox"
                    checked={timeDelay}
                    onChange={(event) => setTimeDelay(event.target.checked)}
                  />
                  <span>
                    <strong>Time delay</strong>
                    <small>Prevent this rule from spending before a date.</small>
                  </span>
                </label>
                {timeDelay ? (
                  <label className="date-field">
                    <span>Available from · 00:00 UTC</span>
                    <input
                      type="date"
                      value={unlockDate}
                      onChange={(event) => setUnlockDate(event.target.value)}
                      min={firstFutureRuleDate()}
                      max="2038-01-19"
                    />
                    <small>
                      Bitcoin uses median time past; activation may be later.
                    </small>
                  </label>
                ) : (
                  <p className="option-note">This rule can spend immediately.</p>
                )}
              </div>
            </div>

            <div className="add-rule-row">
              <p role="status" aria-live="polite">{draftMessage ?? "Ready to add."}</p>
              <button
                className="add-rule-button"
                type="button"
                onClick={addRule}
                disabled={Boolean(draftMessage)}
              >
                <Plus size={17} aria-hidden="true" />
                ADD RULE
              </button>
            </div>
          </section>

          <section className="your-rules" aria-labelledby="your-rules-heading">
            <div className="section-heading compact">
              <div>
                <p className="section-number">03</p>
                <h2 id="your-rules-heading">YOUR RULES</h2>
                <p>Any one complete rule can unlock the Bitcoin.</p>
              </div>
              <span>{rules.length} / {MAX_RULES}</span>
            </div>

            {rules.length === 0 ? (
              <p className="empty-rules">No rules yet. Add one above.</p>
            ) : (
              <ol className="rule-list">
                {rules.map((rule) => (
                  <li key={rule.id}>
                    <span className="rule-index">RULE</span>
                    <p>{ruleSummary(rule, rowById)}</p>
                    <div className="rule-members" aria-label="Keys in this saved rule">
                      {rule.keyRowIds.map((id) => {
                        const row = rowById.get(id);
                        return (
                          <span key={id}>
                            <small>{row?.role ?? "key"}</small>
                            {row?.label.trim() || "Unnamed key"}
                          </span>
                        );
                      })}
                    </div>
                    <button
                      type="button"
                      onClick={() => removeRule(rule.id)}
                      aria-label={`Remove rule: ${ruleSummary(rule, rowById)}`}
                    >
                      <Trash2 size={16} aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </section>

          {feedback ? (
            <p className="feedback" role="status" aria-live="polite">{feedback}</p>
          ) : null}
        </div>

        <aside className="script-pane" aria-labelledby="script-heading">
          <header>
            <div>
              <p>Live output</p>
              <h2 id="script-heading">LIVE BITCOIN SCRIPT</h2>
            </div>
            <span>{live.compiled ? "Valid" : rules.length ? "Check rules" : "Empty"}</span>
          </header>

          <section className="live-section policy-summary">
            <h3>Policy</h3>
            <p>{naturalPolicy}</p>
            {live.message ? (
              <p className="live-error" role="status" aria-live="polite">
                {live.message}
              </p>
            ) : null}
          </section>

          <section className={`live-section${rules.length === 0 ? " is-empty" : ""}`}>
            <div className="live-label">
              <h3>Miniscript</h3>
              {live.compiled ? (
                <CopyButton
                  key={live.compiled.miniscript}
                  value={live.compiled.miniscript}
                  label="Miniscript"
                />
              ) : null}
            </div>
            <code>{live.compiled?.miniscript ?? (rules.length ? "waiting for valid rules" : "No rules yet")}</code>
          </section>

          <section className={`live-section${rules.length === 0 ? " is-empty" : ""}`}>
            <div className="live-label">
              <h3>Bitcoin Script (ASM)</h3>
              {live.compiled ? (
                <CopyButton
                  key={live.compiled.asm}
                  value={live.compiled.asm}
                  label="Bitcoin Script ASM"
                />
              ) : null}
            </div>
            <code>{live.compiled?.asm ?? (rules.length ? "waiting for valid rules" : "No rules yet")}</code>
          </section>

          {live.compiled ? (
            <section className="address-block">
              <div>
                <span>{network === "regtest" ? "Regtest" : "Signet"} P2WSH address</span>
                <CopyButton
                  key={live.compiled.address}
                  value={live.compiled.address}
                  label="P2WSH address"
                />
              </div>
              <code>{live.compiled.address}</code>
            </section>
          ) : null}

          <details className="technical-details">
            <summary>Technical details</summary>
            {live.compiled ? (
              <div className="technical-content">
                <TechnicalItem label="Checksummed descriptor" value={live.compiled.descriptor} />
                <TechnicalItem label="Witness script · hex" value={live.compiled.witness_script_hex} />
                <TechnicalItem label="scriptPubKey · hex" value={live.compiled.script_pubkey_hex} />
                <TechnicalItem label="Canonical manifest · SHA256" value={live.compiled.policy_manifest_sha256} />

                <div className="checks-summary">
                  <span>Internal checks</span>
                  <p>{live.compiled.invariants.length} of {live.compiled.invariants.length} passed.</p>
                </div>

                <div className="warnings">
                  <span>Before funding</span>
                  <ul>
                    {live.compiled.warnings.map((warning) => <li key={warning}>{warning}</li>)}
                  </ul>
                </div>

                <button className="download-button" type="button" onClick={downloadPolicy}>
                  <Download size={16} aria-hidden="true" />
                  Download policy JSON
                </button>
              </div>
            ) : (
              <p className="technical-waiting">
                Descriptor, script hex, checks, warnings, and JSON appear after a valid rule is added.
              </p>
            )}
          </details>
        </aside>
      </div>

      <footer>
        Preview software. Rehearse on regtest or signet and verify with Bitcoin Core before funding.
      </footer>
    </main>
  );
}
