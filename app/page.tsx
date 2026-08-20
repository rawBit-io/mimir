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
  TEMPLATE_ID_V2,
  compileComposedPolicy,
  unixFromComposerUtc,
  validateCompressedPublicKey,
  type CompiledComposerPolicy,
  type ComposerNetwork,
  type ComposerRequest,
} from "../lib/composer";

type Role = "owner" | "heirs";
type UiNetwork = Exclude<ComposerNetwork, "bitcoin">;

type SignerRow = {
  id: string;
  label: string;
  publicKey: string;
  role: Role;
};

type LiveCompilation = {
  compiled: CompiledComposerPolicy | null;
  message: string | null;
};

type RowFieldState = {
  labelInvalid: boolean;
  publicKeyInvalid: boolean;
};

const DEFAULT_OWNER_UNLOCK = "2030-01-01T00:00";
const DEFAULT_HEIR_UNLOCK = "2035-01-01T00:00";
const MAX_KEYS = 20;
const MAX_KEYS_PER_ROLE = 10;

function initialRows(): SignerRow[] {
  return [
    { id: "signer-0", label: "Owner", publicKey: "", role: "owner" },
    { id: "signer-1", label: "Heir", publicKey: "", role: "heirs" },
  ];
}

function exactUtc(value: string): string {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) {
    throw new Error("Choose an exact UTC date and time for both paths.");
  }
  return `${value}:00Z`;
}

function normalizedThreshold(value: number, count: number): number {
  if (count === 0) return 0;
  return Math.min(Math.max(1, value), count);
}

function shortUtc(value: string): string {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/);
  if (!match) return "the selected time";
  const [, year, month, day, hour, minute] = match;
  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  return `${Number(day)} ${months[Number(month) - 1]} ${year}, ${hour}:${minute} UTC`;
}

function placeholderFragment(role: Role, threshold: number, count: number): string {
  const prefix = role === "owner" ? "OWNER" : "HEIR";
  if (count === 0) return `<ADD_${prefix}_KEY>`;
  if (count === 1) return `pk(<${prefix}_KEY>)`;
  const keys = Array.from(
    { length: count },
    (_, index) => `<${prefix}_KEY_${index + 1}>`,
  );
  return `multi(${normalizedThreshold(threshold, count)},${keys.join(",")})`;
}

function placeholderUnix(value: string, fallback: string): string {
  try {
    return String(unixFromComposerUtc(exactUtc(value)));
  } catch {
    return fallback;
  }
}

function buildPlaceholder(
  ownerCount: number,
  heirCount: number,
  ownerThreshold: number,
  heirThreshold: number,
  ownerUnlock: string,
  heirUnlock: string,
): string {
  const ownerTime = placeholderUnix(ownerUnlock, "OWNER_TIME");
  const heirTime = placeholderUnix(heirUnlock, "HEIR_TIME");
  return (
    `or_i(and_v(v:after(${ownerTime}),` +
    `${placeholderFragment("owner", ownerThreshold, ownerCount)}),` +
    `and_v(v:after(${heirTime}),` +
    `${placeholderFragment("heirs", heirThreshold, heirCount)}))`
  );
}

function validateRowFields(rows: SignerRow[]): Map<string, RowFieldState> {
  const labels = rows.map((row) => row.label.trim().normalize("NFC"));
  const labelCounts = new Map<string, number>();
  for (const label of labels) {
    const key = label.toLocaleLowerCase("en-US");
    labelCounts.set(key, (labelCounts.get(key) ?? 0) + 1);
  }

  const publicKeys = rows.map((row) => {
    try {
      return validateCompressedPublicKey(row.publicKey);
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
      return [
        row.id,
        {
          labelInvalid:
            !label ||
            label.length > 80 ||
            /\p{Cc}/u.test(label) ||
            (labelCounts.get(label.toLocaleLowerCase("en-US")) ?? 0) > 1,
          publicKeyInvalid:
            !publicKey || (publicKeyCounts.get(publicKey) ?? 0) > 1,
        },
      ];
    }),
  );
}

function compileLive(
  rows: SignerRow[],
  ownerThreshold: number,
  heirThreshold: number,
  ownerUnlock: string,
  heirUnlock: string,
  network: UiNetwork,
): LiveCompilation {
  const owners = rows.filter((row) => row.role === "owner");
  const heirs = rows.filter((row) => row.role === "heirs");

  if (owners.length === 0) {
    return { compiled: null, message: "Mark at least one key as Owner." };
  }
  if (heirs.length === 0) {
    return { compiled: null, message: "Mark at least one key as Heir." };
  }
  if (owners.length > MAX_KEYS_PER_ROLE || heirs.length > MAX_KEYS_PER_ROLE) {
    return { compiled: null, message: "Use no more than 10 keys in either path." };
  }

  const labels = rows.map((row) => row.label.trim().normalize("NFC"));
  const missingLabel = labels.findIndex((label) => !label);
  if (missingLabel !== -1) {
    return { compiled: null, message: `Name key ${missingLabel + 1}.` };
  }
  if (labels.some((label) => label.length > 80)) {
    return { compiled: null, message: "Keep every key label to 80 characters or fewer." };
  }
  if (new Set(labels.map((label) => label.toLocaleLowerCase("en-US"))).size !== labels.length) {
    return { compiled: null, message: "Use a unique label for every key." };
  }

  const publicKeys: string[] = [];
  for (let index = 0; index < rows.length; index += 1) {
    if (!rows[index].publicKey.trim()) {
      return {
        compiled: null,
        message: `Paste the compressed public key for ${labels[index]}.`,
      };
    }
    try {
      publicKeys.push(validateCompressedPublicKey(rows[index].publicKey));
    } catch {
      return {
        compiled: null,
        message: `Enter a valid 66-character compressed public key for ${labels[index]} (starting 02 or 03).`,
      };
    }
  }
  if (new Set(publicKeys).size !== publicKeys.length) {
    return { compiled: null, message: "Each public key can appear only once." };
  }

  const requestIdByPublicKey = new Map(
    [...publicKeys]
      .sort((left, right) => left.localeCompare(right))
      .map((publicKey, index) => [
        publicKey,
        `key-${String(index + 1).padStart(2, "0")}`,
      ]),
  );
  const requestIdByRowId = new Map(
    rows.map((row, index) => [
      row.id,
      requestIdByPublicKey.get(publicKeys[index]) as string,
    ]),
  );

  if (ownerThreshold < 1 || ownerThreshold > owners.length) {
    return { compiled: null, message: "Choose a valid Owner signature threshold." };
  }
  if (heirThreshold < 1 || heirThreshold > heirs.length) {
    return { compiled: null, message: "Choose a valid Heir signature threshold." };
  }

  let ownerUnix: number;
  let heirUnix: number;
  try {
    ownerUnix = unixFromComposerUtc(exactUtc(ownerUnlock));
    heirUnix = unixFromComposerUtc(exactUtc(heirUnlock));
  } catch (error) {
    return {
      compiled: null,
      message: error instanceof Error ? error.message : "Choose valid UTC unlock times.",
    };
  }
  if (ownerUnix >= heirUnix) {
    return { compiled: null, message: "Set the Owner time earlier than the Heir time." };
  }

  const keys = rows.map((row, index) => ({
    id: requestIdByRowId.get(row.id) as string,
    label: labels[index],
    public_key: publicKeys[index],
  }));
  const request: ComposerRequest = {
    format: "mimir-composer-request",
    version: 2,
    network,
    template_id: TEMPLATE_ID_V2,
    keys,
    owner: {
      key_ids: owners.map((row) => requestIdByRowId.get(row.id) as string),
      threshold: ownerThreshold,
      unlock_unix: ownerUnix,
    },
    heirs: {
      key_ids: heirs.map((row) => requestIdByRowId.get(row.id) as string),
      threshold: heirThreshold,
      unlock_unix: heirUnix,
    },
  };

  try {
    return { compiled: compileComposedPolicy(request), message: null };
  } catch (error) {
    return {
      compiled: null,
      message: error instanceof Error ? error.message : "The policy could not be compiled.",
    };
  }
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
        <CopyButton value={value} label={label} />
      </div>
      <code>{value}</code>
    </div>
  );
}

export default function Home() {
  const [rows, setRows] = useState<SignerRow[]>(initialRows);
  const [ownerThreshold, setOwnerThreshold] = useState(1);
  const [heirThreshold, setHeirThreshold] = useState(1);
  const [ownerUnlock, setOwnerUnlock] = useState(DEFAULT_OWNER_UNLOCK);
  const [heirUnlock, setHeirUnlock] = useState(DEFAULT_HEIR_UNLOCK);
  const [network, setNetwork] = useState<UiNetwork>("regtest");
  const nextSignerId = useRef(2);

  const ownerCount = rows.filter((row) => row.role === "owner").length;
  const heirCount = rows.filter((row) => row.role === "heirs").length;

  const live = useMemo(
    () =>
      compileLive(
        rows,
        ownerThreshold,
        heirThreshold,
        ownerUnlock,
        heirUnlock,
        network,
      ),
    [rows, ownerThreshold, heirThreshold, ownerUnlock, heirUnlock, network],
  );

  const placeholder = useMemo(
    () =>
      buildPlaceholder(
        ownerCount,
        heirCount,
        ownerThreshold,
        heirThreshold,
        ownerUnlock,
        heirUnlock,
      ),
    [ownerCount, heirCount, ownerThreshold, heirThreshold, ownerUnlock, heirUnlock],
  );
  const rowFieldStates = useMemo(() => validateRowFields(rows), [rows]);

  const policySentence =
    ownerCount === 0 || heirCount === 0
      ? "Add at least one Owner key and one Heir key to complete the recovery path."
      : `${ownerThreshold} of ${ownerCount} Owner ${ownerCount === 1 ? "key" : "keys"} may spend from ${shortUtc(ownerUnlock)}. ${heirThreshold} of ${heirCount} Heir ${heirCount === 1 ? "key" : "keys"} may also spend from ${shortUtc(heirUnlock)}. The Owner path stays available.`;

  function updateRow(id: string, patch: Partial<Omit<SignerRow, "id">>) {
    setRows((current) =>
      current.map((row) => (row.id === id ? { ...row, ...patch } : row)),
    );
  }

  function changeRole(id: string, role: Role) {
    const current = rows.find((row) => row.id === id);
    if (!current || current.role === role) return;
    const nextOwnerCount = ownerCount + (role === "owner" ? 1 : -1);
    const nextHeirCount = heirCount + (role === "heirs" ? 1 : -1);
    if (nextOwnerCount > MAX_KEYS_PER_ROLE || nextHeirCount > MAX_KEYS_PER_ROLE) return;
    updateRow(id, { role });
    setOwnerThreshold((value) => normalizedThreshold(value, nextOwnerCount));
    setHeirThreshold((value) => normalizedThreshold(value, nextHeirCount));
  }

  function addKey() {
    const nextRole: Role =
      heirCount < MAX_KEYS_PER_ROLE ? "heirs" : "owner";
    if (
      rows.length >= MAX_KEYS ||
      (heirCount >= MAX_KEYS_PER_ROLE && ownerCount >= MAX_KEYS_PER_ROLE)
    ) {
      return;
    }
    setRows((current) => [
      ...current,
      {
        id: `signer-${nextSignerId.current++}`,
        label: "",
        publicKey: "",
        role: nextRole,
      },
    ]);
    if (nextRole === "owner") {
      setOwnerThreshold((value) => normalizedThreshold(value, ownerCount + 1));
    } else {
      setHeirThreshold((value) => normalizedThreshold(value, heirCount + 1));
    }
  }

  function removeKey(id: string) {
    const removed = rows.find((row) => row.id === id);
    if (!removed) return;
    const nextOwnerCount = ownerCount - (removed.role === "owner" ? 1 : 0);
    const nextHeirCount = heirCount - (removed.role === "heirs" ? 1 : 0);
    setRows((current) => current.filter((row) => row.id !== id));
    setOwnerThreshold((value) => normalizedThreshold(value, nextOwnerCount));
    setHeirThreshold((value) => normalizedThreshold(value, nextHeirCount));
  }

  function reset() {
    if (!window.confirm("Clear every key and reset both rules? This cannot be undone.")) {
      return;
    }
    setRows(initialRows());
    nextSignerId.current = 2;
    setOwnerThreshold(1);
    setHeirThreshold(1);
    setOwnerUnlock(DEFAULT_OWNER_UNLOCK);
    setHeirUnlock(DEFAULT_HEIR_UNLOCK);
    setNetwork("regtest");
  }

  function downloadManifest() {
    if (!live.compiled) return;
    const contents = live.compiled.canonical_manifest;
    const blob = new Blob([contents], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `mimir-${live.compiled.request.network}-${live.compiled.policy_manifest_sha256.slice(0, 12)}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function changeNetwork(value: string) {
    if (value === "regtest" || value === "signet") {
      setNetwork(value);
    }
  }

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
              onChange={(event) => changeNetwork(event.currentTarget.value)}
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
        <section className="builder" aria-labelledby="keys-heading">
          <div className="section-heading">
            <div>
              <p className="section-number">01</p>
              <h2 id="keys-heading">Keys</h2>
              <p>Add the public keys that may spend.</p>
            </div>
            <span>{rows.length} / {MAX_KEYS}</span>
          </div>

          <div className="signer-list">
            {rows.map((row, index) => (
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
                    aria-invalid={rowFieldStates.get(row.id)?.labelInvalid || undefined}
                    aria-describedby={
                      rowFieldStates.get(row.id)?.labelInvalid
                        ? "policy-validation"
                        : undefined
                    }
                  />
                </label>
                <label className="key-field">
                  <span>Compressed public key</span>
                  <input
                    value={row.publicKey}
                    onChange={(event) => updateRow(row.id, { publicKey: event.target.value })}
                    placeholder="02 or 03 + 64 hex characters"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    inputMode="text"
                    aria-invalid={rowFieldStates.get(row.id)?.publicKeyInvalid || undefined}
                    aria-describedby={
                      rowFieldStates.get(row.id)?.publicKeyInvalid
                        ? "policy-validation"
                        : undefined
                    }
                  />
                </label>
                <fieldset className="role-toggle">
                  <legend>Path</legend>
                  <div>
                    <button
                      type="button"
                      className={row.role === "owner" ? "is-active" : ""}
                      onClick={() => changeRole(row.id, "owner")}
                      disabled={row.role !== "owner" && ownerCount >= MAX_KEYS_PER_ROLE}
                      aria-pressed={row.role === "owner"}
                      aria-label={`${row.label || `Key ${index + 1}`} uses the Owner path`}
                    >
                      Owner
                    </button>
                    <button
                      type="button"
                      className={row.role === "heirs" ? "is-active" : ""}
                      onClick={() => changeRole(row.id, "heirs")}
                      disabled={row.role !== "heirs" && heirCount >= MAX_KEYS_PER_ROLE}
                      aria-pressed={row.role === "heirs"}
                      aria-label={`${row.label || `Key ${index + 1}`} uses the Heir path`}
                    >
                      Heir
                    </button>
                  </div>
                </fieldset>
                <button
                  className="remove-button"
                  type="button"
                  onClick={() => removeKey(row.id)}
                  aria-label={`Remove ${row.label || `key ${index + 1}`}`}
                >
                  <Trash2 size={17} aria-hidden="true" />
                </button>
              </article>
            ))}
          </div>

          <button
            className="add-button"
            type="button"
            aria-label="ADD KEY"
            onClick={addKey}
            disabled={
              rows.length >= MAX_KEYS ||
              (heirCount >= MAX_KEYS_PER_ROLE && ownerCount >= MAX_KEYS_PER_ROLE)
            }
          >
            <Plus size={17} aria-hidden="true" />
            Add key
          </button>

          <section className="rules" aria-labelledby="rules-heading">
            <div className="section-heading compact">
              <div>
                <p className="section-number">02</p>
                <h2 id="rules-heading">Rules</h2>
              </div>
            </div>

            <div className="rule-row">
              <strong>Owner</strong>
              <span>needs</span>
              <label>
                <span className="sr-only">Owner signature threshold</span>
                <select
                  value={ownerCount === 0 ? 0 : ownerThreshold}
                  onChange={(event) => setOwnerThreshold(Number(event.target.value))}
                  disabled={ownerCount === 0}
                >
                  {ownerCount === 0 ? <option value={0}>—</option> : null}
                  {Array.from({ length: ownerCount }, (_, index) => (
                    <option value={index + 1} key={index + 1}>{index + 1}</option>
                  ))}
                </select>
              </label>
              <span>of {ownerCount} signatures after</span>
              <label className="date-control">
                <span className="sr-only">Owner unlock date and time in UTC</span>
                <input
                  type="datetime-local"
                  value={ownerUnlock}
                  onChange={(event) => setOwnerUnlock(event.target.value)}
                  max="2038-01-19T03:14"
                  step={60}
                />
              </label>
              <span>UTC</span>
            </div>

            <div className="rule-row">
              <strong>Heirs</strong>
              <span>need</span>
              <label>
                <span className="sr-only">Heir signature threshold</span>
                <select
                  value={heirCount === 0 ? 0 : heirThreshold}
                  onChange={(event) => setHeirThreshold(Number(event.target.value))}
                  disabled={heirCount === 0}
                >
                  {heirCount === 0 ? <option value={0}>—</option> : null}
                  {Array.from({ length: heirCount }, (_, index) => (
                    <option value={index + 1} key={index + 1}>{index + 1}</option>
                  ))}
                </select>
              </label>
              <span>of {heirCount} signatures after</span>
              <label className="date-control">
                <span className="sr-only">Heir unlock date and time in UTC</span>
                <input
                  type="datetime-local"
                  value={heirUnlock}
                  onChange={(event) => setHeirUnlock(event.target.value)}
                  max="2038-01-19T03:14"
                  step={60}
                />
              </label>
              <span>UTC</span>
            </div>

            <p className="utc-note">
              Times are interpreted exactly as UTC, not as your device timezone.
            </p>
          </section>

          {live.message ? (
            <p
              className="validation-message"
              id="policy-validation"
              role="status"
              aria-live="polite"
            >
              {live.message}
            </p>
          ) : (
            <p className="valid-message" role="status" aria-live="polite">
              Script valid · updates are compiled immediately
            </p>
          )}
        </section>

        <aside className="script-pane" aria-labelledby="script-heading">
          <header>
            <div>
              <p>Live output</p>
              <h2 id="script-heading">LIVE BITCOIN SCRIPT</h2>
            </div>
            <span>{live.compiled ? "Valid" : "Draft"}</span>
          </header>

          <section className="live-section policy-summary">
            <h3>Policy</h3>
            <p>{policySentence}</p>
          </section>

          <section className="live-section">
            <div className="live-label">
              <h3>{live.compiled ? "Miniscript" : "Policy skeleton"}</h3>
              {live.compiled ? (
                <CopyButton value={live.compiled.miniscript} label="Miniscript" />
              ) : null}
            </div>
            <code>{live.compiled?.miniscript ?? placeholder}</code>
          </section>

          <section className="live-section">
            <div className="live-label">
              <h3>Bitcoin Script (ASM)</h3>
              {live.compiled ? <CopyButton value={live.compiled.asm} label="Bitcoin Script ASM" /> : null}
            </div>
            <code>{live.compiled?.asm ?? "waiting for valid public keys"}</code>
          </section>

          {live.compiled ? (
            <section className="address-block">
              <div>
                <span>{network === "regtest" ? "Regtest" : "Signet"} P2WSH address</span>
                <CopyButton value={live.compiled.address} label="P2WSH address" />
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
                    <li>CLTV spends require a matching transaction nLockTime and a non-final input sequence.</li>
                  </ul>
                </div>

                <button className="download-button" type="button" onClick={downloadManifest}>
                  <Download size={16} aria-hidden="true" />
                  Download policy JSON
                </button>
              </div>
            ) : (
              <p className="technical-waiting">
                Descriptor, script hex, checks, warnings, and JSON appear when the policy is valid.
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
