"use client";

import {
  ArrowDown,
  ArrowRight,
  Braces,
  Check,
  CircleAlert,
  Clipboard,
  Download,
  GripVertical,
  KeyRound,
  LockKeyhole,
  Minus,
  Network,
  Plus,
  Radio,
  ShieldCheck,
  Terminal,
  Trash2,
  Users,
  X,
  Zap,
} from "lucide-react";
import {
  useMemo,
  useState,
  type DragEvent,
  type FormEvent,
} from "react";
import {
  TEMPLATE_ID_V2,
  compileComposedPolicy,
  unixFromComposerUtc,
  validateCompressedPublicKey,
  type CompiledComposerPolicy,
  type ComposerKey,
  type ComposerNetwork,
  type ComposerRequest,
} from "../lib/composer";

type Target = "owner" | "heirs";

const DEMO_KEYS: ComposerKey[] = [
  {
    id: "owner-alpha",
    label: "OWNER // ALPHA",
    public_key:
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  },
  {
    id: "owner-beta",
    label: "OWNER // BETA",
    public_key:
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  },
  {
    id: "heir-one",
    label: "HEIR // ONE",
    public_key:
      "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  },
  {
    id: "heir-two",
    label: "HEIR // TWO",
    public_key:
      "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
  },
  {
    id: "heir-three",
    label: "HEIR // THREE",
    public_key:
      "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
  },
  {
    id: "heir-four",
    label: "HEIR // FOUR",
    public_key:
      "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
  },
];

const DEFAULT_OWNER_UNLOCK = "2030-01-01T00:00:00Z";
const DEFAULT_HEIR_UNLOCK = "2035-01-01T00:00:00Z";

function shortKey(publicKey: string): string {
  return `${publicKey.slice(0, 12)}…${publicKey.slice(-10)}`;
}

function statusForKey(id: string, ownerIds: string[], heirIds: string[]) {
  if (ownerIds.includes(id)) return "OWNER";
  if (heirIds.includes(id)) return "HEIR";
  return "UNASSIGNED";
}

function clampThreshold(value: number, count: number): number {
  return Math.min(Math.max(1, value), Math.max(1, count));
}

function buildRequest(
  keys: ComposerKey[],
  ownerIds: string[],
  heirIds: string[],
  ownerThreshold: number,
  heirThreshold: number,
  ownerUnlock: string,
  heirUnlock: string,
  network: ComposerNetwork,
): ComposerRequest {
  return {
    format: "mimir-composer-request",
    version: 2,
    network,
    template_id: TEMPLATE_ID_V2,
    keys,
    owner: {
      key_ids: ownerIds,
      threshold: ownerThreshold,
      unlock_unix: unixFromComposerUtc(ownerUnlock),
    },
    heirs: {
      key_ids: heirIds,
      threshold: heirThreshold,
      unlock_unix: unixFromComposerUtc(heirUnlock),
    },
  };
}

function CopyButton({ value, name }: { value: string; name: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1_600);
    } catch {
      setCopied(false);
    }
  }

  return (
    <button className="copy-button" type="button" onClick={copy} aria-label={`Copy ${name}`}>
      {copied ? <Check size={14} /> : <Clipboard size={14} />}
      {copied ? "COPIED" : "COPY"}
    </button>
  );
}

function OutputDatum({
  label,
  value,
  accent = false,
  wide = false,
}: {
  label: string;
  value: string;
  accent?: boolean;
  wide?: boolean;
}) {
  return (
    <article className={`output-datum${accent ? " is-accent" : ""}${wide ? " is-wide" : ""}`}>
      <header>
        <span>{label}</span>
        <CopyButton value={value} name={label} />
      </header>
      <code>{value}</code>
    </article>
  );
}

function ThresholdControl({
  value,
  count,
  label,
  onChange,
}: {
  value: number;
  count: number;
  label: string;
  onChange: (value: number) => void;
}) {
  return (
    <div className="threshold-control" aria-label={`${label} signing threshold`}>
      <button
        type="button"
        onClick={() => onChange(clampThreshold(value - 1, count))}
        disabled={value <= 1}
        aria-label={`Decrease ${label} threshold`}
      >
        <Minus size={17} />
      </button>
      <div>
        <strong>{count ? value : 0}</strong>
        <span>OF</span>
        <strong>{count}</strong>
      </div>
      <button
        type="button"
        onClick={() => onChange(clampThreshold(value + 1, count))}
        disabled={count === 0 || value >= count}
        aria-label={`Increase ${label} threshold`}
      >
        <Plus size={17} />
      </button>
    </div>
  );
}

export default function Home() {
  const [keys, setKeys] = useState<ComposerKey[]>(DEMO_KEYS);
  const [ownerIds, setOwnerIds] = useState<string[]>([
    DEMO_KEYS[0].id,
    DEMO_KEYS[1].id,
  ]);
  const [heirIds, setHeirIds] = useState<string[]>(DEMO_KEYS.slice(2).map((key) => key.id));
  const [ownerThreshold, setOwnerThreshold] = useState(2);
  const [heirThreshold, setHeirThreshold] = useState(3);
  const [ownerUnlock, setOwnerUnlock] = useState(DEFAULT_OWNER_UNLOCK);
  const [heirUnlock, setHeirUnlock] = useState(DEFAULT_HEIR_UNLOCK);
  const [network, setNetwork] = useState<ComposerNetwork>("regtest");
  const [mainnetAcknowledged, setMainnetAcknowledged] = useState(false);
  const [activeTarget, setActiveTarget] = useState<Target>("heirs");
  const [labelInput, setLabelInput] = useState("");
  const [keyInput, setKeyInput] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [compileError, setCompileError] = useState<string | null>(null);
  const [compiled, setCompiled] = useState<CompiledComposerPolicy | null>(null);

  const keyById = useMemo(() => new Map(keys.map((key) => [key.id, key])), [keys]);
  const ownerKeys = ownerIds.flatMap((id) => (keyById.get(id) ? [keyById.get(id)!] : []));
  const heirKeys = heirIds.flatMap((id) => (keyById.get(id) ? [keyById.get(id)!] : []));

  function invalidate() {
    setCompiled(null);
    setCompileError(null);
  }

  function addKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    try {
      if (keys.length >= 20) throw new Error("Registry limit reached: 20 public keys.");
      const label = labelInput.trim().normalize("NFC");
      if (!label) throw new Error("Enter a signer label.");
      if (label.length > 80) throw new Error("Signer label cannot exceed 80 characters.");
      const publicKey = validateCompressedPublicKey(keyInput);
      if (keys.some((key) => key.label.toLowerCase() === label.toLowerCase())) {
        throw new Error("Signer labels must be unique.");
      }
      if (keys.some((key) => key.public_key === publicKey)) {
        throw new Error("That public key is already registered.");
      }
      const id = `key-${crypto.randomUUID()}`;
      const added = { id, label, public_key: publicKey };
      setKeys((current) => [...current, added]);
      assignKey(id, activeTarget, added);
      setLabelInput("");
      setKeyInput("");
      invalidate();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Could not add that public key.");
    }
  }

  function assignKey(id: string, target: Target, pendingKey?: ComposerKey) {
    const targetIds = target === "owner" ? ownerIds : heirIds;
    if (!pendingKey && targetIds.includes(id)) return;
    if (targetIds.length >= 10) {
      setFormError(`${target === "owner" ? "Owner" : "Heir"} group limit reached: 10 keys.`);
      return;
    }

    setOwnerIds((current) => {
      const next = current.filter((keyId) => keyId !== id);
      return target === "owner" ? [...next, id] : next;
    });
    setHeirIds((current) => {
      const next = current.filter((keyId) => keyId !== id);
      return target === "heirs" ? [...next, id] : next;
    });
    if (target === "owner") {
      const nextCount = ownerIds.includes(id) ? ownerIds.length : ownerIds.length + 1;
      setOwnerThreshold((current) => clampThreshold(current, nextCount));
      setHeirThreshold((current) => clampThreshold(current, heirIds.filter((keyId) => keyId !== id).length));
    } else {
      const nextCount = heirIds.includes(id) ? heirIds.length : heirIds.length + 1;
      setHeirThreshold((current) => clampThreshold(current, nextCount));
      setOwnerThreshold((current) => clampThreshold(current, ownerIds.filter((keyId) => keyId !== id).length));
    }
    setFormError(null);
    invalidate();
  }

  function unassignKey(id: string, target: Target) {
    if (target === "owner") {
      const next = ownerIds.filter((keyId) => keyId !== id);
      setOwnerIds(next);
      setOwnerThreshold((current) => clampThreshold(current, next.length));
    } else {
      const next = heirIds.filter((keyId) => keyId !== id);
      setHeirIds(next);
      setHeirThreshold((current) => clampThreshold(current, next.length));
    }
    invalidate();
  }

  function removeKey(id: string) {
    setKeys((current) => current.filter((key) => key.id !== id));
    const nextOwners = ownerIds.filter((keyId) => keyId !== id);
    const nextHeirs = heirIds.filter((keyId) => keyId !== id);
    setOwnerIds(nextOwners);
    setHeirIds(nextHeirs);
    setOwnerThreshold((current) => clampThreshold(current, nextOwners.length));
    setHeirThreshold((current) => clampThreshold(current, nextHeirs.length));
    invalidate();
  }

  function clearRegistry() {
    setKeys([]);
    setOwnerIds([]);
    setHeirIds([]);
    setOwnerThreshold(1);
    setHeirThreshold(1);
    setFormError(null);
    invalidate();
  }

  function dropOn(event: DragEvent<HTMLElement>, target: Target) {
    event.preventDefault();
    const id = event.dataTransfer.getData("text/mimir-key");
    if (id && keyById.has(id)) assignKey(id, target);
  }

  function compilePolicy() {
    setCompileError(null);
    try {
      if (network === "bitcoin" && !mainnetAcknowledged) {
        throw new Error("Acknowledge the mainnet preview warning before compiling.");
      }
      const request = buildRequest(
        keys,
        ownerIds,
        heirIds,
        ownerThreshold,
        heirThreshold,
        ownerUnlock,
        heirUnlock,
        network,
      );
      setCompiled(compileComposedPolicy(request));
      window.requestAnimationFrame(() => {
        document.getElementById("compiled-output")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch (error) {
      setCompiled(null);
      setCompileError(error instanceof Error ? error.message : "Policy compilation failed closed.");
    }
  }

  function downloadManifest() {
    if (!compiled) return;
    const blob = new Blob([`${JSON.stringify(compiled.manifest, null, 2)}\n`], {
      type: "application/json;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `mimir-${compiled.request.network}-${compiled.policy_manifest_sha256.slice(0, 12)}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function renderGroupPanel(target: Target) {
    const isOwner = target === "owner";
    const selectedKeys = isOwner ? ownerKeys : heirKeys;
    const threshold = isOwner ? ownerThreshold : heirThreshold;
    const setThreshold = isOwner ? setOwnerThreshold : setHeirThreshold;
    const unlock = isOwner ? ownerUnlock : heirUnlock;
    const setUnlock = isOwner ? setOwnerUnlock : setHeirUnlock;
    const title = isOwner ? "OWNER CONTROL" : "HEIR QUORUM";

    return (
      <section
        className={`group-panel ${target}${activeTarget === target ? " is-target" : ""}`}
        onDragOver={(event) => event.preventDefault()}
        onDrop={(event) => dropOn(event, target)}
        aria-labelledby={`${target}-heading`}
      >
        <header className="panel-heading">
          <div>
            {isOwner ? <ShieldCheck size={19} /> : <Users size={19} />}
            <div>
              <span className="eyebrow">BRANCH // {isOwner ? "01" : "02"}</span>
              <h2 id={`${target}-heading`}>{title}</h2>
            </div>
          </div>
          <button
            type="button"
            className={`target-button${activeTarget === target ? " is-active" : ""}`}
            onClick={() => setActiveTarget(target)}
          >
            {activeTarget === target ? <Radio size={14} /> : <Plus size={14} />}
            {activeTarget === target ? "ACTIVE DROP" : "SET TARGET"}
          </button>
        </header>

        <div className="group-controls">
          <ThresholdControl
            value={threshold}
            count={selectedKeys.length}
            label={isOwner ? "owner" : "heir"}
            onChange={(value) => {
              setThreshold(value);
              invalidate();
            }}
          />
          <label className="utc-field">
            <span>UNLOCK // UTC</span>
            <input
              value={unlock}
              onChange={(event) => {
                setUnlock(event.target.value);
                invalidate();
              }}
              inputMode="text"
              spellCheck={false}
              aria-label={`${title} unlock UTC`}
            />
          </label>
        </div>

        <div className="drop-zone">
          {selectedKeys.length === 0 ? (
            <div className="drop-empty">
              <ArrowDown size={20} />
              DROP OR CLICK A KEY
            </div>
          ) : (
            selectedKeys.map((key, index) => (
              <div className="assigned-key" key={key.id}>
                <span className="ordinal">{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{key.label}</strong>
                  <code>{shortKey(key.public_key)}</code>
                </div>
                <button
                  type="button"
                  onClick={() => unassignKey(key.id, target)}
                  aria-label={`Remove ${key.label} from ${title}`}
                >
                  <X size={15} />
                </button>
              </div>
            ))
          )}
        </div>
        <p className="branch-note">
          {isOwner
            ? "OWNER PATH NEVER EXPIRES AFTER ACTIVATION."
            : "HEIR PATH ACTIVATES LATER; OWNER REMAINS VALID."}
        </p>
      </section>
    );
  }

  return (
    <main>
      <header className="masthead">
        <div className="brand-mark" aria-hidden="true">
          <Terminal size={25} strokeWidth={1.5} />
        </div>
        <div className="brand-copy">
          <p className="system-line">SYS::MIMIR_V2 / STATUS::LOCAL_ONLY</p>
          <h1>MIMIR // POLICY TERMINAL</h1>
          <p className="subline">COMPOSE K-OF-N VAULTS · PUBLIC KEYS ONLY</p>
        </div>
        <div className="runtime-status">
          <span className="pulse" />
          OFFLINE CORE
        </div>
      </header>

      <section className="notice-strip" aria-label="Safety status">
        <span><LockKeyhole size={14} /> NO SECRETS</span>
        <span><Network size={14} /> NO NETWORK</span>
        <span><Braces size={14} /> DETERMINISTIC OUTPUT</span>
        <span className="amber"><CircleAlert size={14} /> PRE-MAINNET PREVIEW</span>
      </section>

      <div className="terminal-shell">
        <section className="registry-panel" aria-labelledby="registry-heading">
          <header className="section-heading">
            <div>
              <span className="section-index">01</span>
              <div>
                <p className="eyebrow">IDENTITY BUFFER</p>
                <h2 id="registry-heading">PUBLIC KEY REGISTRY</h2>
              </div>
            </div>
            <div className="registry-actions">
              <span className="capacity">{String(keys.length).padStart(2, "0")} / 20</span>
              <button type="button" onClick={clearRegistry} disabled={keys.length === 0}>
                <Trash2 size={13} /> CLEAR KEYRING
              </button>
            </div>
          </header>

          <form className="key-form" onSubmit={addKey}>
            <label>
              <span>SIGNER LABEL</span>
              <input
                value={labelInput}
                onChange={(event) => setLabelInput(event.target.value)}
                placeholder="E.G. HEIR // EAST"
                autoComplete="off"
              />
            </label>
            <label className="public-key-input">
              <span>COMPRESSED PUBLIC KEY // 66 HEX</span>
              <input
                value={keyInput}
                onChange={(event) => setKeyInput(event.target.value)}
                placeholder="02 OR 03 + 64 HEX CHARACTERS"
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <button className="add-key-button" type="submit">
              <Plus size={20} />
              ADD KEY
            </button>
          </form>
          {formError && <p className="inline-error"><CircleAlert size={15} /> {formError}</p>}

          <div className="target-switch" aria-label="Click assignment target">
            <span>CLICK TARGET</span>
            <button
              type="button"
              className={activeTarget === "owner" ? "is-active owner" : ""}
              onClick={() => setActiveTarget("owner")}
            >
              OWNER
            </button>
            <button
              type="button"
              className={activeTarget === "heirs" ? "is-active heirs" : ""}
              onClick={() => setActiveTarget("heirs")}
            >
              HEIRS
            </button>
          </div>

          <div className="key-grid">
            {keys.map((key) => {
              const status = statusForKey(key.id, ownerIds, heirIds);
              return (
                <article
                  className={`key-card ${status.toLowerCase()}`}
                  key={key.id}
                  draggable
                  role="button"
                  tabIndex={0}
                  onDragStart={(event) => {
                    event.dataTransfer.effectAllowed = "move";
                    event.dataTransfer.setData("text/mimir-key", key.id);
                  }}
                  onClick={() => assignKey(key.id, activeTarget)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      assignKey(key.id, activeTarget);
                    }
                  }}
                  aria-label={`${key.label}, assigned to ${status}. Click to move to ${activeTarget}.`}
                >
                  <GripVertical className="drag-handle" size={17} aria-hidden="true" />
                  <div className="key-card-body">
                    <div>
                      <KeyRound size={15} />
                      <strong>{key.label}</strong>
                    </div>
                    <code title={key.public_key}>{shortKey(key.public_key)}</code>
                    <span className="key-status">{status}</span>
                  </div>
                  <button
                    type="button"
                    className="delete-key"
                    onClick={(event) => {
                      event.stopPropagation();
                      removeKey(key.id);
                    }}
                    aria-label={`Delete ${key.label}`}
                  >
                    <Trash2 size={15} />
                  </button>
                </article>
              );
            })}
          </div>
          <p className="interaction-hint">
            <Zap size={14} /> CLICK A CARD TO ASSIGN IT TO THE ACTIVE TARGET, OR DRAG IT INTO A BRANCH.
          </p>
        </section>

        <section className="composer-panel" aria-labelledby="composer-heading">
          <header className="section-heading">
            <div>
              <span className="section-index">02</span>
              <div>
                <p className="eyebrow">POLICY GRAPH</p>
                <h2 id="composer-heading">COMPOSE BRANCHES</h2>
              </div>
            </div>
            <span className="template-id">{TEMPLATE_ID_V2}</span>
          </header>

          <div className="branch-grid">
            {renderGroupPanel("owner")}
            {renderGroupPanel("heirs")}
          </div>

          <div className="logic-flow" aria-label="Owner control OR heir quorum produces one P2WSH output">
            <div className="flow-source owner"><ShieldCheck size={18} /><span>OWNER CONTROL</span></div>
            <ArrowRight className="flow-arrow desktop arrow-one" size={21} />
            <ArrowDown className="flow-arrow mobile arrow-one" size={21} />
            <div className="or-node">OR</div>
            <ArrowRight className="flow-arrow desktop arrow-two" size={21} />
            <ArrowDown className="flow-arrow mobile arrow-two" size={21} />
            <div className="flow-sink"><LockKeyhole size={18} /><span>P2WSH VAULT</span></div>
            <div className="flow-source heirs"><Users size={18} /><span>HEIR QUORUM</span></div>
          </div>

          <div className="compile-console">
            <div className="network-picker">
              <span>CHAIN TARGET</span>
              {(["regtest", "signet", "bitcoin"] as ComposerNetwork[]).map((item) => (
                <button
                  key={item}
                  type="button"
                  className={network === item ? "is-active" : ""}
                  onClick={() => {
                    setNetwork(item);
                    setMainnetAcknowledged(false);
                    invalidate();
                  }}
                >
                  {item === "bitcoin" ? "MAINNET" : item.toUpperCase()}
                </button>
              ))}
            </div>

            {network === "bitcoin" && (
              <label className="mainnet-ack">
                <input
                  type="checkbox"
                  checked={mainnetAcknowledged}
                  onChange={(event) => {
                    setMainnetAcknowledged(event.target.checked);
                    invalidate();
                  }}
                />
                <span>
                  I UNDERSTAND THIS IS PRE-MAINNET PREVIEW SOFTWARE AND WILL INDEPENDENTLY VERIFY THE EXACT OUTPUT.
                </span>
              </label>
            )}

            <button className="compile-button" type="button" onClick={compilePolicy}>
              <Terminal size={20} />
              COMPILE POLICY
              <span>[ CTRL + INTENT ]</span>
            </button>
            {compileError && <p className="compile-error"><CircleAlert size={16} /> HALT: {compileError}</p>}
          </div>
        </section>

        <section className="output-panel" id="compiled-output" aria-labelledby="output-heading">
          <header className="section-heading">
            <div>
              <span className="section-index">03</span>
              <div>
                <p className="eyebrow">DETERMINISTIC BUILD</p>
                <h2 id="output-heading">COMPILED OUTPUT</h2>
              </div>
            </div>
            <span className={`compile-state${compiled ? " is-ready" : ""}`}>
              <span /> {compiled ? "VALID // READY" : "AWAITING COMPILE"}
            </span>
          </header>

          {!compiled ? (
            <div className="empty-output">
              <Terminal size={38} strokeWidth={1.2} />
              <p>&gt; POLICY BUFFER EMPTY_</p>
              <span>ASSIGN KEYS, SET QUORUMS, THEN EXECUTE COMPILE POLICY.</span>
            </div>
          ) : (
            <div className="compiled-content">
              <div className="output-summary">
                <div>
                  <span>NETWORK</span>
                  <strong>{compiled.request.network.toUpperCase()}</strong>
                </div>
                <div>
                  <span>OWNER</span>
                  <strong>{compiled.request.owner.threshold}-OF-{compiled.request.owner.key_ids.length}</strong>
                </div>
                <div>
                  <span>HEIRS</span>
                  <strong>{compiled.request.heirs.threshold}-OF-{compiled.request.heirs.key_ids.length}</strong>
                </div>
                <div>
                  <span>SCRIPT</span>
                  <strong>{compiled.witness_script_bytes} BYTES</strong>
                </div>
              </div>

              <div className="output-grid">
                <OutputDatum label="P2WSH ADDRESS" value={compiled.address} accent wide />
                <OutputDatum label="MINISCRIPT" value={compiled.miniscript} wide />
                <OutputDatum label="CHECKSUMMED DESCRIPTOR" value={compiled.descriptor} wide />
                <OutputDatum label="SCRIPT ASM" value={compiled.asm} wide />
                <OutputDatum label="WITNESS SCRIPT // HEX" value={compiled.witness_script_hex} />
                <OutputDatum label="SCRIPTPUBKEY // HEX" value={compiled.script_pubkey_hex} />
                <OutputDatum label="POLICY MANIFEST // SHA256" value={compiled.policy_manifest_sha256} wide />
              </div>

              <div className="diagnostic-grid">
                <section className="invariant-list">
                  <h3><ShieldCheck size={16} /> INVARIANTS // {compiled.invariants.length}/{compiled.invariants.length}</h3>
                  {compiled.invariants.map((invariant) => (
                    <p key={invariant.id}>
                      <Check size={14} />
                      <span>{invariant.label}</span>
                    </p>
                  ))}
                </section>
                <section className="warning-list">
                  <h3><CircleAlert size={16} /> OPERATOR WARNINGS</h3>
                  {compiled.warnings.map((warning) => (
                    <p key={warning}>
                      <span>!</span>
                      {warning}
                    </p>
                  ))}
                </section>
              </div>

              <div className="export-bar">
                <div>
                  <p>CANONICAL POLICY MANIFEST</p>
                  <span>JSON · PUBLIC DATA · REPRODUCIBLE HASH</span>
                </div>
                <button type="button" onClick={downloadManifest}>
                  <Download size={17} /> DOWNLOAD JSON
                </button>
              </div>
            </div>
          )}
        </section>
      </div>

      <footer>
        <div>
          <span>MIMIR_V2::PUBLIC_POLICY_COMPILER</span>
          <span>NO STORAGE // NO ANALYTICS // NO OUTBOUND REQUESTS</span>
        </div>
        <p>
          <CircleAlert size={14} /> PRE-MAINNET SOFTWARE. REHEARSE ON REGTEST OR SIGNET AND VERIFY WITH BITCOIN CORE BEFORE FUNDING.
        </p>
      </footer>
    </main>
  );
}
