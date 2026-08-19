"use client";

import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Binary,
  Box,
  CalendarClock,
  Check,
  CheckCircle2,
  Circle,
  CircleCheck,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileCheck2,
  FileJson,
  Info,
  KeyRound,
  Landmark,
  LockKeyhole,
  Printer,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  WifiOff,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  buildVaultBundle,
  compilePolicy,
  createCapsule,
  networkLabel,
  runStaticSelfTests,
  secretLikeReason,
  unixFromUtcInput,
  type CapsuleResult,
  type CompiledPolicy,
  type NetworkName,
  type PolicyRequest,
  type VaultBundle,
} from "../lib/mimir";

const DEMO = {
  network: "regtest" as NetworkName,
  owner: {
    fingerprint: "5a3469b6",
    origin: "m/48'/1'/0'/2'",
    xpub:
      "tpubDEhFJsryccF9b2PaR3mgUBVfoYbpVaXsmpK6sonC8cysYcpJzYsZfiwkR9JaoiNWCT9o1HN2bFccb2wMnAXGdKpW6nYQukZMZXfF32RnS6y",
  },
  heir: {
    fingerprint: "1de75e0e",
    origin: "m/48'/1'/0'/2'",
    xpub:
      "tpubDEWZ8YQw72Yqbfmhw1g1Xnh6jt41X9vRk7UHmrKkRUWTye9P7R9ZdF894Yn1odHU7FgRPTYxL5dZHafRpbiHVNwyuxJt6pMA37SNWpvwYhX",
  },
  ownerUtc: "2030-01-01T00:00:00Z",
  heirUtc: "2035-01-01T00:00:00Z",
};

const STEPS = [
  { eyebrow: "Vault", title: "Set the boundary", short: "Network & policy", icon: LockKeyhole },
  { eyebrow: "Participants", title: "Add public identities", short: "Owner & heir", icon: KeyRound },
  { eyebrow: "Timeline", title: "Fix the unlock dates", short: "Absolute UTC locks", icon: CalendarClock },
  { eyebrow: "Review", title: "Verify the artifacts", short: "Export & compare", icon: FileCheck2 },
] as const;

const NETWORK_OPTIONS: Array<{
  id: NetworkName;
  name: string;
  detail: string;
  tone: string;
}> = [
  { id: "regtest", name: "Regtest", detail: "Local rehearsal", tone: "Recommended first" },
  { id: "signet", name: "Signet", detail: "Public test network", tone: "Rehearsal" },
  { id: "bitcoin", name: "Mainnet", detail: "Real bitcoin", tone: "Preview locked" },
];

type ParticipantForm = { fingerprint: string; origin: string; xpub: string };
type ReviewTab = "summary" | "artifacts" | "verify";

function shortHash(value: string, head = 10, tail = 8) {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function daysBetween(a: number, b: number) {
  return Math.round((b - a) / 86_400);
}

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function downloadText(filename: string, content: string, type = "text/plain") {
  downloadBlob(filename, new Blob([content], { type }));
}

function ValueBlock({
  label,
  value,
  onCopy,
  accent = false,
}: {
  label: string;
  value: string;
  onCopy: (value: string, label: string) => void;
  accent?: boolean;
}) {
  return (
    <div className={`value-block ${accent ? "value-block-accent" : ""}`}>
      <div className="value-block-head">
        <span>{label}</span>
        <button
          className="icon-button"
          type="button"
          onClick={() => onCopy(value, label)}
          aria-label={`Copy ${label}`}
        >
          <Copy size={15} aria-hidden="true" />
        </button>
      </div>
      <code>{value}</code>
    </div>
  );
}

function ParticipantCard({
  role,
  data,
  onChange,
  revealed,
  onReveal,
}: {
  role: "Owner" | "Heir";
  data: ParticipantForm;
  onChange: (next: ParticipantForm) => void;
  revealed: boolean;
  onReveal: () => void;
}) {
  const secretWarning = secretLikeReason(data.xpub);
  const isOwner = role === "Owner";
  return (
    <article className={`participant-card ${isOwner ? "owner" : "heir"}`}>
      <header className="participant-head">
        <div className="role-mark">{isOwner ? "01" : "02"}</div>
        <div>
          <span className="mini-label">{role.toUpperCase()}</span>
          <h3>{isOwner ? "Primary recovery path" : "Inheritance path"}</h3>
        </div>
        <span className="public-pill">PUBLIC ONLY</span>
      </header>

      <div className="field-grid compact-grid">
        <label className="field">
          <span>Master fingerprint</span>
          <input
            value={data.fingerprint}
            maxLength={8}
            spellCheck={false}
            autoComplete="off"
            placeholder="8 hex characters"
            onChange={(event) => onChange({ ...data, fingerprint: event.target.value })}
          />
          <small>Exactly 8 lowercase hex characters</small>
        </label>
        <label className="field">
          <span>Account origin</span>
          <input
            value={data.origin}
            spellCheck={false}
            autoComplete="off"
            placeholder="m/48'/1'/0'/2'"
            onChange={(event) => onChange({ ...data, origin: event.target.value })}
          />
          <small>Canonical path from the master key</small>
        </label>
      </div>

      <label className={`field xpub-field ${secretWarning ? "field-error" : ""}`}>
        <span>Account extended public key</span>
        <div className="input-with-action">
          <input
            value={data.xpub}
            type={revealed ? "text" : "password"}
            spellCheck={false}
            autoComplete="off"
            placeholder="tpub… or xpub…"
            onChange={(event) => onChange({ ...data, xpub: event.target.value })}
          />
          <button
            type="button"
            onClick={onReveal}
            aria-label={`${revealed ? "Hide" : "Show"} ${role.toLowerCase()} xpub`}
          >
            {revealed ? <EyeOff size={17} /> : <Eye size={17} />}
          </button>
        </div>
        {secretWarning ? (
          <small className="error-copy">
            <AlertTriangle size={13} /> Looks like a {secretWarning}. Remove it now.
          </small>
        ) : (
          <small>Full value remains available for final review</small>
        )}
      </label>

      <footer className="participant-foot">
        <span>Vault child</span>
        <code>/0/0</code>
        <span className="grow" />
        <span>Maps to</span>
        <strong>{isOwner ? "@0" : "@1"}</strong>
      </footer>
    </article>
  );
}

export default function Home() {
  const [step, setStep] = useState(0);
  const [network, setNetwork] = useState<NetworkName>(DEMO.network);
  const [mainnetAttested, setMainnetAttested] = useState(false);
  const [owner, setOwner] = useState<ParticipantForm>(DEMO.owner);
  const [heir, setHeir] = useState<ParticipantForm>(DEMO.heir);
  const [ownerRevealed, setOwnerRevealed] = useState(true);
  const [heirRevealed, setHeirRevealed] = useState(true);
  const [ownerUtc, setOwnerUtc] = useState(DEMO.ownerUtc);
  const [heirUtc, setHeirUtc] = useState(DEMO.heirUtc);
  const [note, setNote] = useState("");
  const [compiled, setCompiled] = useState<CompiledPolicy | null>(null);
  const [capsule, setCapsule] = useState<CapsuleResult | null>(null);
  const [bundle, setBundle] = useState<VaultBundle | null>(null);
  const [compileError, setCompileError] = useState<string | null>(null);
  const [compiling, setCompiling] = useState(false);
  const [bundleExported, setBundleExported] = useState(false);
  const [backupAcknowledged, setBackupAcknowledged] = useState(false);
  const [reviewTab, setReviewTab] = useState<ReviewTab>("summary");
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);
  const [coreDescriptor, setCoreDescriptor] = useState("");
  const [coreAddress, setCoreAddress] = useState("");
  const [coreVersion, setCoreVersion] = useState("");
  const [coreCheckAttempted, setCoreCheckAttempted] = useState(false);

  const staticTests = useMemo(() => runStaticSelfTests(), []);
  const staticTestsPass = staticTests.every((test) => test.ok);

  const parsedDates = useMemo(() => {
    try {
      const ownerUnix = unixFromUtcInput(ownerUtc);
      const heirUnix = unixFromUtcInput(heirUtc);
      return {
        ownerUnix,
        heirUnix,
        error:
          ownerUnix < heirUnix
            ? null
            : "Owner unlock must be strictly earlier than heir unlock.",
      };
    } catch (error) {
      return {
        ownerUnix: null,
        heirUnix: null,
        error: error instanceof Error ? error.message : "Invalid UTC date.",
      };
    }
  }, [ownerUtc, heirUtc]);

  const coreVerified = Boolean(
    compiled &&
      coreDescriptor === compiled.manifest.descriptor.fixed &&
      coreAddress === compiled.manifest.address &&
      coreVersion.length > 0,
  );

  const formComplete =
    owner.fingerprint.length > 0 &&
    owner.origin.length > 0 &&
    owner.xpub.length > 0 &&
    heir.fingerprint.length > 0 &&
    heir.origin.length > 0 &&
    heir.xpub.length > 0 &&
    !secretLikeReason(owner.xpub) &&
    !secretLikeReason(heir.xpub);

  function invalidate() {
    setCompiled(null);
    setCapsule(null);
    setBundle(null);
    setBundleExported(false);
    setBackupAcknowledged(false);
    setCoreDescriptor("");
    setCoreAddress("");
    setCoreVersion("");
    setCoreCheckAttempted(false);
    setCompileError(null);
  }

  function updateNetwork(next: NetworkName) {
    invalidate();
    setNetwork(next);
    if (next !== "bitcoin") setMainnetAttested(false);
  }

  function loadDemo() {
    invalidate();
    setNetwork(DEMO.network);
    setOwner(DEMO.owner);
    setHeir(DEMO.heir);
    setOwnerUtc(DEMO.ownerUtc);
    setHeirUtc(DEMO.heirUtc);
    setNote("");
    setMainnetAttested(false);
    setOwnerRevealed(true);
    setHeirRevealed(true);
    setStep(0);
  }

  function requestFromForm(): PolicyRequest {
    return {
      format: "mimir-policy-request",
      version: 1,
      network,
      template_id: "mimir-absolute-two-path-v1",
      vault_derivation: { branch: 0, index: 0 },
      participants: [
        {
          role: "owner",
          master_fingerprint: owner.fingerprint,
          origin_path: owner.origin,
          xpub: owner.xpub,
        },
        {
          role: "heir",
          master_fingerprint: heir.fingerprint,
          origin_path: heir.origin,
          xpub: heir.xpub,
        },
      ],
      locks: {
        owner_unix: unixFromUtcInput(ownerUtc),
        heir_unix: unixFromUtcInput(heirUtc),
      },
    };
  }

  async function compileFromForm() {
    setCompiling(true);
    setCompileError(null);
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    try {
      if (!staticTestsPass) throw new Error("A built-in compiler self-test failed.");
      if (network === "bitcoin" && !mainnetAttested) {
        throw new Error("Acknowledge the mainnet preview guardrail before compiling.");
      }
      const nextCompiled = compilePolicy(requestFromForm());
      const nextCapsule = createCapsule(nextCompiled, note);
      const nextBundle = buildVaultBundle(nextCompiled, nextCapsule);
      setCompiled(nextCompiled);
      setCapsule(nextCapsule);
      setBundle(nextBundle);
      setBundleExported(false);
      setBackupAcknowledged(false);
      setCoreCheckAttempted(false);
      setReviewTab("summary");
      setStep(3);
    } catch (error) {
      setCompileError(
        error instanceof Error ? error.message : "Policy compilation failed closed.",
      );
    } finally {
      setCompiling(false);
    }
  }

  async function nextStep() {
    if (step < 2) {
      setStep((current) => current + 1);
      return;
    }
    if (step === 2) await compileFromForm();
  }

  function copyValue(value: string, label: string) {
    void navigator.clipboard.writeText(value).then(() => {
      setCopiedLabel(label);
      window.setTimeout(() => setCopiedLabel(null), 1600);
    });
  }

  function exportBundle() {
    if (!bundle || !compiled) return;
    downloadText(
      `mimir-${compiled.policy_manifest_sha256.slice(0, 12)}-vault-bundle.json`,
      `${JSON.stringify(bundle, null, 2)}\n`,
      "application/json",
    );
    setBundleExported(true);
  }

  function exportCapsule() {
    if (!capsule || !compiled) return;
    downloadBlob(
      `mimir-${compiled.policy_manifest_sha256.slice(0, 12)}-recovery-capsule.bip138`,
      new Blob([capsule.raw_bytes as BlobPart], { type: "application/octet-stream" }),
    );
  }

  const canContinue =
    (step === 0 && (network !== "bitcoin" || mainnetAttested)) ||
    (step === 1 && formComplete) ||
    (step === 2 && !parsedDates.error && !secretLikeReason(note));

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Mimir home">
          <span className="brand-mark" aria-hidden="true">M</span>
          <span>
            <strong>MIMIR</strong>
            <small>VAULT POLICY COMPILER</small>
          </span>
        </a>
        <div className="top-status">
          <span className="status-chip offline"><WifiOff size={14} /> No network access</span>
          <span className="status-chip preview"><ShieldAlert size={14} /> Pre-mainnet preview</span>
          <button className="quiet-button" type="button" onClick={loadDemo}>
            <RefreshCw size={15} /> Reset demo
          </button>
        </div>
      </header>

      <div className="workspace" id="top">
        <aside className="step-rail">
          <div className="rail-intro">
            <span className="eyebrow">ONE FROZEN POLICY</span>
            <h1>A vault that outlives the app.</h1>
            <p>
              Compile public recovery artifacts. Bitcoin Core remains the source of
              truth for verification, funding, and spending.
            </p>
          </div>
          <nav className="steps" aria-label="Policy creation steps">
            {STEPS.map((item, index) => {
              const Icon = item.icon;
              const active = step === index;
              const complete = step > index || (index === 3 && Boolean(compiled));
              return (
                <button
                  key={item.eyebrow}
                  type="button"
                  className={`step-button ${active ? "active" : ""} ${complete ? "complete" : ""}`}
                  onClick={() => {
                    if (index <= step || (index === 3 && compiled)) setStep(index);
                  }}
                  disabled={index > step && !(index === 3 && compiled)}
                  aria-current={active ? "step" : undefined}
                >
                  <span className="step-icon">
                    {complete && !active ? <Check size={17} /> : <Icon size={17} />}
                  </span>
                  <span><small>0{index + 1}</small><strong>{item.short}</strong></span>
                </button>
              );
            })}
          </nav>
          <div className="rail-boundary">
            <ShieldCheck size={18} />
            <div><strong>Public data only</strong><span>No seeds. No signing. No transactions.</span></div>
          </div>
        </aside>

        <section className="main-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">STEP 0{step + 1} · {STEPS[step].eyebrow.toUpperCase()}</span>
              <h2>{STEPS[step].title}</h2>
            </div>
            <div className="profile-stamp"><span>PROFILE</span><strong>ABSOLUTE · 2 PATH · V1</strong></div>
          </div>

          {compileError && (
            <div className="fatal-banner" role="alert">
              <AlertTriangle size={19} />
              <div><strong>Compilation stopped</strong><span>{compileError}</span></div>
            </div>
          )}

          {step === 0 && (
            <div className="step-content vault-step">
              <section className="hero-copy">
                <span className="hero-kicker"><span /> IMMUTABLE RECOVERY FOUNDATION</span>
                <h3>Two keys. Two dates.<br /><em>One exact script.</em></h3>
                <p>
                  The owner unlocks first. The heir unlocks later. No emergency branch,
                  no account, and no private material ever enters Mimir.
                </p>
              </section>

              <section className="network-section" aria-labelledby="network-title">
                <div className="section-title-row">
                  <div><span className="mini-label">NETWORK</span><h3 id="network-title">Where will the address be used?</h3></div>
                  <span className="required-label">REQUIRED</span>
                </div>
                <div className="network-options">
                  {NETWORK_OPTIONS.map((option) => (
                    <button
                      key={option.id}
                      className={`network-card ${network === option.id ? "selected" : ""}`}
                      type="button"
                      onClick={() => updateNetwork(option.id)}
                      aria-pressed={network === option.id}
                    >
                      <span className="network-radio">
                        {network === option.id ? <CircleCheck size={18} /> : <Circle size={18} />}
                      </span>
                      <strong>{option.name}</strong><span>{option.detail}</span><small>{option.tone}</small>
                    </button>
                  ))}
                </div>
              </section>

              <section className="policy-card">
                <div className="policy-card-head">
                  <div className="policy-glyph" aria-hidden="true"><span /><span /></div>
                  <div><span className="mini-label">FROZEN TEMPLATE</span><h3>Absolute two-path recovery</h3></div>
                  <span className="fixed-pill">FIXED</span>
                </div>
                <div className="policy-paths">
                  <div><span className="path-dot owner-dot" /><strong>Owner</strong><small>after T_OWNER + signature</small></div>
                  <div className="path-or">OR</div>
                  <div><span className="path-dot heir-dot" /><strong>Heir</strong><small>after T_HEIR + signature</small></div>
                </div>
                <code className="policy-code">
                  wsh(or_i(and_v(v:after(T_OWNER),pk(@0)), and_v(v:after(T_HEIR),pk(@1))))
                </code>
              </section>

              {network === "bitcoin" && (
                <label className="attestation danger-attestation">
                  <input type="checkbox" checked={mainnetAttested} onChange={(event) => setMainnetAttested(event.target.checked)} />
                  <span className="custom-checkbox"><Check size={14} /></span>
                  <span>
                    <strong>I understand this is not a mainnet-ready release.</strong>
                    <small>I will rehearse first and independently reproduce every artifact in Bitcoin Core before funding.</small>
                  </span>
                </label>
              )}

              <div className="boundary-strip">
                <ShieldCheck size={20} />
                <div><strong>Mimir never needs private keys.</strong><span>Do not enter a seed, mnemonic, passphrase, xprv, WIF, or PIN.</span></div>
                <span className="self-test-badge">
                  {staticTestsPass ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
                  {staticTestsPass ? `${staticTests.length} self-tests pass` : "Self-test failure"}
                </span>
              </div>
            </div>
          )}

          {step === 1 && (
            <div className="step-content participants-step">
              <div className="intro-row">
                <p>
                  Use a dedicated account xpub for each role. Mimir validates the
                  serialized public key, network, origin depth, and fixed public child.
                </p>
                <button className="text-button" type="button" onClick={loadDemo}>Load regtest example</button>
              </div>
              <ParticipantCard
                role="Owner"
                data={owner}
                revealed={ownerRevealed}
                onReveal={() => setOwnerRevealed((value) => !value)}
                onChange={(next) => { invalidate(); setOwner(next); }}
              />
              <ParticipantCard
                role="Heir"
                data={heir}
                revealed={heirRevealed}
                onReveal={() => setHeirRevealed((value) => !value)}
                onChange={(next) => { invalidate(); setHeir(next); }}
              />
              <div className="info-banner">
                <Info size={18} />
                <p>
                  <strong>Mimir cannot prove key provenance.</strong> Confirm each
                  fingerprint, origin, and xpub on its source wallet or hardware display.
                  Reusing an ordinary wallet xpub can reveal capsule metadata to services that already know it.
                </p>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="step-content timeline-step">
              <div className="date-card-grid">
                <label className="date-card owner-date">
                  <span className="date-index">01</span><span className="mini-label">OWNER UNLOCK · UTC</span>
                  <input value={ownerUtc} spellCheck={false} autoComplete="off" onChange={(event) => { invalidate(); setOwnerUtc(event.target.value); }} />
                  <span className="unix-row"><span>UNIX</span><code>{parsedDates.ownerUnix ?? "—"}</code></span>
                  <small>Earliest time the owner path can satisfy CLTV.</small>
                </label>
                <label className="date-card heir-date">
                  <span className="date-index">02</span><span className="mini-label">HEIR UNLOCK · UTC</span>
                  <input value={heirUtc} spellCheck={false} autoComplete="off" onChange={(event) => { invalidate(); setHeirUtc(event.target.value); }} />
                  <span className="unix-row"><span>UNIX</span><code>{parsedDates.heirUnix ?? "—"}</code></span>
                  <small>After this date, owner or heir may recover.</small>
                </label>
              </div>

              <div className="format-hint">
                Enter exact whole-second UTC values as <code>YYYY-MM-DDTHH:MM:SSZ</code>.
                Mimir does not round or adjust dates. The template’s last possible date is 2038-01-19T03:14:07Z.
              </div>

              {parsedDates.error ? (
                <div className="inline-error" role="alert"><AlertTriangle size={17} /> {parsedDates.error}</div>
              ) : (
                <section className="timeline-visual" aria-label="Vault spending timeline">
                  <div className="timeline-track">
                    <span className="track-segment locked" /><span className="track-segment owner-window" /><span className="track-segment open-window" />
                    <span className="track-node owner-node" /><span className="track-node heir-node" />
                  </div>
                  <div className="timeline-labels">
                    <div><small>BEFORE OWNER</small><strong>Nobody can spend</strong></div>
                    <div><small>OWNER WINDOW · {daysBetween(parsedDates.ownerUnix!, parsedDates.heirUnix!)} DAYS</small><strong>Owner only</strong></div>
                    <div><small>AFTER HEIR</small><strong>Owner or heir</strong></div>
                  </div>
                </section>
              )}

              <label className={`field note-field ${secretLikeReason(note) ? "field-error" : ""}`}>
                <span>Optional encrypted recovery note <small>PUBLIC METADATA ONLY</small></span>
                <textarea
                  value={note}
                  maxLength={1000}
                  placeholder="Example: Contact the executor named in the physical recovery package."
                  onChange={(event) => { invalidate(); setNote(event.target.value); }}
                />
                <span className="field-meta">
                  {secretLikeReason(note) ? (
                    <span className="error-copy"><AlertTriangle size={13} /> Remove {secretLikeReason(note)}.</span>
                  ) : (
                    <span>No seeds, passphrases, private keys, PINs, or credentials.</span>
                  )}
                  <span>{new TextEncoder().encode(note).length}/1000 bytes</span>
                </span>
              </label>

              <div className="warning-grid">
                <div><AlertTriangle size={18} /><p><strong>Bitcoin uses median time past.</strong> Eligibility may arrive later than the displayed wall-clock instant.</p></div>
                <div><RefreshCw size={18} /><p><strong>Deposits do not restart the clock.</strong> Every later deposit inherits these exact absolute dates.</p></div>
              </div>
            </div>
          )}

          {step === 3 && compiled && capsule && bundle && (
            <div className="step-content review-step">
              <div className="review-status-row">
                <div className="review-status-copy">
                  <span className="status-orb"><Check size={16} /></span>
                  <div><span className="mini-label">POLICY COMPILED</span><h3>{networkLabel(compiled.manifest.network)}</h3></div>
                </div>
                <div className="review-badges">
                  <span className="badge warning-badge">UNVERIFIED</span>
                  <span className="badge plain-badge">/0/0 FIXED</span>
                  <span className="badge plain-badge">{bundle.artifacts.length} ARTIFACTS</span>
                </div>
              </div>

              <div className="review-tabs" role="tablist" aria-label="Compiled policy review">
                {([
                  ["summary", "Summary"],
                  ["artifacts", "Critical artifacts"],
                  ["verify", "Core verification"],
                ] as Array<[ReviewTab, string]>).map(([id, label]) => (
                  <button key={id} role="tab" aria-selected={reviewTab === id} className={reviewTab === id ? "active" : ""} type="button" onClick={() => setReviewTab(id)}>
                    {label}
                  </button>
                ))}
              </div>

              {reviewTab === "summary" && (
                <div className="review-pane summary-pane" role="tabpanel">
                  <section className="address-card">
                    <div className="address-card-head">
                      <span>VAULT ADDRESS · {compiled.manifest.network.toUpperCase()}</span>
                      <span className={coreVerified ? "verified-label" : "unverified-label"}>
                        {coreVerified ? <CheckCircle2 size={14} /> : <ShieldAlert size={14} />}
                        {coreVerified ? "CORE MATCHED" : "UNVERIFIED"}
                      </span>
                    </div>
                    <div className="address-value">
                      <code>{compiled.manifest.address}</code>
                      <button type="button" onClick={() => copyValue(compiled.manifest.address, "Vault address")} aria-label="Copy vault address">
                        {copiedLabel === "Vault address" ? <Check size={18} /> : <Copy size={18} />}
                      </button>
                    </div>
                    <p>Do not treat this address as fundable until the bundle is exported and Bitcoin Core reproduces it exactly.</p>
                  </section>

                  <section className="compiled-timeline">
                    <div className="timeline-mini-column">
                      <span className="timeline-mini-node locked-mini" /><span className="timeline-mini-line" />
                      <span className="timeline-mini-node owner-mini" /><span className="timeline-mini-line" />
                      <span className="timeline-mini-node heir-mini" />
                    </div>
                    <div className="compiled-events">
                      <div><small>BEFORE {compiled.manifest.locks.owner.utc}</small><strong>Nobody can spend</strong></div>
                      <div><small>{compiled.manifest.locks.owner.utc} · {compiled.manifest.locks.owner.unix}</small><strong>Owner path opens</strong></div>
                      <div><small>{compiled.manifest.locks.heir.utc} · {compiled.manifest.locks.heir.unix}</small><strong>Heir path opens; owner remains valid</strong></div>
                    </div>
                  </section>

                  <div className="metric-grid">
                    <div><span className="metric-icon"><Binary size={17} /></span><span>Witness program</span><code>{shortHash(compiled.manifest.script.witness_program_sha256, 12, 10)}</code></div>
                    <div><span className="metric-icon"><FileJson size={17} /></span><span>Policy manifest</span><code>{shortHash(compiled.policy_manifest_sha256, 12, 10)}</code></div>
                    <div><span className="metric-icon"><Box size={17} /></span><span>Capsule</span><code>{capsule.byte_length.toLocaleString()} bytes · {shortHash(capsule.capsule_sha256, 8, 6)}</code></div>
                  </div>

                  <section className="check-section">
                    <div className="section-title-row">
                      <div><span className="mini-label">INTERNAL CONSISTENCY</span><h3>{compiled.invariants.length + staticTests.length + 1} checks passed</h3></div>
                      <span className="pass-pill"><CheckCircle2 size={15} /> PASS</span>
                    </div>
                    <div className="check-list">
                      {[...staticTests, ...compiled.invariants].map((item) => (
                        <div key={item.id}><Check size={14} /><span>{item.label}</span></div>
                      ))}
                      <div><Check size={14} /><span>Owner and heir decrypt the generated BIP 138 capsule</span></div>
                    </div>
                  </section>

                  <div className="warning-stack">
                    {compiled.warnings.map((warning) => (
                      <div key={warning}><AlertTriangle size={16} /><span>{warning}</span></div>
                    ))}
                    <div><Landmark size={16} /><span>Capsule OP_RETURN is {capsule.op_return_script_byte_length.toLocaleString()} script bytes. Relay policy and fees vary; test the final signed transaction on your intended node.</span></div>
                  </div>
                </div>
              )}

              {reviewTab === "artifacts" && (
                <div className="review-pane artifacts-pane" role="tabpanel">
                  <ValueBlock label="Fixed checksummed descriptor" value={compiled.manifest.descriptor.fixed} onCopy={copyValue} accent />
                  <ValueBlock label="Account multipath descriptor" value={compiled.manifest.descriptor.account_multipath} onCopy={copyValue} />
                  <ValueBlock label="BIP 388 wallet policy template" value={compiled.manifest.wallet_policy.template} onCopy={copyValue} />
                  <div className="two-column-values">
                    <ValueBlock label="Owner derived /0/0 pubkey" value={compiled.manifest.participants[0].derived_pubkey} onCopy={copyValue} />
                    <ValueBlock label="Heir derived /0/0 pubkey" value={compiled.manifest.participants[1].derived_pubkey} onCopy={copyValue} />
                  </div>
                  <ValueBlock label="Witness script" value={compiled.manifest.script.witness_script_hex} onCopy={copyValue} />
                  <ValueBlock label="scriptPubKey" value={compiled.manifest.script.script_pubkey_hex} onCopy={copyValue} />
                  <ValueBlock label="Capsule data hex for Bitcoin Core" value={capsule.data_hex} onCopy={copyValue} />
                  <ValueBlock label="Expected OP_RETURN scriptPubKey" value={capsule.op_return_script_pubkey_hex} onCopy={copyValue} />
                  <div className="hash-table">
                    <div><span>Policy manifest SHA256</span><code>{compiled.policy_manifest_sha256}</code></div>
                    <div><span>Capsule SHA256</span><code>{capsule.capsule_sha256}</code></div>
                    <div><span>Release manifest SHA256</span><code>{compiled.release_manifest_sha256}</code></div>
                  </div>
                </div>
              )}

              {reviewTab === "verify" && (
                <div className="review-pane verify-pane" role="tabpanel">
                  <div className="verify-intro">
                    <div className="verify-number">01</div>
                    <div>
                      <span className="mini-label">EXPORT FIRST</span>
                      <h3>Make the recovery bundle independent of Mimir.</h3>
                      <p>The package contains all 24 logical public artifacts, exact hashes, printable guidance, empty records, and the raw BIP 138 capsule.</p>
                    </div>
                  </div>
                  <div className="export-actions">
                    <button className="primary-action" type="button" onClick={exportBundle}><Download size={17} /> Export vault bundle</button>
                    <button className="secondary-action" type="button" onClick={exportCapsule}><Binary size={17} /> Raw .bip138</button>
                    <button className="secondary-action" type="button" onClick={() => window.print()}><Printer size={17} /> Print review</button>
                  </div>
                  <label className={`attestation ${bundleExported ? "enabled" : ""}`}>
                    <input type="checkbox" checked={backupAcknowledged} disabled={!bundleExported} onChange={(event) => setBackupAcknowledged(event.target.checked)} />
                    <span className="custom-checkbox"><Check size={14} /></span>
                    <span>
                      <strong>I saved two copies on different media.</strong>
                      <small>{bundleExported ? "The address is now ready for independent verification—not funding." : "Export the bundle before this acknowledgment becomes available."}</small>
                    </span>
                  </label>

                  <div className="verify-divider" />
                  <div className="verify-intro">
                    <div className="verify-number">02</div>
                    <div>
                      <span className="mini-label">INDEPENDENT CHECK</span>
                      <h3>Paste the exact Bitcoin Core results.</h3>
                      <p>Mimir performs only a byte-for-byte comparison. It never connects to Core and does not normalize pasted values.</p>
                    </div>
                  </div>
                  <div className="core-form">
                    <label className="field">
                      <span>Bitcoin Core version</span>
                      <input value={coreVersion} placeholder="Record the exact version" disabled={!backupAcknowledged} onChange={(event) => { setCoreCheckAttempted(false); setCoreVersion(event.target.value); }} />
                    </label>
                    <label className="field">
                      <span>Core canonical descriptor</span>
                      <textarea value={coreDescriptor} placeholder="Paste the full checksummed descriptor" disabled={!backupAcknowledged} onChange={(event) => { setCoreCheckAttempted(false); setCoreDescriptor(event.target.value); }} />
                    </label>
                    <label className="field">
                      <span>Core-derived address</span>
                      <input value={coreAddress} placeholder={compiled.manifest.address.slice(0, 12) + "…"} disabled={!backupAcknowledged} onChange={(event) => { setCoreCheckAttempted(false); setCoreAddress(event.target.value); }} />
                    </label>
                    <button
                      className="primary-action"
                      type="button"
                      disabled={!backupAcknowledged || !coreDescriptor || !coreAddress || !coreVersion}
                      onClick={() => { setCoreCheckAttempted(true); setReviewTab("verify"); }}
                    >
                      <ShieldCheck size={17} /> Compare exact values
                    </button>
                  </div>

                  {coreCheckAttempted && (
                    <div className={`core-result ${coreVerified ? "success" : "failure"}`} role="status">
                      {coreVerified ? <CheckCircle2 size={20} /> : <AlertTriangle size={20} />}
                      <div>
                        <strong>{coreVerified ? "Exact match recorded" : "Mismatch — do not fund"}</strong>
                        <span>{coreVerified ? "The pasted descriptor and address match this Mimir output. Preserve the completed external verification record." : "At least one complete value differs. Check network, whitespace, xpubs, dates, and the Core result independently."}</span>
                      </div>
                    </div>
                  )}

                  <div className="readiness-grid">
                    <div className={bundleExported ? "done" : ""}>{bundleExported ? <CheckCircle2 size={18} /> : <Circle size={18} />}<span>Bundle exported</span></div>
                    <div className={backupAcknowledged ? "done" : ""}>{backupAcknowledged ? <CheckCircle2 size={18} /> : <Circle size={18} />}<span>Two backups acknowledged</span></div>
                    <div className={coreVerified ? "done" : ""}>{coreVerified ? <CheckCircle2 size={18} /> : <Circle size={18} />}<span>Core exact match</span></div>
                  </div>
                </div>
              )}
            </div>
          )}

          <footer className="panel-footer">
            <button className="back-button" type="button" disabled={step === 0} onClick={() => setStep((current) => Math.max(0, current - 1))}>
              <ArrowLeft size={17} /> Back
            </button>
            <div className="footer-note"><LockKeyhole size={14} /> Inputs are held in memory only and never saved automatically.</div>
            {step < 3 ? (
              <button className="continue-button" type="button" disabled={!canContinue || compiling} onClick={() => void nextStep()}>
                {compiling ? (
                  <><RefreshCw className="spin" size={17} /> Compiling…</>
                ) : step === 2 ? (
                  <>Compile policy <ShieldCheck size={17} /></>
                ) : (
                  <>Continue <ArrowRight size={17} /></>
                )}
              </button>
            ) : (
              <button className="continue-button" type="button" onClick={() => setReviewTab(reviewTab === "verify" ? "summary" : "verify")}>
                {reviewTab === "verify" ? "Review summary" : "Export & verify"}
                {reviewTab === "verify" ? <ArrowLeft size={17} /> : <ArrowRight size={17} />}
              </button>
            )}
          </footer>
        </section>

        <aside className="context-rail">
          <section className="context-card trust-card">
            <span className="mini-label">TRUST BOUNDARY</span>
            <div className="trust-row active"><span><ShieldCheck size={16} /></span><div><strong>Mimir</strong><small>Public policy artifacts</small></div><Check size={15} /></div>
            <div className="trust-connector" />
            <div className="trust-row"><span><Landmark size={16} /></span><div><strong>Bitcoin Core</strong><small>Verify · fund · monitor</small></div></div>
            <div className="trust-connector" />
            <div className="trust-row"><span><KeyRound size={16} /></span><div><strong>Offline signer</strong><small>Review · sign one path</small></div></div>
          </section>

          <section className="context-card never-card">
            <span className="mini-label">NEVER ENTER</span>
            <ul>
              <li><span>×</span> Seed or mnemonic</li><li><span>×</span> xprv or WIF</li>
              <li><span>×</span> BIP39 passphrase</li><li><span>×</span> PIN or credentials</li>
            </ul>
          </section>

          <section className="context-card release-card">
            <div className="release-card-head"><span className="mini-label">RELEASE</span><span className="orange-dot" /></div>
            <strong>mimir-v1-preview.1</strong>
            <p>Frozen policy profile. Mainnet gates, independent review, and Core end-to-end certification remain incomplete.</p>
            <button
              className="release-hash"
              type="button"
              onClick={() => { if (compiled) copyValue(compiled.release_manifest_sha256, "Release hash"); }}
              disabled={!compiled}
            >
              <code>{compiled ? shortHash(compiled.release_manifest_sha256, 8, 6) : "available after compile"}</code>
              {compiled && <Copy size={13} />}
            </button>
          </section>

          {compiled && capsule && (
            <section className="context-card session-card">
              <span className="mini-label">CURRENT COMPILE</span>
              <dl>
                <div><dt>Network</dt><dd>{compiled.manifest.network}</dd></div>
                <div><dt>Script</dt><dd>87 bytes</dd></div>
                <div><dt>Capsule</dt><dd>{capsule.byte_length.toLocaleString()} bytes</dd></div>
                <div><dt>Recipients</dt><dd>{capsule.recipient_count} + {capsule.encoded_secret_count - capsule.recipient_count} decoys</dd></div>
              </dl>
            </section>
          )}
        </aside>
      </div>

      <div className={`copy-toast ${copiedLabel ? "visible" : ""}`} role="status">
        <Check size={15} /> {copiedLabel ? `${copiedLabel} copied` : "Copied"}
      </div>
    </main>
  );
}
