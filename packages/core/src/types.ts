// Shared contracts for Signhold. All packages import from here; never redefine.

export type Chain = "evm" | "solana";

export type Verdict = "allow" | "block" | "escalate";

/** What an agent proposes to do. Chain-specific payload lives in `raw`. */
export interface TransactionIntent {
  id: string;                 // client-generated UUID
  chain: Chain;
  chainId?: number | string;  // EVM chainId (1, 8453) or Solana cluster ("mainnet-beta")
  from: string;               // agent wallet address
  to?: string;                // EVM: target contract/EOA. Solana: primary program or recipient if known
  value?: bigint;             // native value in base units (wei / lamports)
  data?: `0x${string}`;       // EVM calldata
  raw?: string;               // Solana: base64 serialized (versioned) transaction
  description?: string;       // agent's stated purpose, free text
  metadata?: Record<string, unknown>;
}

export interface AssetDelta {
  asset: string;              // "native" | token mint/contract address
  symbol?: string;
  decimals: number;
  amount: bigint;             // signed: negative = outflow from `from`
  usdValue?: number;          // signed, best-effort
}

export interface ApprovalChange {
  token: string;
  spender: string;
  previous: bigint;
  next: bigint;               // 2^256-1 or u64::MAX => unlimited
  unlimited: boolean;
  /** Whether the spender has code (EVM) / is executable. `undefined` = unknown; `false` = EOA. */
  spenderIsContract?: boolean;
}

export interface SimulationResult {
  ok: boolean;                // simulation executed without revert
  revertReason?: string;
  deltas: AssetDelta[];       // net asset changes for `from`
  approvals: ApprovalChange[];
  contractsTouched: string[]; // addresses / program ids invoked
  /**
   * Addresses that receive assets from `from` as decoded by the adapter: ERC-20
   * transfer/transferFrom `to`, swap recipients, SPL transfer destinations (and their
   * owners when known), native transfer targets. Policy/behavior/reputation treat
   * these as counterparties alongside `to` and `contractsTouched`. Optional: older
   * adapters may omit it.
   */
  recipients?: string[];
  newContracts: string[];     // contracts/programs with no prior history (if known)
  gasEstimate?: bigint;
  warnings: string[];         // adapter-level heuristics, e.g. "selfdestruct opcode"
  rawTrace?: unknown;
}

export interface AgentContext {
  agentId: string;
  tenantId?: string;
  /** rolling spend already committed in the current window, USD */
  spentUsdInWindow?: number;
  windowSeconds?: number;
  /** trusted address lists supplied by the operator */
  allowlist?: string[];
  denylist?: string[];
  now?: Date;
}

export type RuleKind =
  | "max_tx_usd"
  | "max_window_usd"
  | "allowlist_only"
  | "denylist"
  | "no_unlimited_approvals"
  | "no_eoa_approvals"
  | "max_slippage_bps"
  | "no_new_contracts"
  | "require_simulation_ok"
  | "max_native_value"
  | "custom";

export interface PolicyRule {
  id: string;
  kind: RuleKind;
  /** verdict when the rule fires; default "block" */
  onViolation?: Exclude<Verdict, "allow">;
  params?: Record<string, unknown>;
  description?: string;
}

export interface PolicySet {
  id: string;
  version: number;
  rules: PolicyRule[];
}

export interface RuleFinding {
  ruleId: string;
  kind: RuleKind;
  verdict: Exclude<Verdict, "allow">;
  message: string;            // human-readable, safe to show operators
  evidence?: Record<string, unknown>;
}

export interface Decision {
  intentId: string;
  verdict: Verdict;
  findings: RuleFinding[];
  riskScore: number;          // 0..100
  explanation: string;        // one paragraph summarising why
  simulation?: SimulationResult;
  policyId: string;
  policyVersion: number;
  evaluatedAt: string;        // ISO timestamp
}

export interface ChainAdapter {
  readonly chain: Chain;
  /** Decode + simulate. Must not throw for ordinary reverts; set ok=false instead. */
  simulate(intent: TransactionIntent): Promise<SimulationResult>;
}

/**
 * What an audit record documents. `check` is a policy decision; `approval` and
 * `approval_rejected` are the server-verified outcome of a human approval attempt
 * against an earlier `escalate` check (see `ApprovalAuditData`); `attestation` and
 * `attestation_refused` record the service signing (or refusing to sign) an on-chain
 * attestation of a check's verdict for a Safe transaction (see `AttestationAuditData`).
 * Absent = `check` (records written before approvals existed).
 */
export type AuditRecordType = "check" | "approval" | "approval_rejected" | "attestation" | "attestation_refused";

/**
 * Attached to an `escalate` check record when server-side human approval is
 * enabled: the challenge a registered approver device must sign. Being inside the
 * sealed check record, the challenge is bound into the hash chain before the
 * agent ever sees it.
 */
export interface ApprovalRequest {
  /** sha256 hex of the canonical challenge payload (see `computeApprovalChallenge`). */
  challenge: string;
  issuedAt: string;
  expiresAt: string;
}

/** Outcome of an approval attempt, carried by `approval` / `approval_rejected` records. */
export interface ApprovalAuditData {
  /** `id` of the `check` record this attempt refers to. */
  checkAuditId: string;
  /** The challenge presented for signature (as stored server-side for that check). */
  challenge: string;
  outcome: "approved" | "rejected";
  /** Server-generated id of a successful approval. */
  approvalId?: string;
  /** Registered approver key that produced a valid signature (approved) or was claimed (rejected). */
  approverKeyId?: string;
  /** `approvedAt` as asserted by the device, only on `approved`. */
  approvedAt?: string;
  /** Free-text reason supplied by the approver, control-stripped and length-capped. */
  reason?: string;
  /** Coarse server-side reason for a rejection (never returned over HTTP; audit only). */
  rejectionReason?: string;
  /** Signature scheme the device used. Absent = `ed25519`. */
  scheme?: ApprovalScheme;
}

/**
 * Carried by `attestation` / `attestation_refused` records: the service's EIP-712
 * `Attestation` for a Safe transaction hash (consumed by `SignholdGuard.sol`), or why it
 * refused to sign one. `block` decisions are never attested: their absence on-chain is
 * what blocks them.
 */
export interface AttestationAuditData {
  /** `id` of the `check` record whose verdict was attested. */
  checkAuditId: string;
  outcome: "attested" | "refused";
  /** The Safe (`intent.from`) and the guard contract whose EIP-712 domain the signature is bound to. */
  safe: string;
  guard: string;
  chainId: string;
  /** `Safe.getTransactionHash(...)` of the exact transaction, as recomputed by the service. */
  safeTxHash: string;
  /** Verdict code as attested: 1 = allow, 2 = escalate. Absent on refusals. */
  verdictCode?: 1 | 2;
  /** Unix seconds after which the guard refuses the attestation. */
  expiresAt?: string;
  /** `sha256(utf8(checkAuditId))`, the bytes32 the guard stores. */
  auditIdBytes32?: string;
  /** The attestor address (never the key) and its signature, so the chain can be audited against the contract. */
  attestor?: string;
  signature?: string;
  /** Coarse server-side reason for a refusal (never returned over HTTP; audit only). */
  refusalReason?: string;
}

export interface AuditRecord {
  id: string;
  /** Record kind; absent means `check` (legacy). */
  type?: AuditRecordType;
  intent: TransactionIntent;
  decision: Decision;
  context: AgentContext;
  recordedAt: string;
  /** Who submitted the request (API key identity, correlation id). Optional for legacy records. */
  principal?: AuditPrincipal;
  /** Hash-chain + signature metadata. Absent on legacy/unsealed records. */
  integrity?: AuditIntegrity;
  /** On `escalate` checks: the challenge an approver must sign. */
  approvalRequest?: ApprovalRequest;
  /** On `approval` / `approval_rejected` records: what was (not) approved. */
  approval?: ApprovalAuditData;
  /** On `attestation` / `attestation_refused` records: what was (not) attested for on-chain enforcement. */
  attestation?: AttestationAuditData;
}

export interface CheckRequest {
  intent: TransactionIntent;
  context: AgentContext;
  policyId?: string;
}

export interface CheckResponse {
  decision: Decision;
  auditId: string;
  /**
   * Present only when `decision.verdict` is `escalate` and the server has approver
   * keys registered. The agent cannot do anything with it except hand it to a human:
   * a registered device signs `challenge` and posts the signature to
   * `POST /v1/approvals`; the server verifies it and records the approval.
   */
  approval?: { challenge: string; expiresAt: string };
}

/**
 * How an approval was signed. `ed25519` (default): base64 Ed25519 signature over the UTF-8
 * challenge. `eip712`: 0x-hex secp256k1 signature over the `SignholdGuard` EIP-712 `Approval`
 * struct for the Safe transaction the service attested for this audit id, so the same device
 * signature satisfies both `POST /v1/approvals` and the on-chain guard.
 */
export type ApprovalScheme = "ed25519" | "eip712";

/** Body of `POST /v1/approvals`: produced by the trusted approver device, never by the agent. */
export interface ApprovalSubmission {
  auditId: string;
  keyId: string;
  /** base64 Ed25519 signature over the UTF-8 bytes of the hex challenge, or (scheme `eip712`) a 0x-hex secp256k1 signature. */
  signature: string;
  /** ISO timestamp asserted by the device; must fall inside the approval window. Whole seconds for `eip712`. */
  approvedAt: string;
  reason?: string;
  scheme?: ApprovalScheme;
}

/** Safe transaction fields as sent to `POST /v1/attestations` (bigints as decimal strings over HTTP). */
export interface SafeTxFields {
  to: string;
  value: string | bigint;
  data: string;
  operation: number;
  safeTxGas: string | bigint;
  baseGas: string | bigint;
  gasPrice: string | bigint;
  gasToken: string;
  refundReceiver: string;
  nonce: string | bigint;
}

/** Body of `POST /v1/attestations`: the agent asks the service to attest a check's verdict for an exact Safe transaction. */
export interface AttestationRequest {
  auditId: string;
  safe: string;
  guard: string;
  chainId: number | string;
  safeTx: SafeTxFields;
  /** Optional cross-check: refused when it differs from the hash the service computes. */
  safeTxHash?: string;
}

/** Body of a `200` from `POST /v1/attestations`. */
export interface AttestationResponse {
  auditId: string;
  attestationAuditId: string;
  safe: string;
  guard: string;
  chainId: string;
  safeTxHash: string;
  verdict: "allow" | "escalate";
  verdictCode: 1 | 2;
  /** ISO timestamp. */
  expiresAt: string;
  /** Unix seconds as a decimal string: the `expiresAt` the guard verifies. */
  expiresAtUnix: string;
  auditIdBytes32: string;
  attestor: string;
  /** 65-byte secp256k1 signature, 0x-hex. */
  signature: string;
}

export type ApprovalStatus = "pending" | "approved" | "expired" | "rejected" | "unknown";

/** Body of `GET /v1/approvals/:auditId`. */
export interface ApprovalStatusResponse {
  auditId: string;
  status: ApprovalStatus;
  expiresAt?: string;
  approvedBy?: string;
  approvalId?: string;
  approvedAt?: string;
}

// ---- Tamper-evident audit (additive; records without `integrity` are legacy/unsealed) ----

/** Hash-chain + optional signature metadata attached to every sealed audit record. */
export interface AuditIntegrity {
  /** 0-based position in the chain. */
  seq: number;
  /** `hash` of the previous record, or 64 zero hex chars for the genesis record. */
  prevHash: string;
  /** sha256 (hex) of the canonical JSON of the record body + `{seq, prevHash}`. */
  hash: string;
  /** Algorithm identifier, currently "sha256-v1". */
  alg: string;
  /** base64 Ed25519 signature over the hex `hash` (UTF-8), when signing is enabled. */
  signature?: string;
  /** Fingerprint (sha256 hex, truncated) of the signing public key. */
  keyId?: string;
}

/** Who submitted the request that produced an audit record. */
export interface AuditPrincipal {
  /** Identity of the API key (never the key itself). */
  apiKeyId?: string;
  /** Server-generated correlation id for the request. */
  requestId?: string;
  /** Whether the request carried a valid HMAC signature. */
  signed?: boolean;
  /**
   * On approval records: the registered approver key whose Ed25519 signature was
   * verified server-side. Distinct from `apiKeyId` (transport auth) by design.
   */
  approverKeyId?: string;
}
