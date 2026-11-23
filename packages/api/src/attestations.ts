/**
 * On-chain enforcement: the service attests a check's verdict for an exact Safe transaction.
 *
 * `SignholdGuard.sol` (contracts/safe-guard) lets a Safe execute a transaction only when the
 * Signhold attestor key has signed an EIP-712 `Attestation{safe, safeTxHash, verdict, expiresAt,
 * auditId}` for that transaction hash (and, for `escalate`, a registered device has signed an
 * `Approval`). This module is the server side of that: it verifies that the Safe transaction
 * the agent presents is exactly the intent the service decided on, and signs the verdict.
 *
 * It never attests `block` (the guard treats absence as blocked), never attests a transaction
 * that differs from the audited intent in `to` / `value` / `data` / chain id, and never attests
 * a delegatecall or a gas-refund-bearing transaction (the simulation did not cover them).
 *
 * The attestor key is a third key kind: secp256k1, held by the service, distinct from the
 * Ed25519 audit signing key, and refused as an approver (key separation).
 */
import type { AttestationAuditData, AttestationRequest, AttestationResponse, AuditRecord } from "@signhold/core";
import {
  GUARD_VERDICT,
  SafeOperation,
  auditIdToBytes32,
  computeSafeTxHash,
  createAttestor,
  isPlainSafeTx,
  type Attestor,
  type GuardDomainInput,
  type SafeTransaction,
} from "@signhold/safe-guard";
import { getAddress, isAddress, type Address, type Hex } from "viem";
import { z } from "zod";
import { DEFAULT_APPROVAL_TTL_MS, type Eip712ApprovalBinding } from "./approvals.js";
import { evmAddressSchema } from "./serialization.js";

export const DEFAULT_MAX_ISSUED_ATTESTATIONS = 10_000;

export interface AttestorOptions {
  /** 32-byte secp256k1 private key (0x-hex). Never the audit key, never an approver key. */
  privateKey: string;
  /** Optional allowlist of guard contract addresses the service will sign for. Empty = any. */
  guards?: readonly string[];
  /** Lifetime of an attestation. Default: the approval TTL (15 minutes). */
  ttlMs?: number;
  /** Upper bound on issued attestations remembered for `eip712` approvals. Default 10k. */
  maxIssued?: number;
  now?: () => number;
}

const bigintString = z.union([z.string().max(80).regex(/^\d+$/, "expected decimal integer string"), z.bigint(), z.number().int().nonnegative().finite()]).transform((v) => (typeof v === "bigint" ? v : BigInt(v)));
const uint256 = bigintString.refine((v) => v >= 0n && v < 1n << 256n, "must fit in uint256");
const hexData = z
  .string()
  .max(2 + 128 * 1024)
  .regex(/^0x([0-9a-fA-F]{2})*$/, "expected 0x-prefixed even-length hex")
  .transform((v) => v as Hex);
const bytes32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/, "expected 32-byte hex").transform((v) => v as Hex);

export const attestationRequestSchema = z
  .object({
    auditId: z.string().uuid(),
    safe: evmAddressSchema,
    guard: evmAddressSchema,
    chainId: z.union([z.number().int().positive().finite(), z.string().regex(/^\d{1,20}$/)]),
    safeTx: z
      .object({
        to: evmAddressSchema,
        value: uint256,
        data: hexData,
        operation: z.union([z.literal(0), z.literal(1)]),
        safeTxGas: uint256,
        baseGas: uint256,
        gasPrice: uint256,
        gasToken: evmAddressSchema,
        refundReceiver: evmAddressSchema,
        nonce: uint256,
      })
      .strict(),
    safeTxHash: bytes32.optional(),
  })
  .strict();

export type ParsedAttestationRequest = z.infer<typeof attestationRequestSchema>;

export function parseAttestationRequest(body: unknown): ParsedAttestationRequest {
  return attestationRequestSchema.parse(body);
}

export type AttestationRefusalReason =
  | "unknown_audit"
  | "not_check"
  | "blocked"
  | "unknown_verdict"
  | "guard_not_allowed"
  | "chain_mismatch"
  | "safe_mismatch"
  | "intent_mismatch"
  | "unsupported_safe_tx"
  | "hash_mismatch";

export interface IssuedAttestation {
  auditId: string;
  safe: Address;
  guard: Address;
  chainId: bigint;
  safeTxHash: Hex;
  auditIdBytes32: Hex;
  verdict: "allow" | "escalate";
  verdictCode: 1 | 2;
  expiresAtUnix: bigint;
  attestationAuditId?: string;
}

function toSafeTransaction(tx: ParsedAttestationRequest["safeTx"]): SafeTransaction {
  return {
    to: getAddress(tx.to),
    value: tx.value,
    data: tx.data,
    operation: tx.operation === 0 ? SafeOperation.Call : SafeOperation.DelegateCall,
    safeTxGas: tx.safeTxGas,
    baseGas: tx.baseGas,
    gasPrice: tx.gasPrice,
    gasToken: getAddress(tx.gasToken),
    refundReceiver: getAddress(tx.refundReceiver),
    nonce: tx.nonce,
  };
}

/**
 * Every check for an attestation request, in a fixed order; empty = attestable. The
 * caller reports a generic 403 and logs the reasons (same policy as approvals).
 */
export function verifyAttestationRequest(req: ParsedAttestationRequest, record: AuditRecord | undefined, opts: { guards?: ReadonlySet<string> }): AttestationRefusalReason[] {
  const reasons: AttestationRefusalReason[] = [];
  if (!record) reasons.push("unknown_audit");
  if (record && (record.type ?? "check") !== "check") reasons.push("not_check");
  const verdict = record?.decision.verdict;
  if (verdict === "block") reasons.push("blocked");
  else if (record && verdict !== "allow" && verdict !== "escalate") reasons.push("unknown_verdict");
  if (opts.guards && opts.guards.size > 0 && !opts.guards.has(req.guard.toLowerCase())) reasons.push("guard_not_allowed");

  const intent = record?.intent;
  if (intent) {
    if (intent.chain !== "evm" || intent.chainId === undefined || BigInt(intent.chainId) !== BigInt(req.chainId)) reasons.push("chain_mismatch");
    if (!isAddress(intent.from, { strict: false }) || getAddress(intent.from) !== getAddress(req.safe)) reasons.push("safe_mismatch");
    const to = intent.to && isAddress(intent.to, { strict: false }) ? getAddress(intent.to) : undefined;
    const value = intent.value ?? 0n;
    const data = (intent.data ?? "0x").toLowerCase();
    if (to !== getAddress(req.safeTx.to) || value !== req.safeTx.value || data !== req.safeTx.data.toLowerCase()) reasons.push("intent_mismatch");
  }
  const tx = toSafeTransaction(req.safeTx);
  if (!isPlainSafeTx(tx)) reasons.push("unsupported_safe_tx");
  if (req.safeTxHash !== undefined && req.safeTxHash.toLowerCase() !== computeSafeTxHash(BigInt(req.chainId), getAddress(req.safe), tx).toLowerCase()) reasons.push("hash_mismatch");
  return reasons;
}

/** Issues attestations and remembers them (bounded) so `eip712` approvals can be bound to them. */
export class AttestationService {
  readonly attestor: Attestor;
  readonly guards: ReadonlySet<string>;
  readonly ttlMs: number;
  private readonly maxIssued: number;
  private readonly now: () => number;
  private readonly issued = new Map<string, IssuedAttestation>();

  constructor(opts: AttestorOptions) {
    this.attestor = createAttestor({ privateKey: opts.privateKey });
    const guards = (opts.guards ?? []).map((g) => g.trim()).filter(Boolean);
    for (const g of guards) if (!isAddress(g, { strict: false })) throw new Error(`SIGNHOLD_ATTESTOR_GUARDS: '${g}' is not an EVM address`);
    this.guards = new Set(guards.map((g) => g.toLowerCase()));
    this.ttlMs = opts.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) throw new Error("attestation ttlMs must be a positive number");
    this.maxIssued = opts.maxIssued ?? DEFAULT_MAX_ISSUED_ATTESTATIONS;
    this.now = opts.now ?? Date.now;
  }

  get address(): Address {
    return this.attestor.address;
  }

  verify(req: ParsedAttestationRequest, record: AuditRecord | undefined): AttestationRefusalReason[] {
    return verifyAttestationRequest(req, record, { guards: this.guards });
  }

  /** Describe the request for an audit record without signing anything. */
  describe(req: ParsedAttestationRequest, checkAuditId: string): Pick<AttestationAuditData, "checkAuditId" | "safe" | "guard" | "chainId" | "safeTxHash"> {
    return {
      checkAuditId,
      safe: getAddress(req.safe),
      guard: getAddress(req.guard),
      chainId: String(req.chainId),
      safeTxHash: computeSafeTxHash(BigInt(req.chainId), getAddress(req.safe), toSafeTransaction(req.safeTx)),
    };
  }

  /** Sign an attestation for a request `verify()` accepted. Caller must have checked `verify()` returned []. */
  async issue(req: ParsedAttestationRequest, record: AuditRecord): Promise<{ response: Omit<AttestationResponse, "attestationAuditId">; audit: AttestationAuditData; issued: IssuedAttestation }> {
    const verdict = record.decision.verdict;
    if (verdict !== "allow" && verdict !== "escalate") throw new Error("refusing to attest a non-attestable verdict");
    const safe = getAddress(req.safe);
    const guard = getAddress(req.guard);
    const chainId = BigInt(req.chainId);
    const safeTxHash = computeSafeTxHash(chainId, safe, toSafeTransaction(req.safeTx));
    const nowMs = this.now();
    const expiresAtMs = nowMs + this.ttlMs;
    const expiresAtUnix = BigInt(Math.floor(expiresAtMs / 1000));
    const auditIdBytes32 = auditIdToBytes32(record.id);
    const verdictCode = GUARD_VERDICT[verdict];
    const domain: GuardDomainInput = { chainId, guard };
    const signature = await this.attestor.signAttestation(domain, { safe, safeTxHash, verdict: verdictCode, expiresAt: expiresAtUnix, auditId: auditIdBytes32 });
    const issued: IssuedAttestation = { auditId: record.id, safe, guard, chainId, safeTxHash, auditIdBytes32, verdict, verdictCode, expiresAtUnix };
    const response: Omit<AttestationResponse, "attestationAuditId"> = {
      auditId: record.id,
      safe,
      guard,
      chainId: String(chainId),
      safeTxHash,
      verdict,
      verdictCode,
      expiresAt: new Date(Number(expiresAtUnix) * 1000).toISOString(),
      expiresAtUnix: expiresAtUnix.toString(),
      auditIdBytes32,
      attestor: this.attestor.address,
      signature,
    };
    const audit: AttestationAuditData = {
      checkAuditId: record.id,
      outcome: "attested",
      safe,
      guard,
      chainId: String(chainId),
      safeTxHash,
      verdictCode,
      expiresAt: expiresAtUnix.toString(),
      auditIdBytes32,
      attestor: this.attestor.address,
      signature,
    };
    return { response, audit, issued };
  }

  /** Remember an issued attestation (after its audit record is sealed) so an `eip712` approval can be bound to it. */
  remember(issued: IssuedAttestation, attestationAuditId: string): void {
    if (this.issued.size >= this.maxIssued) {
      const t = this.now();
      for (const [k, v] of this.issued) {
        if (Number(v.expiresAtUnix) * 1000 < t) this.issued.delete(k);
        if (this.issued.size < this.maxIssued) break;
      }
      if (this.issued.size >= this.maxIssued) this.issued.delete(this.issued.keys().next().value as string);
    }
    this.issued.set(issued.auditId, { ...issued, attestationAuditId });
  }

  get(auditId: string): IssuedAttestation | undefined {
    return this.issued.get(auditId);
  }

  /** The binding an `eip712` approval for `auditId` must match, if the service attested it (and it has not expired). */
  bindingFor(auditId: string): Eip712ApprovalBinding | undefined {
    const a = this.issued.get(auditId);
    if (!a) return undefined;
    if (Number(a.expiresAtUnix) * 1000 < this.now()) return undefined;
    return { domain: { chainId: a.chainId, guard: a.guard }, safe: a.safe, safeTxHash: a.safeTxHash, auditIdBytes32: a.auditIdBytes32 };
  }
}
