/**
 * EIP-712 structures verified by `SignholdGuard.sol`. The domain is the guard's own
 * (`name = "SignholdGuard"`, `version = "1"`, chain id, guard address), so a signature is
 * bound to one guard on one chain; `safe` inside each struct binds it to the Safe as well.
 *
 *   Attestation(address safe,bytes32 safeTxHash,uint8 verdict,uint64 expiresAt,bytes32 auditId)
 *   Approval(address safe,bytes32 safeTxHash,bytes32 auditId,uint64 approvedAt)
 *
 * `auditId` on-chain is `sha256(utf8(auditId))` of the Signhold audit record id (see `auditIdToBytes32`);
 * `expiresAt` / `approvedAt` are unix seconds.
 */
import { createHash } from "node:crypto";
import { getAddress, hashTypedData, keccak256, recoverTypedDataAddress, stringToBytes, type Address, type Hex } from "viem";

export const SAFE_GUARD_DOMAIN_NAME = "SignholdGuard";
export const SAFE_GUARD_DOMAIN_VERSION = "1";

/** Verdict codes as attested on-chain. `block` has no code: it is never attested. */
export const GUARD_VERDICT = { allow: 1, escalate: 2 } as const;
export type GuardVerdictName = keyof typeof GUARD_VERDICT;
export type GuardVerdictCode = (typeof GUARD_VERDICT)[GuardVerdictName];

/** `keccak256("signhold.safe-guard.recovery.v1")`: the sentinel audit id of the owner escape hatch. */
export const RECOVERY_AUDIT_ID: Hex = keccak256(stringToBytes("signhold.safe-guard.recovery.v1"));

export const ATTESTATION_TYPES = {
  Attestation: [
    { name: "safe", type: "address" },
    { name: "safeTxHash", type: "bytes32" },
    { name: "verdict", type: "uint8" },
    { name: "expiresAt", type: "uint64" },
    { name: "auditId", type: "bytes32" },
  ],
} as const;

export const APPROVAL_TYPES = {
  Approval: [
    { name: "safe", type: "address" },
    { name: "safeTxHash", type: "bytes32" },
    { name: "auditId", type: "bytes32" },
    { name: "approvedAt", type: "uint64" },
  ],
} as const;

export interface GuardDomainInput {
  chainId: bigint | number;
  guard: Address;
}

export function guardDomain({ chainId, guard }: GuardDomainInput) {
  return { name: SAFE_GUARD_DOMAIN_NAME, version: SAFE_GUARD_DOMAIN_VERSION, chainId: BigInt(chainId), verifyingContract: getAddress(guard) } as const;
}

/** The bytes32 under which a Signhold audit record id is referenced on-chain: `sha256(utf8(auditId))`. */
export function auditIdToBytes32(auditId: string): Hex {
  if (typeof auditId !== "string" || auditId.length === 0) throw new TypeError("auditId must be a non-empty string");
  return `0x${createHash("sha256").update(auditId, "utf8").digest("hex")}`;
}

export interface AttestationMessage {
  safe: Address;
  safeTxHash: Hex;
  verdict: GuardVerdictCode;
  /** Unix seconds. */
  expiresAt: bigint;
  /** bytes32 (see `auditIdToBytes32`). */
  auditId: Hex;
}

export interface ApprovalMessage {
  safe: Address;
  safeTxHash: Hex;
  auditId: Hex;
  /** Unix seconds. */
  approvedAt: bigint;
}

const BYTES32_RE = /^0x[0-9a-fA-F]{64}$/;

function assertBytes32(v: string, name: string): void {
  if (!BYTES32_RE.test(v)) throw new TypeError(`${name} must be a 0x-prefixed 32-byte hex string`);
}

function assertUint64(v: bigint, name: string): void {
  if (typeof v !== "bigint" || v < 0n || v >= 1n << 64n) throw new TypeError(`${name} must be a uint64 bigint`);
}

export function attestationTypedData(domain: GuardDomainInput, message: AttestationMessage) {
  assertBytes32(message.safeTxHash, "safeTxHash");
  assertBytes32(message.auditId, "auditId");
  assertUint64(message.expiresAt, "expiresAt");
  if (message.verdict !== GUARD_VERDICT.allow && message.verdict !== GUARD_VERDICT.escalate) throw new TypeError("verdict must be 1 (allow) or 2 (escalate)");
  return {
    domain: guardDomain(domain),
    types: ATTESTATION_TYPES,
    primaryType: "Attestation",
    message: { safe: getAddress(message.safe), safeTxHash: message.safeTxHash, verdict: message.verdict, expiresAt: message.expiresAt, auditId: message.auditId },
  } as const;
}

export function approvalTypedData(domain: GuardDomainInput, message: ApprovalMessage) {
  assertBytes32(message.safeTxHash, "safeTxHash");
  assertBytes32(message.auditId, "auditId");
  assertUint64(message.approvedAt, "approvedAt");
  return {
    domain: guardDomain(domain),
    types: APPROVAL_TYPES,
    primaryType: "Approval",
    message: { safe: getAddress(message.safe), safeTxHash: message.safeTxHash, auditId: message.auditId, approvedAt: message.approvedAt },
  } as const;
}

export function hashAttestation(domain: GuardDomainInput, message: AttestationMessage): Hex {
  return hashTypedData(attestationTypedData(domain, message));
}

export function hashApproval(domain: GuardDomainInput, message: ApprovalMessage): Hex {
  return hashTypedData(approvalTypedData(domain, message));
}

/** Address that produced `signature` over the attestation, or `undefined` for a malformed signature. Never throws. */
export async function recoverAttestationSigner(domain: GuardDomainInput, message: AttestationMessage, signature: Hex): Promise<Address | undefined> {
  try {
    return await recoverTypedDataAddress({ ...attestationTypedData(domain, message), signature });
  } catch {
    return undefined;
  }
}

/** Address that produced `signature` over the approval, or `undefined` for a malformed signature. Never throws. */
export async function recoverApprovalSigner(domain: GuardDomainInput, message: ApprovalMessage, signature: Hex): Promise<Address | undefined> {
  try {
    return await recoverTypedDataAddress({ ...approvalTypedData(domain, message), signature });
  } catch {
    return undefined;
  }
}
