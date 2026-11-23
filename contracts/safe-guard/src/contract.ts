/**
 * viem helpers around `SignholdGuard`: submitting attestations / approvals (anyone may relay
 * them; authority comes from the signatures) and reading guard state.
 */
import type { Account, Address, Chain, Hex, PublicClient, Transport, WalletClient } from "viem";
import { SIGNHOLD_GUARD_ABI, SIGNHOLD_GUARD_BYTECODE } from "./abi.js";
import type { P256PublicKey, P256Signature } from "./approval.js";
import type { AttestationMessage, ApprovalMessage, GuardVerdictCode } from "./typedData.js";

export type GuardWalletClient = WalletClient<Transport, Chain | undefined, Account>;

export interface GuardDeployConfig {
  safe: Address;
  attestor: Address;
  approvers?: Address[];
  p256Approvers?: P256PublicKey[];
  p256Enabled?: boolean;
  /** Seconds an approval stays valid after `approvedAt`. Default 900 (15 minutes, the service default). */
  approvalWindowSeconds?: bigint;
  /** Maximum attestation lifetime accepted at submission. Default 3600. */
  attestationTtlSeconds?: bigint;
}

export const DEFAULT_APPROVAL_WINDOW_SECONDS = 900n;
export const DEFAULT_ATTESTATION_TTL_SECONDS = 3600n;

/** Deploy a guard. Returns the deployment transaction hash; read the address from the receipt. */
export async function deployGuard(wallet: GuardWalletClient, cfg: GuardDeployConfig): Promise<Hex> {
  const p256 = cfg.p256Approvers ?? [];
  return wallet.deployContract({
    abi: SIGNHOLD_GUARD_ABI,
    bytecode: SIGNHOLD_GUARD_BYTECODE,
    chain: wallet.chain,
    args: [
      cfg.safe,
      cfg.attestor,
      cfg.approvers ?? [],
      p256.map((k) => k.qx),
      p256.map((k) => k.qy),
      cfg.p256Enabled ?? false,
      cfg.approvalWindowSeconds ?? DEFAULT_APPROVAL_WINDOW_SECONDS,
      cfg.attestationTtlSeconds ?? DEFAULT_ATTESTATION_TTL_SECONDS,
    ],
  });
}

export interface SubmitAttestationInput {
  guard: Address;
  message: AttestationMessage;
  signature: Hex;
}

export async function submitAttestation(wallet: GuardWalletClient, input: SubmitAttestationInput): Promise<Hex> {
  const { message } = input;
  return wallet.writeContract({
    address: input.guard,
    abi: SIGNHOLD_GUARD_ABI,
    functionName: "submitAttestation",
    args: [message.safeTxHash, message.verdict, message.expiresAt, message.auditId, input.signature],
    chain: wallet.chain,
  });
}

export interface SubmitApprovalInput {
  guard: Address;
  message: ApprovalMessage;
  approver: Address;
  signature: Hex;
}

export async function submitApproval(wallet: GuardWalletClient, input: SubmitApprovalInput): Promise<Hex> {
  const { message } = input;
  return wallet.writeContract({
    address: input.guard,
    abi: SIGNHOLD_GUARD_ABI,
    functionName: "submitApproval",
    args: [message.safeTxHash, message.auditId, input.approver, message.approvedAt, input.signature],
    chain: wallet.chain,
  });
}

export interface SubmitApprovalP256Input {
  guard: Address;
  message: ApprovalMessage;
  publicKey: P256PublicKey;
  signature: P256Signature;
}

export async function submitApprovalP256(wallet: GuardWalletClient, input: SubmitApprovalP256Input): Promise<Hex> {
  const { message, publicKey, signature } = input;
  return wallet.writeContract({
    address: input.guard,
    abi: SIGNHOLD_GUARD_ABI,
    functionName: "submitApprovalP256",
    args: [message.safeTxHash, message.auditId, publicKey.qx, publicKey.qy, message.approvedAt, signature.r, signature.s],
    chain: wallet.chain,
  });
}

export interface StoredAttestation {
  verdict: GuardVerdictCode | 0;
  expiresAt: bigint;
  auditId: Hex;
}

export async function readAttestation(client: PublicClient, guard: Address, safeTxHash: Hex): Promise<StoredAttestation> {
  const [verdict, expiresAt, auditId] = await client.readContract({ address: guard, abi: SIGNHOLD_GUARD_ABI, functionName: "attestations", args: [safeTxHash] });
  return { verdict: verdict as GuardVerdictCode | 0, expiresAt, auditId };
}

export interface StoredApproval {
  approverId: Hex;
  auditId: Hex;
  approvedAt: bigint;
}

export async function readApproval(client: PublicClient, guard: Address, safeTxHash: Hex): Promise<StoredApproval> {
  const [approverId, auditId, approvedAt] = await client.readContract({ address: guard, abi: SIGNHOLD_GUARD_ABI, functionName: "approvals", args: [safeTxHash] });
  return { approverId, auditId, approvedAt };
}
