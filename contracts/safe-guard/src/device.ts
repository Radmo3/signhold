/**
 * Approver-device flow for on-chain approvals, mirroring the trusted-display rules of
 * `packages/api/scripts/approve.ts` (I-HITL, arXiv:2610.35835):
 *
 *   1. the device obtains the sealed audit record itself (from the API with its own key, or
 *      a copy obtained out of band), never a summary relayed by the agent;
 *   2. it recomputes the server challenge from the record and refuses a tampered record;
 *   3. it checks that the Safe transaction it is asked to approve IS the transaction the service
 *      decided on (chain id, Safe = intent.from, to, value, data; plain call, no gas refund);
 *   4. it computes the Safe transaction hash locally (never trusting one relayed by the agent);
 *   5. it shows the decoded transaction, the findings and the explanation on its own display;
 *   6. only after the human's explicit confirmation does it sign the EIP-712 `Approval`.
 *
 * Nothing here talks to the chain: the returned signature is what `submitApproval` /
 * `submitApprovalP256` (or anyone relaying it) puts on-chain, and what `POST /v1/approvals`
 * accepts with `scheme: "eip712"` so one device signature serves both paths.
 */
import { computeApprovalChallenge, toDecimal, type AuditRecord, type TransactionIntent } from "@signhold/core";
import { getAddress, isAddress, type Address, type Hex } from "viem";
import { signApproval, signApprovalP256, p256PublicKeyFromPrivate, type P256PublicKey, type P256Signature, type TypedDataSigner } from "./approval.js";
import { computeSafeTxHash, isGuardRemovalTx, isPlainSafeTx, type SafeTransaction } from "./safeTx.js";
import { approvalTypedData, auditIdToBytes32, RECOVERY_AUDIT_ID, type ApprovalMessage } from "./typedData.js";

export class ApprovalRefusedError extends Error {
  constructor(message: string) {
    super(`REFUSING TO SIGN: ${message}`);
    this.name = "ApprovalRefusedError";
  }
}

/** Either a secp256k1 signer (any viem account) or a P-256 private key held by this device. */
export type DeviceSigner = { kind: "secp256k1"; signer: TypedDataSigner } | { kind: "p256"; privateKey: Uint8Array | Hex };

export interface DeviceApprovalResult {
  safeTxHash: Hex;
  message: ApprovalMessage;
  typedData: ReturnType<typeof approvalTypedData>;
  /** secp256k1: 65-byte signature and the approver address. */
  secp256k1?: { approver: Address; signature: Hex };
  /** P-256: raw `r`/`s` and the public key coordinates registered in the guard. */
  p256?: { publicKey: P256PublicKey; signature: P256Signature };
}

export interface ApproveSafeTransactionOptions {
  /** The audit id the agent reported. The record must carry the same id. */
  auditId: string;
  /** Obtains the sealed record: fetch it from the API with the DEVICE's credentials or read a copy obtained out of band. */
  loadRecord: () => Promise<unknown> | unknown;
  chainId: bigint | number;
  guard: Address;
  safe: Address;
  /** The Safe transaction as it will be executed. The hash is computed here, never trusted from the agent. */
  safeTx: SafeTransaction;
  /** Optional cross-check: the hash the service attested (from `POST /v1/attestations`). Must match. */
  expectedSafeTxHash?: Hex;
  signer: DeviceSigner;
  /** Trusted display. Defaults to stderr. */
  display?: (lines: string[]) => void;
  /** Explicit human confirmation. Must resolve to literal `true`; anything else aborts. */
  confirm: () => Promise<boolean> | boolean;
  /** Clock (unix ms). */
  now?: () => number;
}

/** Fetch `GET /v1/audit/:id` with the device's own API key (never the agent's). */
export function recordLoaderFromApi(baseUrl: string, apiKey: string, auditId: string, fetchImpl: typeof fetch = fetch): () => Promise<unknown> {
  if (!/^https?:\/\//.test(baseUrl)) throw new TypeError("baseUrl must be an http(s) URL");
  return async () => {
    const res = await fetchImpl(`${baseUrl.replace(/\/+$/, "")}/v1/audit/${encodeURIComponent(auditId)}`, { headers: { accept: "application/json", "x-api-key": apiKey } });
    if (!res.ok) throw new Error(`could not fetch audit record: HTTP ${res.status}`);
    return JSON.parse(await res.text());
  };
}

const short = (s: string) => (s.length > 18 ? `${s.slice(0, 10)}…${s.slice(-6)}` : s);
const stripControl = (s: string) => s.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 200);
const big = (v: unknown): bigint => (typeof v === "bigint" ? v : v === undefined || v === null ? 0n : BigInt(v as string | number));

function describeRecord(rec: AuditRecord): string[] {
  const { intent, decision } = rec;
  const sim = decision.simulation;
  const lines: string[] = [];
  lines.push(`audit id   : ${rec.id}`);
  lines.push(`agent      : ${rec.context.agentId}${rec.context.tenantId ? ` (tenant ${rec.context.tenantId})` : ""}`);
  lines.push(`chain      : ${intent.chain}${intent.chainId !== undefined ? ` / ${intent.chainId}` : ""}`);
  lines.push(`from (Safe): ${intent.from}`);
  lines.push(`to         : ${intent.to ?? "(none)"}`);
  if (intent.value !== undefined) lines.push(`native val : ${big(intent.value).toString()} wei`);
  if (sim) {
    lines.push(`simulation : ${sim.ok ? "ok" : `FAILED${sim.revertReason ? ` (${sim.revertReason})` : ""}`}`);
    if (sim.recipients?.length) lines.push(`recipients : ${sim.recipients.join(", ")}`);
    for (const d of sim.deltas) {
      const amt = toDecimal(big(d.amount), d.decimals);
      lines.push(`  delta    : ${amt > 0 ? "+" : ""}${amt} ${d.symbol ?? short(d.asset)}${d.usdValue !== undefined ? ` (~$${d.usdValue.toFixed(2)})` : ""}`);
    }
    for (const a of sim.approvals) {
      lines.push(`  approval : ${short(a.token)} -> spender ${a.spender}${a.unlimited ? " UNLIMITED" : ` ${big(a.next).toString()}`}${a.spenderIsContract === false ? " (EOA spender)" : ""}`);
    }
    if (sim.contractsTouched.length) lines.push(`contracts  : ${sim.contractsTouched.join(", ")}`);
    if (sim.newContracts.length) lines.push(`NEW/unknown: ${sim.newContracts.join(", ")}`);
    for (const w of sim.warnings) lines.push(`  warning  : ${w}`);
  }
  lines.push(`verdict    : ${decision.verdict}  risk ${decision.riskScore}/100  policy ${decision.policyId}@${decision.policyVersion}`);
  for (const f of decision.findings) lines.push(`  finding  : [${f.verdict}] ${f.ruleId}: ${f.message}`);
  lines.push(`explanation: ${decision.explanation}`);
  if (intent.description) lines.push(`AGENT-SUPPLIED TEXT (untrusted, not evidence): ${JSON.stringify(stripControl(intent.description))}`);
  return lines;
}

function describeSafeTx(safe: Address, tx: SafeTransaction, hash: Hex, guard: Address, chainId: bigint | number): string[] {
  return [
    `Safe       : ${safe} (chain ${chainId}) guarded by ${guard}`,
    `safeTx.to  : ${tx.to}${tx.to.toLowerCase() === safe.toLowerCase() ? "  <-- THE SAFE ITSELF (configuration change)" : tx.to.toLowerCase() === guard.toLowerCase() ? "  <-- THE GUARD (re-key / pause / unpause)" : ""}`,
    `safeTx.val : ${tx.value.toString()} wei`,
    `safeTx.data: ${tx.data.length > 74 ? `${tx.data.slice(0, 74)}… (${(tx.data.length - 2) / 2} bytes)` : tx.data}`,
    `operation  : ${tx.operation === 0 ? "Call" : "DelegateCall"}   nonce ${tx.nonce.toString()}   gasPrice ${tx.gasPrice.toString()}`,
    `safeTxHash : ${hash}`,
  ];
}

function asRecord(raw: unknown): AuditRecord {
  if (!raw || typeof raw !== "object") throw new ApprovalRefusedError("audit record is not an object");
  const r = raw as AuditRecord;
  if (typeof r.id !== "string" || !r.intent || !r.decision || !r.context) throw new ApprovalRefusedError("audit record is malformed");
  return r;
}

function intentMatchesSafeTx(intent: TransactionIntent, chainId: bigint | number, safe: Address, tx: SafeTransaction): string | undefined {
  if (intent.chain !== "evm") return `record is for chain '${intent.chain}', not evm`;
  if (intent.chainId === undefined || BigInt(intent.chainId) !== BigInt(chainId)) return `record chain id ${String(intent.chainId)} != ${String(chainId)}`;
  if (!isAddress(intent.from) || getAddress(intent.from) !== getAddress(safe)) return "record `from` is not the Safe";
  if (!intent.to || !isAddress(intent.to) || getAddress(intent.to) !== getAddress(tx.to)) return "record `to` differs from the Safe transaction";
  if (big(intent.value) !== tx.value) return "record `value` differs from the Safe transaction";
  if ((intent.data ?? "0x").toLowerCase() !== tx.data.toLowerCase()) return "record calldata differs from the Safe transaction";
  if (!isPlainSafeTx(tx)) return "Safe transaction is not a plain call without gas refund";
  return undefined;
}

async function signMessage(signer: DeviceSigner, domain: { chainId: bigint | number; guard: Address }, message: ApprovalMessage): Promise<Pick<DeviceApprovalResult, "secp256k1" | "p256">> {
  if (signer.kind === "secp256k1") {
    return { secp256k1: { approver: signer.signer.address, signature: await signApproval(signer.signer, domain, message) } };
  }
  return { p256: { publicKey: p256PublicKeyFromPrivate(signer.privateKey), signature: signApprovalP256(signer.privateKey, domain, message) } };
}

/**
 * Review and approve an escalated Safe transaction on the device. Throws `ApprovalRefusedError`
 * (and never signs) when the record, the transaction or the human's answer does not check out.
 */
export async function approveSafeTransaction(opts: ApproveSafeTransactionOptions): Promise<DeviceApprovalResult> {
  const display = opts.display ?? ((lines) => console.error(lines.join("\n")));
  const rec = asRecord(await opts.loadRecord());
  if (rec.id !== opts.auditId) throw new ApprovalRefusedError(`record id ${rec.id} does not match auditId ${opts.auditId}`);
  if ((rec.type ?? "check") !== "check") throw new ApprovalRefusedError(`record is a '${rec.type}' record, not a check`);
  if (rec.decision.verdict === "block") throw new ApprovalRefusedError("the service BLOCKED this transaction; blocked transactions are never approvable");
  if (rec.decision.verdict !== "escalate" && rec.decision.verdict !== "allow") throw new ApprovalRefusedError(`unknown verdict '${String(rec.decision.verdict)}'`);

  if (rec.approvalRequest) {
    const challenge = computeApprovalChallenge({
      auditId: rec.id,
      intent: rec.intent,
      decision: rec.decision,
      policyId: rec.decision.policyId,
      policyVersion: rec.decision.policyVersion,
      agentId: rec.context.agentId,
      issuedAt: rec.approvalRequest.issuedAt,
    });
    if (rec.approvalRequest.challenge !== challenge) throw new ApprovalRefusedError("the record's challenge does not match the record's own contents (record tampered)");
  }

  const mismatch = intentMatchesSafeTx(rec.intent, opts.chainId, opts.safe, opts.safeTx);
  if (mismatch) throw new ApprovalRefusedError(`the Safe transaction is not the one the service decided on: ${mismatch}`);

  const safeTxHash = computeSafeTxHash(opts.chainId, opts.safe, opts.safeTx);
  if (opts.expectedSafeTxHash && opts.expectedSafeTxHash.toLowerCase() !== safeTxHash.toLowerCase()) {
    throw new ApprovalRefusedError("the attested safeTxHash does not match the transaction shown (relayed hash points elsewhere)");
  }
  const sensitive = opts.safeTx.to.toLowerCase() === opts.safe.toLowerCase() || opts.safeTx.to.toLowerCase() === opts.guard.toLowerCase();
  if (rec.decision.verdict === "allow" && !sensitive) {
    throw new ApprovalRefusedError("the service allowed this transaction and it touches neither the Safe nor the guard; no human approval is needed or useful");
  }

  display([
    "",
    "================ ESCALATED SAFE TRANSACTION — REVIEW BEFORE APPROVING ================",
    ...describeRecord(rec),
    "---- what will execute on-chain (hash computed on this device) ----",
    ...describeSafeTx(opts.safe, opts.safeTx, safeTxHash, opts.guard, opts.chainId),
    "=======================================================================================",
    "",
  ]);
  if ((await opts.confirm()) !== true) throw new ApprovalRefusedError("aborted by approver");

  const message: ApprovalMessage = {
    safe: getAddress(opts.safe),
    safeTxHash,
    auditId: auditIdToBytes32(rec.id),
    approvedAt: BigInt(Math.floor((opts.now ?? Date.now)() / 1000)),
  };
  const domain = { chainId: opts.chainId, guard: opts.guard };
  return { safeTxHash, message, typedData: approvalTypedData(domain, message), ...(await signMessage(opts.signer, domain, message)) };
}

export interface ApproveGuardRemovalOptions {
  chainId: bigint | number;
  guard: Address;
  safe: Address;
  /** Must be exactly `safe.setGuard(address(0))` as a plain call. */
  safeTx: SafeTransaction;
  signer: DeviceSigner;
  display?: (lines: string[]) => void;
  confirm: () => Promise<boolean> | boolean;
  now?: () => number;
}

/**
 * Owner escape hatch: approve removal of the guard without a Signhold attestation (service down,
 * attestor key lost). Refuses anything that is not exactly `setGuard(address(0))` on the Safe.
 */
export async function approveGuardRemoval(opts: ApproveGuardRemovalOptions): Promise<DeviceApprovalResult> {
  const display = opts.display ?? ((lines) => console.error(lines.join("\n")));
  if (!isGuardRemovalTx(opts.safe, opts.safeTx)) throw new ApprovalRefusedError("recovery approvals are only valid for exactly `setGuard(address(0))` on the Safe");
  const safeTxHash = computeSafeTxHash(opts.chainId, opts.safe, opts.safeTx);
  display([
    "",
    "================ GUARD REMOVAL (RECOVERY, NO SIGNHOLD ATTESTATION) ================",
    "After this executes the Safe is NO LONGER protected by SignholdGuard.",
    ...describeSafeTx(opts.safe, opts.safeTx, safeTxHash, opts.guard, opts.chainId),
    "===================================================================================",
    "",
  ]);
  if ((await opts.confirm()) !== true) throw new ApprovalRefusedError("aborted by approver");
  const message: ApprovalMessage = { safe: getAddress(opts.safe), safeTxHash, auditId: RECOVERY_AUDIT_ID, approvedAt: BigInt(Math.floor((opts.now ?? Date.now)() / 1000)) };
  const domain = { chainId: opts.chainId, guard: opts.guard };
  return { safeTxHash, message, typedData: approvalTypedData(domain, message), ...(await signMessage(opts.signer, domain, message)) };
}
