import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { before, describe, it } from "node:test";
import { bytesToHex, encodeAbiParameters, encodeFunctionData, getAddress, hashTypedData, keccak256, parseEventLogs, toHex, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  APPROVAL_TYPES,
  ATTESTATION_TYPES,
  GUARD_VERDICT,
  RECOVERY_AUDIT_ID,
  SIGNHOLD_GUARD_ABI,
  SafeOperation,
  approvalTypedData,
  attestationTypedData,
  auditIdToBytes32,
  computeSafeTxHash,
  createAttestor,
  encodeSetGuard,
  generateP256PrivateKey,
  guardDomain,
  p256ApproverId,
  p256PublicKeyFromPrivate,
  plainSafeTx,
  recoverApprovalSigner,
  recoverAttestationSigner,
  signApproval,
  signApprovalP256,
  verifyApprovalP256,
  type ApprovalMessage,
  type AttestationMessage,
  type SafeTransaction,
} from "../src/index.js";
import {
  APPROVAL_WINDOW,
  ERC165_INTERFACE_ID,
  P256_PRECOMPILE,
  SAFE_ARTIFACT,
  SAFE_GUARD_INTERFACE_ID,
  deployFixture,
  erc20Approve,
  erc20Transfer,
  execSafeTx,
  execSafeTxExpectRevert,
  guardAt,
  now,
  readGuardSlot,
  recordGas,
  revertName,
  safeNonce,
  type Fixture,
} from "../testlib/helpers.js";

const require = createRequire(import.meta.url);
const UINT256_MAX = (1n << 256n) - 1n;

// ---- Per-fixture helpers modelling the three parties ----

function domainOf(fx: Fixture) {
  return { chainId: fx.chainId, guard: fx.guard };
}

async function attest(fx: Fixture, tx: SafeTransaction, verdict: "allow" | "escalate", opts: { auditId?: string; expiresIn?: bigint; signer?: typeof fx.attestor; submitter?: typeof fx.relayer } = {}) {
  const signerAccount = opts.signer ?? fx.attestor;
  const message: AttestationMessage = {
    safe: fx.safe,
    safeTxHash: computeSafeTxHash(fx.chainId, fx.safe, tx),
    verdict: GUARD_VERDICT[verdict],
    expiresAt: (await now(fx)) + (opts.expiresIn ?? 900n),
    auditId: auditIdToBytes32(opts.auditId ?? "audit-1"),
  };
  const signature = await signerAccount.signTypedData(attestationTypedData(domainOf(fx), message));
  const g = guardAt(fx, opts.submitter);
  const hash = await g.write.submitAttestation([message.safeTxHash, message.verdict, message.expiresAt, message.auditId, signature]);
  const receipt = await fx.publicClient.waitForTransactionReceipt({ hash });
  recordGas("submitAttestation", receipt);
  return { message, signature, receipt };
}

async function approve(fx: Fixture, tx: SafeTransaction, opts: { auditId?: string | Hex; signer?: typeof fx.approver; claimAs?: Address; approvedAt?: bigint } = {}) {
  const signer = opts.signer ?? fx.approver;
  const auditId = opts.auditId === undefined ? auditIdToBytes32("audit-1") : opts.auditId.startsWith("0x") && opts.auditId.length === 66 ? (opts.auditId as Hex) : auditIdToBytes32(opts.auditId);
  const message: ApprovalMessage = { safe: fx.safe, safeTxHash: computeSafeTxHash(fx.chainId, fx.safe, tx), auditId, approvedAt: opts.approvedAt ?? (await now(fx)) };
  const signature = await signApproval(signer, domainOf(fx), message);
  const hash = await guardAt(fx).write.submitApproval([message.safeTxHash, message.auditId, opts.claimAs ?? signer.address, message.approvedAt, signature]);
  const receipt = await fx.publicClient.waitForTransactionReceipt({ hash });
  recordGas("submitApproval (secp256k1)", receipt);
  return { message, signature, receipt };
}

async function expectRevert(p: Promise<unknown>, name: string): Promise<void> {
  try {
    await p;
  } catch (err) {
    assert.equal(revertName(err), name);
    return;
  }
  assert.fail(`expected revert ${name}`);
}

// Every transfer gets a unique amount so that transactions built at the same (unconsumed) Safe nonce
// in different tests never share a hash, i.e. never inherit each other's attestations.
let seq = 0n;
const transferTx = async (fx: Fixture, amount?: bigint) => plainSafeTx({ to: fx.token, data: erc20Transfer(fx.recipient, amount ?? 5_000_000n + ++seq), nonce: await safeNonce(fx) });
const tokenBalance = (fx: Fixture, who: Address) =>
  fx.publicClient.readContract({ address: fx.token, abi: [{ type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] }], functionName: "balanceOf", args: [who] });

describe("SignholdGuard", { concurrency: false }, () => {
  let fx: Fixture;
  before(async () => {
    fx = await deployFixture();
  });

  describe("parity with Safe and off-chain builders", () => {
    it("is installed on a real Safe 1.5.0 and advertises the Safe guard interface id", async () => {
      assert.equal(await readGuardSlot(fx), fx.guard);
      const g = guardAt(fx);
      assert.equal(await g.read.supportsInterface([SAFE_GUARD_INTERFACE_ID]), true);
      assert.equal(await g.read.supportsInterface([ERC165_INTERFACE_ID]), true);
      assert.equal(await g.read.supportsInterface(["0xdeadbeef"]), false);
      assert.equal(getAddress(await g.read.safe()), fx.safe);
      assert.equal(getAddress(await g.read.attestor()), fx.attestor.address);
      assert.equal(await g.read.approvers([fx.approver.address]), true);
      assert.equal(await g.read.RECOVERY_AUDIT_ID(), RECOVERY_AUDIT_ID);
    });

    it("computeSafeTxHash matches Safe.getTransactionHash for the current nonce", async () => {
      const tx = await transferTx(fx);
      const onChain = await fx.publicClient.readContract({
        address: fx.safe,
        abi: SAFE_ARTIFACT.abi,
        functionName: "getTransactionHash",
        args: [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, tx.nonce],
      });
      assert.equal(onChain, computeSafeTxHash(fx.chainId, fx.safe, tx));
    });

    it("EIP-712 digests match the contract's hashAttestation / hashApproval and the type hashes", async () => {
      const g = guardAt(fx);
      const h = computeSafeTxHash(fx.chainId, fx.safe, await transferTx(fx));
      const att: AttestationMessage = { safe: fx.safe, safeTxHash: h, verdict: 2, expiresAt: 1_700_000_000n, auditId: auditIdToBytes32("x") };
      assert.equal(await g.read.hashAttestation([h, att.verdict, att.expiresAt, att.auditId]), hashTypedData(attestationTypedData(domainOf(fx), att)));
      const ap: ApprovalMessage = { safe: fx.safe, safeTxHash: h, auditId: att.auditId, approvedAt: 1_700_000_000n };
      assert.equal(await g.read.hashApproval([h, ap.auditId, ap.approvedAt]), hashTypedData(approvalTypedData(domainOf(fx), ap)));
      const d = guardDomain(domainOf(fx));
      assert.equal(
        await g.read.domainSeparator(),
        keccak256(
          encodeAbiParameters(
            [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
            [keccak256(toHex("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")), keccak256(toHex(d.name)), keccak256(toHex(d.version)), d.chainId, d.verifyingContract],
          ),
        ),
      );
      const sig = await fx.attestor.signTypedData(attestationTypedData(domainOf(fx), att));
      assert.equal(await recoverAttestationSigner(domainOf(fx), att, sig), fx.attestor.address);
      const asig = await signApproval(fx.approver, domainOf(fx), ap);
      assert.equal(await recoverApprovalSigner(domainOf(fx), ap, asig), fx.approver.address);
      assert.equal(await recoverApprovalSigner(domainOf(fx), ap, "0x1234"), undefined);
      assert.deepEqual(Object.keys(ATTESTATION_TYPES), ["Attestation"]);
      assert.deepEqual(Object.keys(APPROVAL_TYPES), ["Approval"]);
    });

    it("the committed ABI/bytecode module matches the compiled artifact", () => {
      const artifact = JSON.parse(readFileSync(require.resolve("../artifacts/contracts/SignholdGuard.sol/SignholdGuard.json"), "utf8")) as { abi: unknown };
      assert.deepEqual(SIGNHOLD_GUARD_ABI, artifact.abi);
    });

    it("createAttestor derives the address and signs attestations the contract accepts", async () => {
      const pk = generatePrivateKey();
      const attestor = createAttestor({ privateKey: pk });
      assert.equal(attestor.address, privateKeyToAccount(pk).address);
      const tx = await transferTx(fx);
      const message: AttestationMessage = { safe: fx.safe, safeTxHash: computeSafeTxHash(fx.chainId, fx.safe, tx), verdict: 1, expiresAt: (await now(fx)) + 60n, auditId: auditIdToBytes32("z") };
      const sig = await attestor.signAttestation(domainOf(fx), message);
      assert.equal(await recoverAttestationSigner(domainOf(fx), message, sig), attestor.address);
      // ... but a key the guard does not know is still refused on-chain.
      await expectRevert(guardAt(fx).write.submitAttestation([message.safeTxHash, 1, message.expiresAt, message.auditId, sig]), "InvalidAttestorSignature");
    });
  });

  describe("verdict enforcement", () => {
    it("allow: attested transaction executes and the entries are cleared afterwards", async () => {
      const tx = await transferTx(fx);
      const before_ = await tokenBalance(fx, fx.recipient);
      const { message } = await attest(fx, tx, "allow");
      const receipt = await execSafeTx(fx, tx);
      recordGas("execTransaction (allow)", receipt);
      assert.equal(await tokenBalance(fx, fx.recipient), before_ + 5_000_000n + seq);
      const checked = parseEventLogs({ abi: SIGNHOLD_GUARD_ABI, logs: receipt.logs, eventName: "TransactionChecked" })[0];
      assert.equal(checked.args.verdict, 1);
      assert.equal(checked.args.approvalConsumed, false);
      const executed = parseEventLogs({ abi: SIGNHOLD_GUARD_ABI, logs: receipt.logs, eventName: "TransactionExecuted" })[0];
      assert.equal(executed.args.success, true);
      const [verdict] = await guardAt(fx).read.attestations([message.safeTxHash]);
      assert.equal(verdict, 0);
    });

    it("block (never attested): an unlimited approve reverts NotAttested and nothing moves", async () => {
      const tx = plainSafeTx({ to: fx.token, data: erc20Approve(fx.stranger.address, UINT256_MAX), nonce: await safeNonce(fx) });
      assert.equal(await execSafeTxExpectRevert(fx, tx), "NotAttested");
      const allowance = await fx.publicClient.readContract({
        address: fx.token,
        abi: [{ type: "function", name: "allowance", stateMutability: "view", inputs: [{ type: "address" }, { type: "address" }], outputs: [{ type: "uint256" }] }],
        functionName: "allowance",
        args: [fx.safe, fx.stranger.address],
      });
      assert.equal(allowance, 0n);
    });

    it("escalate without approval reverts ApprovalRequired; the nonce is not consumed", async () => {
      const nonce = await safeNonce(fx);
      const tx = await transferTx(fx, 500_000_000n);
      await attest(fx, tx, "escalate");
      assert.equal(await execSafeTxExpectRevert(fx, tx), "ApprovalRequired");
      assert.equal(await safeNonce(fx), nonce);
    });

    it("escalate with a device approval executes exactly once; the approval cannot be replayed", async () => {
      const tx = await transferTx(fx, 500_000_000n);
      const { message: att } = await attest(fx, tx, "escalate", { auditId: "audit-esc" });
      const { message, signature } = await approve(fx, tx, { auditId: "audit-esc" });
      const receipt = await execSafeTx(fx, tx);
      recordGas("execTransaction (escalate + approval)", receipt);
      const checked = parseEventLogs({ abi: SIGNHOLD_GUARD_ABI, logs: receipt.logs, eventName: "TransactionChecked" })[0];
      assert.equal(checked.args.approvalConsumed, true);
      assert.equal(checked.args.approverId, `0x${fx.approver.address.slice(2).toLowerCase().padStart(64, "0")}`);
      const [, , approvedAt] = await guardAt(fx).read.approvals([att.safeTxHash]);
      assert.equal(approvedAt, 0n);
      // Replaying the same signed approval: the attestation is gone with the executed transaction.
      await expectRevert(guardAt(fx).write.submitApproval([message.safeTxHash, message.auditId, fx.approver.address, message.approvedAt, signature]), "NotAttested");
      // Re-attesting the same (already executed) hash cannot resurrect it: the Safe nonce has moved on.
      const next = await transferTx(fx, 500_000_000n);
      assert.notEqual(computeSafeTxHash(fx.chainId, fx.safe, next), message.safeTxHash);
      await attest(fx, next, "escalate", { auditId: "audit-esc" });
      await expectRevert(guardAt(fx).write.submitApproval([computeSafeTxHash(fx.chainId, fx.safe, next), message.auditId, fx.approver.address, message.approvedAt, signature]), "InvalidApproverSignature");
      assert.equal(await execSafeTxExpectRevert(fx, next), "ApprovalRequired");
    });

    it("expired attestation reverts (and expiry is validated at submission too)", async () => {
      const tx = await transferTx(fx);
      await attest(fx, tx, "allow", { expiresIn: 100n });
      await fx.conn.networkHelpers.time.increase(101);
      assert.equal(await execSafeTxExpectRevert(fx, tx), "AttestationExpired");
      const h = computeSafeTxHash(fx.chainId, fx.safe, tx);
      const past: AttestationMessage = { safe: fx.safe, safeTxHash: h, verdict: 1, expiresAt: (await now(fx)) - 1n, auditId: auditIdToBytes32("p") };
      await expectRevert(guardAt(fx).write.submitAttestation([h, 1, past.expiresAt, past.auditId, await fx.attestor.signTypedData(attestationTypedData(domainOf(fx), past))]), "AttestationExpiredAtSubmission");
      const far: AttestationMessage = { ...past, expiresAt: (await now(fx)) + 3601n + 10n };
      await expectRevert(guardAt(fx).write.submitAttestation([h, 1, far.expiresAt, far.auditId, await fx.attestor.signTypedData(attestationTypedData(domainOf(fx), far))]), "AttestationTooFarInFuture");
    });

    it("attestation signed by the wrong key, a bad verdict, or a bad audit id is refused", async () => {
      const tx = await transferTx(fx);
      await expectRevert(attest(fx, tx, "allow", { signer: fx.stranger }), "InvalidAttestorSignature");
      await expectRevert(attest(fx, tx, "allow", { signer: fx.approver }), "InvalidAttestorSignature");
      const h = computeSafeTxHash(fx.chainId, fx.safe, tx);
      const exp = (await now(fx)) + 60n;
      await expectRevert(guardAt(fx).write.submitAttestation([h, 3, exp, auditIdToBytes32("q"), "0x"]), "InvalidVerdict");
      await expectRevert(guardAt(fx).write.submitAttestation([h, 0, exp, auditIdToBytes32("q"), "0x"]), "InvalidVerdict");
      await expectRevert(guardAt(fx).write.submitAttestation([h, 1, exp, `0x${"0".repeat(64)}`, "0x"]), "InvalidAuditId");
      await expectRevert(guardAt(fx).write.submitAttestation([h, 1, exp, RECOVERY_AUDIT_ID, "0x"]), "InvalidAuditId");
      await expectRevert(guardAt(fx).write.submitAttestation([h, 1, exp, auditIdToBytes32("q"), "0x"]), "InvalidAttestorSignature");
      assert.equal(await execSafeTxExpectRevert(fx, tx), "NotAttested");
    });

    it("a new attestation may tighten (allow -> escalate) but never loosen (escalate -> allow)", async () => {
      const tx = await transferTx(fx);
      await attest(fx, tx, "allow", { auditId: "a1" });
      await attest(fx, tx, "escalate", { auditId: "a2" });
      await expectRevert(attest(fx, tx, "allow", { auditId: "a3" }), "AttestationDowngrade");
      await attest(fx, tx, "escalate", { auditId: "a4" }); // same level: fine
      assert.equal(await execSafeTxExpectRevert(fx, tx), "ApprovalRequired");
      // An approval bound to a superseded audit id does not count.
      await expectRevert(approve(fx, tx, { auditId: "a2" }), "AuditIdMismatch");
      await approve(fx, tx, { auditId: "a4" });
      await execSafeTx(fx, tx);
    });
  });

  describe("approvals", () => {
    it("approval by an unregistered key, or claiming a registered id with another key, is refused", async () => {
      const tx = await transferTx(fx);
      await attest(fx, tx, "escalate");
      await expectRevert(approve(fx, tx, { signer: fx.stranger }), "UnregisteredApprover");
      await expectRevert(approve(fx, tx, { signer: fx.stranger, claimAs: fx.approver.address }), "InvalidApproverSignature");
      await expectRevert(approve(fx, tx, { signer: fx.attestor, claimAs: fx.approver.address }), "InvalidApproverSignature");
      assert.equal(await execSafeTxExpectRevert(fx, tx), "ApprovalRequired");
    });

    it("an approval for a different transaction hash does not transfer", async () => {
      const a = await transferTx(fx, 1n);
      const b = { ...a, data: erc20Transfer(fx.stranger.address, 999_000_000n + ++seq) }; // same nonce, different payload
      await attest(fx, a, "escalate", { auditId: "ab" });
      await attest(fx, b, "escalate", { auditId: "ab" });
      const { message, signature } = await approve(fx, b, { auditId: "ab" });
      // Re-binding the device's signature for B to A's hash fails signature recovery…
      await expectRevert(guardAt(fx).write.submitApproval([computeSafeTxHash(fx.chainId, fx.safe, a), message.auditId, fx.approver.address, message.approvedAt, signature]), "InvalidApproverSignature");
      // …and A has no approval of its own.
      assert.equal(await execSafeTxExpectRevert(fx, a), "ApprovalRequired");
      await execSafeTx(fx, b);
    });

    it("approvals expire, cannot be dated in the future, and cannot be overwritten while live", async () => {
      const tx = await transferTx(fx);
      await attest(fx, tx, "escalate", { expiresIn: 3000n });
      const t = await now(fx);
      await expectRevert(approve(fx, tx, { approvedAt: t + 600n }), "ApprovedAtOutOfWindow");
      await expectRevert(approve(fx, tx, { approvedAt: t - APPROVAL_WINDOW }), "ApprovedAtOutOfWindow");
      await expectRevert(approve(fx, tx, { approvedAt: 0n }), "ApprovedAtOutOfWindow");
      await approve(fx, tx, { approvedAt: t });
      await expectRevert(approve(fx, tx, { approvedAt: t + 1n }), "ApprovalAlreadySubmitted");
      await fx.conn.networkHelpers.time.increase(Number(APPROVAL_WINDOW) + 1);
      assert.equal(await execSafeTxExpectRevert(fx, tx), "ApprovalExpired");
      // An expired approval can be replaced by a fresh one.
      await approve(fx, tx);
      await execSafeTx(fx, tx);
    });

    it("approval submission needs an unexpired attestation with the same audit id", async () => {
      const tx = await transferTx(fx);
      await expectRevert(approve(fx, tx), "NotAttested");
      await expectRevert(approve(fx, tx, { auditId: `0x${"0".repeat(64)}` }), "InvalidAuditId");
      await attest(fx, tx, "escalate", { auditId: "k1", expiresIn: 50n });
      await expectRevert(approve(fx, tx, { auditId: "k2" }), "AuditIdMismatch");
      await fx.conn.networkHelpers.time.increase(51);
      await expectRevert(approve(fx, tx, { auditId: "k1" }), "AttestationExpired");
    });
  });

  describe("self-protection", () => {
    it("a transaction to the guard needs a device approval even when the service allowed it", async () => {
      const newAttestor = privateKeyToAccount(generatePrivateKey());
      const tx = plainSafeTx({ to: fx.guard, data: encodeFunctionData({ abi: SIGNHOLD_GUARD_ABI, functionName: "setAttestor", args: [newAttestor.address] }), nonce: await safeNonce(fx) });
      await attest(fx, tx, "allow", { auditId: "rekey" });
      assert.equal(await execSafeTxExpectRevert(fx, tx), "ApprovalRequired");
      await approve(fx, tx, { auditId: "rekey" });
      const receipt = await execSafeTx(fx, tx);
      recordGas("execTransaction (setAttestor, approved)", receipt);
      assert.equal(getAddress(await guardAt(fx).read.attestor()), newAttestor.address);
      // Put the original attestor back for the rest of the suite (through the same gate).
      const back = plainSafeTx({ to: fx.guard, data: encodeFunctionData({ abi: SIGNHOLD_GUARD_ABI, functionName: "setAttestor", args: [fx.attestor.address] }), nonce: await safeNonce(fx) });
      const msg: AttestationMessage = { safe: fx.safe, safeTxHash: computeSafeTxHash(fx.chainId, fx.safe, back), verdict: 1, expiresAt: (await now(fx)) + 900n, auditId: auditIdToBytes32("back") };
      await guardAt(fx).write.submitAttestation([msg.safeTxHash, 1, msg.expiresAt, msg.auditId, await newAttestor.signTypedData(attestationTypedData(domainOf(fx), msg))]);
      await approve(fx, back, { auditId: "back" });
      await execSafeTx(fx, back);
      assert.equal(getAddress(await guardAt(fx).read.attestor()), fx.attestor.address);
    });

    it("any transaction to the Safe itself (setGuard, enableModule, addOwner, ...) needs a device approval", async () => {
      const tx = plainSafeTx({ to: fx.safe, data: encodeFunctionData({ abi: SAFE_ARTIFACT.abi, functionName: "enableModule", args: [fx.stranger.address] }), nonce: await safeNonce(fx) });
      await attest(fx, tx, "allow", { auditId: "mod" });
      assert.equal(await execSafeTxExpectRevert(fx, tx), "ApprovalRequired");
    });

    it("delegatecalls and refund-bearing transactions need a device approval", async () => {
      const dc: SafeTransaction = { ...(await transferTx(fx)), operation: SafeOperation.DelegateCall };
      await attest(fx, dc, "allow", { auditId: "dc" });
      assert.equal(await execSafeTxExpectRevert(fx, dc), "ApprovalRequired");
      const refund: SafeTransaction = { ...(await transferTx(fx)), gasPrice: 1n, refundReceiver: fx.stranger.address };
      await attest(fx, refund, "allow", { auditId: "refund" });
      assert.equal(await execSafeTxExpectRevert(fx, refund), "ApprovalRequired");
    });

    it("administration is only reachable through the Safe, and key separation is enforced", async () => {
      const g = guardAt(fx);
      await expectRevert(g.write.setAttestor([fx.stranger.address]), "OnlySafe");
      await expectRevert(g.write.setApprover([fx.stranger.address, true]), "OnlySafe");
      await expectRevert(g.write.setPaused([true]), "OnlySafe");
      await expectRevert(g.write.setP256Enabled([true]), "OnlySafe");
      await expectRevert(g.write.checkTransaction([fx.token, 0n, "0x", 0, 0n, 0n, 0n, fx.token, fx.token, "0x", fx.relayer.account.address]), "OnlySafe");
      // A foreign caller's checkAfterExecution is a no-op (see the misconfigured-Safe test), never a state change.
      await g.write.checkAfterExecution([`0x${"11".repeat(32)}`, true]);
      // Through the Safe: registering the attestor as an approver (or vice versa) is refused.
      const tx = plainSafeTx({ to: fx.guard, data: encodeFunctionData({ abi: SIGNHOLD_GUARD_ABI, functionName: "setApprover", args: [fx.attestor.address, true] }), nonce: await safeNonce(fx) });
      await attest(fx, tx, "escalate", { auditId: "ks" });
      await approve(fx, tx, { auditId: "ks" });
      assert.equal(await execSafeTxExpectRevert(fx, tx), "KeySeparation");
      const tx2 = plainSafeTx({ to: fx.guard, data: encodeFunctionData({ abi: SIGNHOLD_GUARD_ABI, functionName: "setAttestor", args: [fx.approver.address] }), nonce: await safeNonce(fx) });
      await attest(fx, tx2, "escalate", { auditId: "ks2" });
      await approve(fx, tx2, { auditId: "ks2" });
      assert.equal(await execSafeTxExpectRevert(fx, tx2), "KeySeparation");
    });
  });

  describe("misconfiguration", () => {
    it("a Safe the guard was not deployed for can do nothing through it except remove it again", async () => {
      // A second real Safe on the same chain mistakenly installs the first Safe's guard.
      const other = await deployFixture({ conn: fx.conn, installGuard: false });
      const wrongGuard = fx.guard;
      await execSafeTx(other, plainSafeTx({ to: other.safe, data: encodeSetGuard(wrongGuard), nonce: await safeNonce(other) }));
      assert.equal(await readGuardSlot(other), wrongGuard);
      const otherTx = { ...(await transferTx(other)) };
      // No attestation can help: the guard answers OnlySafe to anything but its own Safe...
      assert.equal(await execSafeTxExpectRevert(other, otherTx), "OnlySafe");
      const sensitive = plainSafeTx({ to: other.safe, data: encodeFunctionData({ abi: SAFE_ARTIFACT.abi, functionName: "enableModule", args: [other.stranger.address] }), nonce: await safeNonce(other) });
      assert.equal(await execSafeTxExpectRevert(other, sensitive), "OnlySafe");
      // ...except the exact removal transaction, so the mistake does not brick the other Safe.
      await execSafeTx(other, plainSafeTx({ to: other.safe, data: encodeSetGuard("0x0000000000000000000000000000000000000000"), nonce: await safeNonce(other) }));
      assert.equal(await readGuardSlot(other), "0x0000000000000000000000000000000000000000");
      // The real Safe is unaffected.
      assert.equal(await readGuardSlot(fx), fx.guard);
    });
  });

  describe("pause", () => {
    it("paused: ordinary transactions revert even with an allow attestation; approved unpause lifts it", async () => {
      const pause = plainSafeTx({ to: fx.guard, data: encodeFunctionData({ abi: SIGNHOLD_GUARD_ABI, functionName: "setPaused", args: [true] }), nonce: await safeNonce(fx) });
      await attest(fx, pause, "escalate", { auditId: "pause" });
      await approve(fx, pause, { auditId: "pause" });
      await execSafeTx(fx, pause);
      assert.equal(await guardAt(fx).read.paused(), true);

      const tx = await transferTx(fx);
      await attest(fx, tx, "allow", { auditId: "while-paused" });
      assert.equal(await execSafeTxExpectRevert(fx, tx), "GuardPaused");
      await approve(fx, tx, { auditId: "while-paused" });
      assert.equal(await execSafeTxExpectRevert(fx, tx), "GuardPaused");

      // Unpausing still needs attestation + approval (to == guard), and is possible while paused.
      const unpause = plainSafeTx({ to: fx.guard, data: encodeFunctionData({ abi: SIGNHOLD_GUARD_ABI, functionName: "setPaused", args: [false] }), nonce: await safeNonce(fx) });
      await attest(fx, unpause, "allow", { auditId: "unpause" });
      assert.equal(await execSafeTxExpectRevert(fx, unpause), "ApprovalRequired");
      await approve(fx, unpause, { auditId: "unpause" });
      await execSafeTx(fx, unpause);
      assert.equal(await guardAt(fx).read.paused(), false);
    });
  });

  describe("guard removal (owner escape hatch)", () => {
    it("removing the guard needs a device approval; a recovery approval works without the service", async () => {
      const removal = () => plainSafeTx({ to: fx.safe, data: encodeSetGuard("0x0000000000000000000000000000000000000000"), nonce: safeNonceSync });
      let safeNonceSync = await safeNonce(fx);
      // (1) attested allow but no approval => refused
      await attest(fx, removal(), "allow", { auditId: "rm" });
      assert.equal(await execSafeTxExpectRevert(fx, removal()), "ApprovalRequired");
      // (2) a recovery approval is not a free pass for anything else
      const other = await transferTx(fx);
      await approve(fx, other, { auditId: RECOVERY_AUDIT_ID });
      assert.equal(await execSafeTxExpectRevert(fx, other), "NotAttested");
      // (3) with the device's approval (bound to the attestation) the owners can remove the guard
      await approve(fx, removal(), { auditId: "rm" });
      const receipt = await execSafeTx(fx, removal());
      recordGas("execTransaction (setGuard(0), approved)", receipt);
      assert.equal(await readGuardSlot(fx), "0x0000000000000000000000000000000000000000");
      // Re-install and exercise the no-attestation recovery path.
      await execSafeTx(fx, plainSafeTx({ to: fx.safe, data: encodeSetGuard(fx.guard), nonce: await safeNonce(fx) }));
      assert.equal(await readGuardSlot(fx), fx.guard);
      safeNonceSync = await safeNonce(fx);
      // Unattested removal is reachable, but still needs the device.
      assert.equal(await execSafeTxExpectRevert(fx, removal()), "ApprovalRequired");
      await expectRevert(approve(fx, removal(), { auditId: "unattested" }), "NotAttested");
      await approve(fx, removal(), { auditId: RECOVERY_AUDIT_ID });
      await execSafeTx(fx, removal());
      assert.equal(await readGuardSlot(fx), "0x0000000000000000000000000000000000000000");
      // Re-install for any later test.
      await execSafeTx(fx, plainSafeTx({ to: fx.safe, data: encodeSetGuard(fx.guard), nonce: await safeNonce(fx) }));
    });
  });
});

describe("SignholdGuard P-256 (RIP-7212 / EIP-7951) approvals", { concurrency: false }, () => {
  const devicePriv = bytesToHex(generateP256PrivateKey());
  const deviceKey = p256PublicKeyFromPrivate(devicePriv);
  const strangerPriv = bytesToHex(generateP256PrivateKey());
  const strangerKey = p256PublicKeyFromPrivate(strangerPriv);
  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

  async function p256Approve(fx: Fixture, tx: SafeTransaction, priv: Hex, key = deviceKey, opts: { auditId?: string; mutate?: (r: Hex, s: Hex) => [Hex, Hex]; label?: string } = {}) {
    const message: ApprovalMessage = { safe: fx.safe, safeTxHash: computeSafeTxHash(fx.chainId, fx.safe, tx), auditId: auditIdToBytes32(opts.auditId ?? "audit-1"), approvedAt: await now(fx) };
    let { r, s } = signApprovalP256(priv, domainOf(fx), message);
    if (opts.mutate) [r, s] = opts.mutate(r, s);
    const hash = await guardAt(fx).write.submitApprovalP256([message.safeTxHash, message.auditId, key.qx, key.qy, message.approvedAt, r, s]);
    const receipt = await fx.publicClient.waitForTransactionReceipt({ hash });
    recordGas(opts.label ?? "submitApprovalP256", receipt);
    return receipt;
  }

  describe("with the native precompile (EDR hardfork osaka: EIP-7951 P256VERIFY at 0x100)", () => {
    let fx: Fixture;
    before(async () => {
      fx = await deployFixture({ p256Keys: [deviceKey], p256Enabled: true });
    });

    it("the guard registered the key and off-chain verification agrees with the signer", async () => {
      const g = guardAt(fx);
      assert.equal(await g.read.p256Enabled(), true);
      assert.equal(await g.read.p256Approvers([p256ApproverId(deviceKey)]), true);
      assert.equal(await g.read.p256ApproverId([deviceKey.qx, deviceKey.qy]), p256ApproverId(deviceKey));
      const message: ApprovalMessage = { safe: fx.safe, safeTxHash: `0x${"ab".repeat(32)}`, auditId: auditIdToBytes32("v"), approvedAt: 1n };
      const sig = signApprovalP256(devicePriv, domainOf(fx), message);
      assert.equal(verifyApprovalP256(deviceKey, sig, domainOf(fx), message), true);
      assert.equal(verifyApprovalP256(strangerKey, sig, domainOf(fx), message), false);
    });

    it("escalate + P-256 approval executes; tampered, high-s and unregistered-key approvals are refused", async () => {
      const tx = await transferTx(fx, 500_000_000n);
      await attest(fx, tx, "escalate");
      await expectRevert(p256Approve(fx, tx, strangerPriv, strangerKey), "UnregisteredApprover");
      await expectRevert(p256Approve(fx, tx, strangerPriv, deviceKey), "InvalidApproverSignature"); // wrong key for the claimed id
      await expectRevert(p256Approve(fx, tx, devicePriv, deviceKey, { mutate: (r, s) => [r, `0x${(BigInt(s) ^ 1n).toString(16).padStart(64, "0")}`] }), "InvalidApproverSignature");
      await expectRevert(p256Approve(fx, tx, devicePriv, deviceKey, { mutate: (r, s) => [r, `0x${(N - BigInt(s)).toString(16).padStart(64, "0")}`] }), "InvalidApproverSignature"); // high-s twin
      assert.equal(await execSafeTxExpectRevert(fx, tx), "ApprovalRequired");
      await p256Approve(fx, tx, devicePriv, deviceKey, { label: "submitApprovalP256 (native precompile)" });
      const receipt = await execSafeTx(fx, tx);
      recordGas("execTransaction (escalate + P-256 approval)", receipt);
      const checked = parseEventLogs({ abi: SIGNHOLD_GUARD_ABI, logs: receipt.logs, eventName: "TransactionChecked" })[0];
      assert.equal(checked.args.approverId, p256ApproverId(deviceKey));
    });

    it("a guard with P-256 disabled refuses P-256 approvals even when the precompile exists", async () => {
      const off = await deployFixture({ p256Keys: [deviceKey], p256Enabled: false });
      const tx = await transferTx(off, 1n);
      await attest(off, tx, "escalate");
      await expectRevert(p256Approve(off, tx, devicePriv), "P256Disabled");
    });
  });

  describe("without the precompile (EDR hardfork cancun), and with a mock installed by hardhat_setCode", () => {
    it("enabling P-256 reverts where 0x100 is absent; the mock makes it work; removing it fails closed", async () => {
      const bare = await deployFixture({ network: "hardhatCancun" });
      await expectRevert(
        bare.conn.viem.deployContract("SignholdGuard", [bare.safe, bare.attestor.address, [bare.approver.address], [deviceKey.qx], [deviceKey.qy], true, 900n, 3600n]),
        "P256PrecompileUnavailable",
      );
      // Install the mock precompile (real P-256 math in Solidity, RIP-7212 ABI) at 0x100.
      const mock = await bare.conn.viem.deployContract("MockP256Precompile");
      const mockCode = (await bare.publicClient.getCode({ address: mock.address }))!;
      await bare.conn.networkHelpers.setCode(P256_PRECOMPILE, mockCode);
      const fx = await deployFixture({ conn: bare.conn, p256Keys: [deviceKey], p256Enabled: true });

      const tx = await transferTx(fx, 500_000_000n);
      await attest(fx, tx, "escalate");
      await expectRevert(p256Approve(fx, tx, strangerPriv, deviceKey), "InvalidApproverSignature");
      // Precompile gone again: the approval reverts rather than being silently accepted or ignored.
      await fx.conn.networkHelpers.setCode(P256_PRECOMPILE, "0x");
      await expectRevert(p256Approve(fx, tx, devicePriv), "P256PrecompileUnavailable");
      assert.equal(await execSafeTxExpectRevert(fx, tx), "ApprovalRequired");
      await fx.conn.networkHelpers.setCode(P256_PRECOMPILE, mockCode);
      await p256Approve(fx, tx, devicePriv, deviceKey, { label: "submitApprovalP256 (mock precompile)" });
      await execSafeTx(fx, tx);
    });
  });
});
