/**
 * Signhold on-chain enforcement demo: a Safe guarded by SignholdGuard.
 *
 * Everything runs in this process and nothing touches a network:
 *   - a Hardhat (EDR) chain with a REAL Safe v1.5.0 (pinned artifacts), an ERC-20 and the guard;
 *   - the Signhold HTTP API with the real policy engine, simulating against that chain through
 *     the EVM adapter, holding the ATTESTOR key (secp256k1) and the registry of approver devices;
 *   - an "agent host" that owns the Safe owner key and an API key, and nothing else;
 *   - an "approver device" that owns a secp256k1 key registered in the guard and on the server.
 *
 *   (a) routine ERC-20 transfer   -> allow     -> attested -> Safe executes
 *   (b) unlimited approve         -> block     -> the service refuses to attest (403) -> Safe reverts NotAttested
 *   (c) over-cap transfer         -> escalate  -> attested, agent executes -> reverts ApprovalRequired;
 *                                    device reviews the sealed record + the exact Safe tx, signs once;
 *                                    the signature satisfies the API (eip712) and the guard -> Safe executes
 *   (d) agent removes the guard   -> (whatever the service says) the guard needs a device -> reverts ApprovalRequired
 *
 * Run with: npx tsx examples/safe-guard-demo.ts   (== npm run demo:safe-guard)
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHardhatRuntimeEnvironment } from "hardhat/hre";
import type {} from "@nomicfoundation/hardhat-viem"; // augments NetworkConnection with `viem`
import { encodeFunctionData, getAddress, parseEventLogs, type Abi, type Address, type Hex, type PublicClient } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { UINT256_MAX, type AgentContext, type AuditRecord, type PolicySet, type TransactionIntent, type Verdict } from "@signhold/core";
import { PolicyEngine } from "@signhold/policy";
import { EvmAdapter, ERC20_ABI, type PublicClientLike } from "@signhold/sim-evm";
import { createServer, InMemoryAuditStore } from "@signhold/api";
import { SignholdClient } from "@signhold/sdk";
import {
  SIGNHOLD_GUARD_ABI,
  approveSafeTransaction,
  computeSafeTxHash,
  deployGuard,
  encodeSetGuard,
  plainSafeTx,
  submitApproval,
  submitAttestation,
  type SafeTransaction,
} from "@signhold/safe-guard";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const guardWorkspace = join(here, "..", "contracts", "safe-guard");
const ZERO = "0x0000000000000000000000000000000000000000" as const;

function artifact(path: string): { abi: Abi; bytecode: Hex } {
  const j = JSON.parse(readFileSync(path, "utf8")) as { abi: Abi; bytecode: Hex };
  return { abi: j.abi, bytecode: j.bytecode };
}
const SAFE = artifact(require.resolve("@safe-global/safe-smart-account/build/artifacts/contracts/Safe.sol/Safe.json"));
const FACTORY = artifact(require.resolve("@safe-global/safe-smart-account/build/artifacts/contracts/proxies/SafeProxyFactory.sol/SafeProxyFactory.json"));
const SAFE_ABI = [...SAFE.abi, ...SIGNHOLD_GUARD_ABI.filter((e) => e.type === "error")] as Abi;

/** The policy for this demo: hard blocks for drain vectors, a $100 per-transaction cap that escalates to a human. */
const demoPolicy: PolicySet = {
  id: "safe-guard-demo",
  version: 1,
  rules: [
    { id: "sim-ok", kind: "require_simulation_ok", onViolation: "block" },
    { id: "no-unlimited", kind: "no_unlimited_approvals", onViolation: "block" },
    { id: "no-eoa-approvals", kind: "no_eoa_approvals", onViolation: "block" },
    { id: "tx-cap", kind: "max_tx_usd", params: { maxUsd: 100 }, onViolation: "escalate" },
  ],
};

interface Row { case: string; verdict: string; attested: string; onChain: string; expected: string }

function revertName(err: unknown): string {
  let e: unknown = err;
  for (let i = 0; i < 8 && e && typeof e === "object"; i++) {
    const o = e as { data?: { errorName?: string }; reason?: string; cause?: unknown; details?: string };
    if (o.data?.errorName) return o.data.errorName;
    if (o.reason) return o.reason;
    const m = /custom error '([A-Za-z0-9_]+)\(/.exec(o.details ?? "");
    if (m) return m[1];
    e = o.cause;
  }
  return (err as Error)?.message ?? String(err);
}

async function main() {
  // ---------------------------------------------------------------------------
  // Chain: Hardhat EDR in-process (Osaka rules), funded relayer account.
  // ---------------------------------------------------------------------------
  const configPath = join(guardWorkspace, "hardhat.config.ts");
  const hre = await createHardhatRuntimeEnvironment((await import(configPath)).default, { config: configPath }, guardWorkspace);
  const conn = await hre.network.create({ network: "hardhatMainnet" });
  const publicClient = (await conn.viem.getPublicClient()) as unknown as PublicClient;
  const [relayer] = await conn.viem.getWalletClients();
  const chainId = BigInt(await publicClient.getChainId());
  const erc20Artifact = await hre.artifacts.readArtifact("ERC20Mock");

  // Three parties, three keys. None of them is ever handed to another party.
  const agentOwner = privateKeyToAccount(generatePrivateKey()); // agent host: Safe owner key
  const attestorKey = generatePrivateKey(); //                     Signhold host: attestor key
  const device = privateKeyToAccount(generatePrivateKey()); //    approver device: approver key
  const supplier = privateKeyToAccount(generatePrivateKey()).address;

  const deploy = async (abi: Abi, bytecode: Hex, args: unknown[] = []) => {
    const hash = await relayer.deployContract({ abi, bytecode, args });
    return getAddress((await publicClient.waitForTransactionReceipt({ hash })).contractAddress!);
  };
  const singleton = await deploy(SAFE.abi, SAFE.bytecode);
  const factory = await deploy(FACTORY.abi, FACTORY.bytecode);
  const initializer = encodeFunctionData({ abi: SAFE.abi, functionName: "setup", args: [[agentOwner.address], 1n, ZERO, "0x", ZERO, ZERO, 0n, ZERO] });
  const proxyTx = await relayer.writeContract({ address: factory, abi: FACTORY.abi, functionName: "createProxyWithNonce", args: [singleton, initializer, 1n] });
  const proxyReceipt = await publicClient.waitForTransactionReceipt({ hash: proxyTx });
  const safe = getAddress((parseEventLogs({ abi: FACTORY.abi, logs: proxyReceipt.logs, eventName: "ProxyCreation" })[0] as unknown as { args: { proxy: Address } }).args.proxy);
  const usdc = await deploy(erc20Artifact.abi as Abi, erc20Artifact.bytecode as Hex);
  await relayer.writeContract({ address: usdc, abi: erc20Artifact.abi as Abi, functionName: "mint", args: [safe, 10_000_000_000n] }); // 10,000 USDC
  await relayer.sendTransaction({ to: safe, value: 10n ** 18n });

  // The guard: attestor = the service's key, approvers = the device, 15-minute approval window.
  const attestorAddress = privateKeyToAccount(attestorKey).address;
  const guardTx = await deployGuard(relayer as unknown as Parameters<typeof deployGuard>[0], { safe, attestor: attestorAddress, approvers: [device.address] });
  const guard = getAddress((await publicClient.waitForTransactionReceipt({ hash: guardTx })).contractAddress!);

  const safeNonce = async () => (await publicClient.readContract({ address: safe, abi: SAFE.abi, functionName: "nonce" })) as bigint;
  const execSafeTx = async (tx: SafeTransaction) => {
    const signatures = await agentOwner.sign({ hash: computeSafeTxHash(chainId, safe, tx) });
    const hash = await relayer.writeContract({ address: safe, abi: SAFE_ABI, functionName: "execTransaction", args: [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, signatures] });
    return publicClient.waitForTransactionReceipt({ hash });
  };
  // Owners install the guard with one ordinary Safe transaction. From here on, every execTransaction is checked.
  await execSafeTx(plainSafeTx({ to: safe, data: encodeSetGuard(guard), nonce: await safeNonce() }));

  // ---------------------------------------------------------------------------
  // Signhold API in-process: real engine + demo policy, simulating against THIS chain.
  // Holds the attestor key; registers the device's address as a secp256k1 approver.
  // ---------------------------------------------------------------------------
  const evm = new EvmAdapter({ client: publicClient as unknown as PublicClientLike, knownContracts: new Set([usdc, safe, guard]), priceOracle: async (asset) => (asset === "native" ? 2_500 : 1) });
  const app = await createServer({
    engine: new PolicyEngine(),
    adapters: { evm },
    policies: new Map([[demoPolicy.id, demoPolicy]]),
    defaultPolicyId: demoPolicy.id,
    audit: new InMemoryAuditStore(),
    apiKeys: [{ id: "demo-agent", key: "demo-key" }, { id: "approver-device", key: "approver-key" }],
    approvers: [{ keyId: "ops-wallet", publicKey: device.address, type: "secp256k1" }],
    attestor: { privateKey: attestorKey, guards: [guard] },
    logger: false,
  });
  const baseUrl = await app.listen({ port: 0, host: "127.0.0.1" });
  const client = new SignholdClient({ baseUrl, apiKey: "demo-key" });
  const context: AgentContext = { agentId: "demo-agent", spentUsdInWindow: 0, windowSeconds: 3600 };

  // ---------------------------------------------------------------------------
  // The agent's loop: check -> attest -> execute. It holds the owner key and an API key only.
  // ---------------------------------------------------------------------------
  const intentOf = (id: string, tx: SafeTransaction, description: string): TransactionIntent => ({ id, chain: "evm", chainId: Number(chainId), from: safe, to: tx.to, value: tx.value, data: tx.data, description });
  const serialize = (tx: SafeTransaction) => Object.fromEntries(Object.entries(tx).map(([k, v]) => [k, typeof v === "bigint" ? v.toString() : v])) as unknown as Parameters<typeof client.requestAttestation>[0]["safeTx"];

  async function agentRun(tx: SafeTransaction, intentId: string, description: string) {
    const check = await client.check(intentOf(intentId, tx, description), context);
    let attested = "-";
    let onChain = "-";
    if (check.decision.verdict !== "block") {
      try {
        const att = await client.requestAttestation({ auditId: check.auditId, safe, guard, chainId: Number(chainId), safeTx: serialize(tx), safeTxHash: computeSafeTxHash(chainId, safe, tx) });
        await publicClient.waitForTransactionReceipt({
          hash: await submitAttestation(relayer as unknown as Parameters<typeof submitAttestation>[0], {
            guard,
            message: { safe, safeTxHash: att.safeTxHash as Hex, verdict: att.verdictCode, expiresAt: BigInt(att.expiresAtUnix), auditId: att.auditIdBytes32 as Hex },
            signature: att.signature as Hex,
          }),
        });
        attested = `attested ${att.verdict}`;
      } catch (err) {
        attested = `refused (${(err as { status?: number }).status ?? revertName(err)})`;
      }
    } else {
      try {
        await client.requestAttestation({ auditId: check.auditId, safe, guard, chainId: Number(chainId), safeTx: serialize(tx) });
        attested = "ATTESTED A BLOCK  <-- MISMATCH";
      } catch (err) {
        attested = `refused (HTTP ${(err as { status?: number }).status})`;
      }
    }
    try {
      const receipt = await execSafeTx(tx);
      onChain = receipt.status === "success" ? "executed" : "reverted";
    } catch (err) {
      onChain = `reverted ${revertName(err)}`;
    }
    return { check, attested, onChain };
  }

  const rows: Row[] = [];
  let failures = 0;
  const log: string[] = [];
  const record = (name: string, r: { check: { decision: { verdict: Verdict } }; attested: string; onChain: string }, expectVerdict: Verdict, expectOnChain: string) => {
    const ok = r.check.decision.verdict === expectVerdict && r.onChain.startsWith(expectOnChain);
    if (!ok) failures++;
    rows.push({ case: name, verdict: r.check.decision.verdict, attested: r.attested, onChain: r.onChain + (ok ? "" : "  <-- MISMATCH"), expected: `${expectVerdict} / ${expectOnChain}` });
  };

  // (a) routine transfer: 5 USDC to the supplier.
  const a = plainSafeTx({ to: usdc, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [supplier, 5_000_000n] }), nonce: await safeNonce() });
  record("(a) transfer 5 USDC", await agentRun(a, "00000000-0000-4000-8000-0000000000a1", "pay supplier invoice #42"), "allow", "executed");

  // (b) unlimited approve: blocked by policy; the service will not attest, so the Safe cannot execute it.
  const b = plainSafeTx({ to: usdc, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [supplier, UINT256_MAX] }), nonce: await safeNonce() });
  record("(b) unlimited approve", await agentRun(b, "00000000-0000-4000-8000-0000000000b1", "approve router before swap"), "block", "reverted NotAttested");

  // (c) over-cap transfer: 500 USDC > $100 cap => escalate. Attested as escalate; the agent cannot execute...
  const c = plainSafeTx({ to: usdc, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [supplier, 500_000_000n] }), nonce: await safeNonce() });
  const cRun = await agentRun(c, "00000000-0000-4000-8000-0000000000c1", "pay supplier invoice #43 (large)");
  record("(c) transfer 500 USDC, agent alone", cRun, "escalate", "reverted ApprovalRequired");

  // ...until the device approves. The device fetches the sealed record itself, recomputes the
  // hash of the Safe tx it is shown, and signs ONE EIP-712 approval that both verifiers accept.
  if (cRun.check.decision.verdict === "escalate") {
    const approval = await approveSafeTransaction({
      auditId: cRun.check.auditId,
      loadRecord: async () => {
        const res = await fetch(`${baseUrl}/v1/audit/${cRun.check.auditId}`, { headers: { "x-api-key": "approver-key" } }); // the DEVICE's api key
        return (await res.json()) as AuditRecord;
      },
      chainId,
      guard,
      safe,
      safeTx: c,
      signer: { kind: "secp256k1", signer: device },
      display: (lines) => log.push(...lines.filter((l) => l.trim()).map((l) => `  device display | ${l}`)),
      confirm: async () => true, // a scripted "APPROVE" (a human types it in approve-safe.ts)
    });
    const sig = approval.secp256k1!;
    // Off-chain: the same signature closes the server-side escalation (scheme eip712).
    const apiRes = await fetch(`${baseUrl}/v1/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "approver-key" },
      body: JSON.stringify({ auditId: cRun.check.auditId, keyId: "ops-wallet", signature: sig.signature, approvedAt: new Date(Number(approval.message.approvedAt) * 1000).toISOString(), scheme: "eip712" }),
    });
    log.push(`  API /v1/approvals (eip712): HTTP ${apiRes.status} ${JSON.stringify(await apiRes.json())}`);
    // On-chain: anyone may relay it; the guard verifies the device's signature itself.
    const relayHash = await submitApproval(relayer as unknown as Parameters<typeof submitApproval>[0], { guard, message: approval.message, approver: sig.approver, signature: sig.signature });
    const relayReceipt = await publicClient.waitForTransactionReceipt({ hash: relayHash });
    log.push(`  guard.submitApproval: ${relayReceipt.status} (gas ${relayReceipt.gasUsed})`);
    let onChain: string;
    try {
      const receipt = await execSafeTx(c);
      onChain = receipt.status === "success" ? "executed" : "reverted";
      const checked = parseEventLogs({ abi: SIGNHOLD_GUARD_ABI, logs: receipt.logs, eventName: "TransactionChecked" })[0];
      log.push(`  Safe.execTransaction: ${onChain} (gas ${receipt.gasUsed}); guard consumed approval by 0x${checked.args.approverId.slice(-40)} (the device)`);
    } catch (err) {
      onChain = `reverted ${revertName(err)}`;
    }
    const ok = onChain === "executed" && apiRes.status === 200;
    if (!ok) failures++;
    rows.push({ case: "(c) ... after device approval", verdict: "escalate", attested: "approved by device", onChain: onChain + (ok ? "" : "  <-- MISMATCH"), expected: "escalate / executed" });
    // The approval was single use: it is gone from the guard.
    const [, , approvedAt] = await publicClient.readContract({ address: guard, abi: SIGNHOLD_GUARD_ABI, functionName: "approvals", args: [approval.safeTxHash] });
    log.push(`  approval after execution: ${approvedAt === 0n ? "consumed (single use)" : "STILL PRESENT  <-- MISMATCH"}`);
    if (approvedAt !== 0n) failures++;
  }

  // (d) the agent tries to remove the guard. Whatever the service decides, a call to the Safe itself needs a device.
  const d = plainSafeTx({ to: safe, data: encodeSetGuard(ZERO), nonce: await safeNonce() });
  const dRun = await agentRun(d, "00000000-0000-4000-8000-0000000000d1", "routine maintenance");
  const dOk = dRun.onChain.startsWith("reverted ApprovalRequired") || dRun.onChain.startsWith("reverted NotAttested");
  if (!dOk) failures++;
  rows.push({ case: "(d) agent removes the guard", verdict: dRun.check.decision.verdict, attested: dRun.attested, onChain: dRun.onChain + (dOk ? "" : "  <-- MISMATCH"), expected: "* / reverted ApprovalRequired" });
  const slot = await publicClient.getStorageAt({ address: safe, slot: "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8" });
  const stillGuarded = getAddress(`0x${(slot ?? "0x").slice(-40)}`) === guard;
  if (!stillGuarded) failures++;
  log.push(`  guard slot after (d): ${stillGuarded ? "still SignholdGuard" : "CLEARED  <-- MISMATCH"}`);

  // ---------------------------------------------------------------------------
  printTable(rows);
  console.log("\nDetails:");
  for (const l of log) console.log(l);
  const balance = (await publicClient.readContract({ address: usdc, abi: erc20Artifact.abi as Abi, functionName: "balanceOf", args: [supplier] })) as bigint;
  console.log(`\nsupplier balance: ${Number(balance) / 1e6} USDC (5 from (a) + 500 from (c)); Safe ${safe} guarded by ${guard}`);
  await app.close();
  if (failures > 0) {
    console.error(`\n${failures} expectation(s) did not hold`);
    process.exit(1);
  }
  console.log("\nAll expectations held.");
  process.exit(0);
}

function printTable(rows: Row[]) {
  const w = { case: 36, verdict: 9, attested: 24, onChain: 30, expected: 38 };
  const pad = (s: string, n: number) => s.padEnd(n).slice(0, n);
  const header = `${pad("case", w.case)}  ${pad("verdict", w.verdict)}  ${pad("attestation", w.attested)}  ${pad("on-chain", w.onChain)}  ${pad("expected", w.expected)}`;
  console.log(header);
  console.log("-".repeat(header.length));
  for (const r of rows) console.log(`${pad(r.case, w.case)}  ${pad(r.verdict, w.verdict)}  ${pad(r.attested, w.attested)}  ${pad(r.onChain, w.onChain)}  ${pad(r.expected, w.expected)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
