/**
 * Signhold x Coinbase AgentKit demo (no network, no AgentKit install needed).
 *
 * Starts the HTTP API in-process (real policy engine, EVM adapter over a mock RPC client,
 * reputation layer, a registered approver device), wraps a mock AgentKit-shaped
 * `EvmWalletProvider` with `guardWalletProvider`, and drives it with the transaction
 * requests AgentKit's action providers would produce:
 *
 *   (a) erc20 `transfer` of 5 USDC to a known payee          -> allow,    provider signs
 *   (b) erc20 `approve(router, maxUint256)` (CDP swap prelude) -> block,    provider never called
 *   (c) transfer of 60 USDC to a never-seen address (> cap)   -> escalate, device approves, provider signs
 *   (d) the same, device rejects (challenge expires)          -> escalate, provider never called
 *   (e) `wallet.sign(hash)` (raw hash signing)                -> refused without a check
 *
 * It then shows the two read-only AgentKit actions (`signhold_explain_last_decision`,
 * `signhold_check_status`) the agent could call, and prints a table + assertions like
 * examples/demo.ts.
 *
 * Run with: npx tsx examples/agentkit-demo.ts
 */
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { encodeAbiParameters, encodeFunctionData, type Hex } from "viem";
import { UINT256_MAX, type PolicyRule } from "@signhold/core";
import { PolicyEngine, conservativeDefaultPolicy } from "@signhold/policy";
import { EvmAdapter, ERC20_ABI, type PublicClientLike } from "@signhold/sim-evm";
import { ReputationService, StaticListProvider, createReputationRule } from "@signhold/reputation";
import { REPUTATION_RULE, createServer, InMemoryAuditStore, withCustomRules } from "@signhold/api";
import { SignholdClient, type EscalationInfo } from "@signhold/sdk";
import {
  GuardBlockedError,
  GuardUncheckableError,
  guardWalletProvider,
  signholdActionProvider,
  type EvmWalletProviderLike,
  type NetworkLike,
  type TransactionRequestLike,
} from "@signhold/agentkit";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const AGENT = "0x1111111111111111111111111111111111111111";
const BOB = "0x2222222222222222222222222222222222222222"; // known payee
const CAROL = "0x7777777777777777777777777777777777777777"; // never seen before
const USDC = "0x3333333333333333333333333333333333333333";
const ROUTER = "0x4444444444444444444444444444444444444444";
const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"; // what the CDP swap action approves, unlimited

const SEL_DECIMALS = encodeFunctionData({ abi: ERC20_ABI, functionName: "decimals" });
const SEL_SYMBOL = encodeFunctionData({ abi: ERC20_ABI, functionName: "symbol" });
const SEL_ALLOWANCE = "0xdd62ed3e";
const SEL_BALANCE_OF = "0x70a08231";

/** The mock viem-like read client (same shape as examples/demo.ts). Feeds both the API's adapter and the wallet provider. */
function mockEvmClient(): PublicClientLike {
  const deployed = new Set([USDC, ROUTER, PERMIT2]);
  return {
    async call({ data }) {
      const d = data ?? "0x";
      if (d === SEL_DECIMALS) return { data: encodeAbiParameters([{ type: "uint8" }], [6]) };
      if (d === SEL_SYMBOL) return { data: encodeAbiParameters([{ type: "string" }], ["USDC"]) };
      if (d.startsWith(SEL_ALLOWANCE)) return { data: encodeAbiParameters([{ type: "uint256" }], [0n]) };
      if (d.startsWith(SEL_BALANCE_OF)) return { data: encodeAbiParameters([{ type: "uint256" }], [1_000_000_000n]) };
      return { data: "0x" };
    },
    async estimateGas() { return 52_000n; },
    async getCode({ address }) { return deployed.has(address.toLowerCase()) ? ("0x6001" as Hex) : ("0x" as Hex); },
  };
}

/**
 * A wallet provider in the shape of AgentKit's `EvmWalletProvider` (0.10.4): same method
 * names and signatures, `#private` state like the compiled CDP providers, reads served by
 * the mock client. `signed` counts what actually reached the key.
 */
class MockEvmWalletProvider implements EvmWalletProviderLike {
  #address = AGENT;
  #network: NetworkLike = { protocolFamily: "evm", networkId: "base-mainnet", chainId: "8453" };
  #client: PublicClientLike;
  #nonce = 0;
  signed: string[] = [];
  constructor(client: PublicClientLike) { this.#client = client; }
  getAddress() { return this.#address; }
  getNetwork() { return this.#network; }
  getName() { return "mock_evm_wallet_provider"; }
  async getBalance() { return 10n ** 18n; }
  async readContract(params: { address: string; functionName: string }) {
    const data = params.functionName === "decimals" ? SEL_DECIMALS : SEL_SYMBOL;
    return (await this.#client.call({ to: params.address as `0x${string}`, data })).data;
  }
  getPublicClient() { return this.#client; }
  async waitForTransactionReceipt(txHash: string) { return { status: "success", transactionHash: txHash }; }
  async signTransaction(tx: TransactionRequestLike) { this.signed.push(`signTransaction ${tx.to}`); return `0xsigned${(++this.#nonce).toString(16)}`; }
  async sendTransaction(tx: TransactionRequestLike) { this.signed.push(`sendTransaction ${tx.to}`); return `0x${(++this.#nonce).toString(16).padStart(64, "0")}`; }
  async nativeTransfer(to: string, value: string) { return this.sendTransaction({ to, value: BigInt(value) }); }
  async sign(hash: string) { this.signed.push(`sign ${hash}`); return "0xrawsig"; }
  async signMessage(m: string | Uint8Array) { this.signed.push(`signMessage ${String(m)}`); return "0xmsgsig"; }
  async signTypedData(_td: unknown) { this.signed.push("signTypedData"); return "0xtypedsig"; }
}

/** Approver device fixture: only `sign` touches the private key; only the public half reaches the server. */
function makeTrustedDevice(keyId: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyB64 = (publicKey.export({ type: "spki", format: "der" }) as Buffer).subarray(-32).toString("base64");
  return { keyId, publicKeyB64, sign: (challenge: string) => edSign(null, Buffer.from(challenge, "utf8"), privateKey).toString("base64") };
}

async function main() {
  const client_ = mockEvmClient();
  const adapter = new EvmAdapter({ client: client_, knownContracts: new Set([USDC, ROUTER, PERMIT2]), priceOracle: async (asset) => (asset === "native" ? 2_500 : 1) });
  const reputation = new ReputationService({
    providers: [new StaticListProvider({ allow: [USDC, ROUTER, BOB].map((address) => ({ chain: "evm" as const, address, label: "operator-known", tags: ["operator-allow"] })) })],
    failMode: "closed",
  });
  const engine = new PolicyEngine({ customRules: { reputation: createReputationRule(reputation) } });
  const extra: PolicyRule[] = [
    { id: "tx-cap-25", kind: "max_tx_usd", onViolation: "escalate", params: { maxUsd: 25 }, description: "A human looks at anything above $25." },
    { id: "known-payees", kind: "allowlist_only", onViolation: "escalate", params: { addresses: [USDC, ROUTER, BOB] }, description: "Escalate counterparties the operator has not listed." },
    REPUTATION_RULE,
  ];
  const policy = { ...withCustomRules(conservativeDefaultPolicy, extra), id: "agentkit-demo", version: 1 };

  // Controlled approval clock: a rejection is the human not signing, so the challenge expires.
  let clockOffsetMs = 0;
  const device = makeTrustedDevice("ops-phone");
  const app = await createServer({
    engine,
    adapters: { evm: adapter },
    policies: new Map([[policy.id, policy]]),
    defaultPolicyId: policy.id,
    audit: new InMemoryAuditStore(),
    reputation,
    apiKeys: [{ id: "agentkit-agent", key: "agent-key" }, { id: "approver-device", key: "device-key" }],
    approvers: [{ keyId: device.keyId, publicKey: device.publicKeyB64 }],
    approvals: { ttlMs: 60_000, now: () => Date.now() + clockOffsetMs },
    logger: false,
  });
  const baseUrl = await app.listen({ port: 0, host: "127.0.0.1" });

  // ---- The agent side: holds the agent's API key only. ----
  const client = new SignholdClient({ baseUrl, apiKey: "agent-key", retries: 0 });
  const provider = new MockEvmWalletProvider(client_);
  let deviceWillApprove = true;
  const deviceLog: string[] = [];
  const wallet = guardWalletProvider(provider, client, {
    context: { agentId: "agentkit-agent", windowSeconds: 3600 },
    waitForApproval: { intervalMs: 50, timeoutMs: 10_000 },
    describe: (method, args) => `${method} requested by the AgentKit agent (${JSON.stringify(args, (_k, v) => (typeof v === "bigint" ? v.toString() : v)).slice(0, 200)})`,
    // Routing hook: in production this pushes auditId + challenge to the human's device. Here the
    // device fixture decides immediately. Nothing in this callback can approve.
    onEscalationPending: async (info: EscalationInfo) => {
      if (!deviceWillApprove) {
        deviceLog.push(`device: did not sign ${info.auditId} (${info.decision.findings.map((f) => f.ruleId).join(", ")}); challenge left to expire`);
        clockOffsetMs += 61_000;
        return;
      }
      const body = { auditId: info.auditId, keyId: device.keyId, signature: device.sign(info.approval!.challenge), approvedAt: new Date(Date.now() + clockOffsetMs).toISOString(), reason: "new vendor confirmed by phone" };
      const res = await fetch(`${baseUrl}/v1/approvals`, { method: "POST", headers: { "content-type": "application/json", "x-api-key": "device-key" }, body: JSON.stringify(body) });
      deviceLog.push(`device: signed challenge for ${info.auditId} -> server HTTP ${res.status}`);
    },
  });
  // What AgentKit.from({ walletProvider: wallet, actionProviders: [...] }) would register:
  const actions = signholdActionProvider({ client, wallet }).getActions(wallet);
  const explain = actions.find((a) => a.name === "signhold_explain_last_decision")!;
  const checkStatus = actions.find((a) => a.name === "signhold_check_status")!;

  // AgentKit-shaped requests, as erc20ActionProvider / the CDP swap action build them.
  const transferTo = (to: string, units: bigint): TransactionRequestLike => ({ to: USDC, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [to as `0x${string}`, units] }) });
  const unlimitedApprove: TransactionRequestLike = { to: USDC, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [PERMIT2, UINT256_MAX] }) };

  type Row = { case: string; outcome: string; expected: string; signed: string; detail: string };
  const rows: Row[] = [];
  let failures = 0;
  const run = async (name: string, expected: string, expectSigned: boolean, fn: () => Promise<unknown>) => {
    const before = provider.signed.length;
    let outcome: string;
    let detail = "";
    try {
      const r = await fn();
      outcome = "proceeded";
      detail = `provider returned ${String(r)}`;
    } catch (err) {
      const e = err as { name?: string; code?: string; message?: string; decision?: { explanation: string } };
      outcome = e.code ?? e.name ?? "error";
      detail = (e.decision?.explanation ?? e.message ?? "").slice(0, 160);
    }
    const signedNow = provider.signed.length > before;
    const ok = outcome === expected && signedNow === expectSigned;
    if (!ok) failures++;
    rows.push({ case: name, outcome: `${outcome}${ok ? "" : "  <-- MISMATCH"}`, expected, signed: signedNow ? "yes" : "no", detail });
  };

  await run("(a) transfer 5 USDC to known payee", "proceeded", true, () => wallet.sendTransaction(transferTo(BOB, 5_000_000n)));
  await run("(b) approve(Permit2, maxUint256)", "blocked", false, () => wallet.sendTransaction(unlimitedApprove));
  deviceWillApprove = true;
  await run("(c) 60 USDC to never-seen address, device approves", "proceeded", true, () => wallet.sendTransaction(transferTo(CAROL, 60_000_000n)));
  const explainedC = JSON.parse(await explain.invoke({})) as { auditId: string; verdict: string; findings: Array<{ ruleId: string }> };
  deviceWillApprove = false;
  await run("(d) 60 USDC to never-seen address, device rejects", "approval_denied", false, () => wallet.signTransaction(transferTo(CAROL, 60_000_000n)));
  const explainedD = JSON.parse(await explain.invoke({})) as { auditId: string; verdict: string; findings: Array<{ ruleId: string }>; approval?: unknown };
  await run("(e) wallet.sign(hash) — raw hash signing", "uncheckable", false, async () => wallet.sign(`0x${"ab".repeat(32)}`));

  // ---- The read-only actions the agent gets. ----
  const statusC = JSON.parse(await checkStatus.invoke({ auditId: explainedC.auditId })) as { status: string; approvedBy?: string };
  const statusD = JSON.parse(await checkStatus.invoke({ auditId: explainedD.auditId })) as { status: string };
  const hostile = JSON.parse(await checkStatus.invoke({ auditId: explainedD.auditId, approve: true, keyId: "ops-phone", signature: "x" })) as { status: string };

  printTable(rows);
  console.log("\nApprover device (I-HITL):");
  for (const l of deviceLog) console.log(`- ${l}`);
  console.log("\nAgentKit actions available to the agent (read-only):");
  console.log(`- ${explain.name} after (c): verdict=${explainedC.verdict} rules=${explainedC.findings.map((f) => f.ruleId).join(",")} auditId=${explainedC.auditId}`);
  console.log(`- ${explain.name} after (d): verdict=${explainedD.verdict} rules=${explainedD.findings.map((f) => f.ruleId).join(",")}`);
  console.log(`- ${checkStatus.name}(${explainedC.auditId.slice(0, 8)}…): ${statusC.status} by ${statusC.approvedBy}`);
  console.log(`- ${checkStatus.name}(${explainedD.auditId.slice(0, 8)}…): ${statusD.status}`);
  console.log(`- ${checkStatus.name} with {approve:true, signature:…}: still ${hostile.status} (arguments beyond auditId are ignored; nothing here can approve)`);
  console.log(`\nProvider key usage: ${provider.signed.length} signature(s): ${provider.signed.join("; ")}`);

  if (explainedC.verdict !== "escalate" || statusC.status !== "approved" || statusC.approvedBy !== device.keyId) failures++;
  if (explainedD.verdict !== "escalate" || statusD.status !== "expired" || hostile.status !== "expired") failures++;
  if (provider.signed.length !== 2) failures++;
  if (!(await wallet.sendTransaction(transferTo(BOB, 1_000_000n)).then(() => true, (e) => e instanceof GuardBlockedError || e instanceof GuardUncheckableError))) failures++; // still usable afterwards

  await app.close();
  if (failures > 0) {
    console.error(`\n${failures} expectation(s) did not hold`);
    process.exit(1);
  }
  console.log("\nAll outcomes matched expectations.");
}

function printTable(rows: Array<{ case: string; outcome: string; expected: string; signed: string; detail: string }>) {
  const w = { case: 52, outcome: 28, expected: 16, signed: 6 };
  const pad = (s: string, n: number) => s.padEnd(n).slice(0, n);
  const line = `${pad("case", w.case)}  ${pad("outcome", w.outcome)}  ${pad("expected", w.expected)}  ${pad("signed", w.signed)}`;
  console.log(line);
  console.log("-".repeat(line.length));
  for (const r of rows) console.log(`${pad(r.case, w.case)}  ${pad(r.outcome, w.outcome)}  ${pad(r.expected, w.expected)}  ${pad(r.signed, w.signed)}`);
  console.log("\nDetails:");
  for (const r of rows) console.log(`- ${r.case}: ${r.detail}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
