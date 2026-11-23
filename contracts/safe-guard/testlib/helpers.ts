/**
 * Test fixtures: a REAL Safe (v1.5.0 singleton + proxy factory, deployed from the pinned
 * `@safe-global/safe-smart-account` artifacts, compiled by Safe with solc 0.7.6), one owner key
 * held "by the agent", an attestor key "on the Signhold host", approver keys "on devices",
 * and the SignholdGuard compiled by this workspace. No network.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { network } from "hardhat";
import {
  concatHex,
  encodeFunctionData,
  getAddress,
  getContract,
  keccak256,
  parseEventLogs,
  toHex,
  type Abi,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import {
  SIGNHOLD_GUARD_ABI,
  computeSafeTxHash,
  deployGuard,
  plainSafeTx,
  type SafeTransaction,
} from "../src/index.js";

const require = createRequire(import.meta.url);

function loadSafeArtifact(rel: string): { abi: Abi; bytecode: Hex } {
  const path = require.resolve(`@safe-global/safe-smart-account/build/artifacts/contracts/${rel}`);
  const json = JSON.parse(readFileSync(path, "utf8")) as { abi: Abi; bytecode: Hex };
  return { abi: json.abi, bytecode: json.bytecode };
}

export const SAFE_ARTIFACT = loadSafeArtifact("Safe.sol/Safe.json");
export const SAFE_PROXY_FACTORY_ARTIFACT = loadSafeArtifact("proxies/SafeProxyFactory.sol/SafeProxyFactory.json");

/** The Safe's ABI extended with the guard's custom errors so reverts bubbling through `execTransaction` decode. */
export const SAFE_ABI_WITH_GUARD_ERRORS = [...SAFE_ARTIFACT.abi, ...SIGNHOLD_GUARD_ABI.filter((e) => e.type === "error")] as Abi;

/** Interface id of Safe's `ITransactionGuard` (1.5.0) / `Guard` (1.4.1), from GuardManager.sol. */
export const SAFE_GUARD_INTERFACE_ID = "0xe6d7a83a" as const;
export const ERC165_INTERFACE_ID = "0x01ffc9a7" as const;
/** keccak256("guard_manager.guard.address"), the slot `setGuard` writes. */
export const GUARD_STORAGE_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8" as const;
export const P256_PRECOMPILE: Address = "0x0000000000000000000000000000000000000100";

export type Connection = Awaited<ReturnType<typeof network.create>>;

export interface Fixture {
  conn: Connection;
  publicClient: PublicClient;
  chainId: bigint;
  /** The executor: a funded hardhat account that relays Safe transactions (it is not an owner). */
  relayer: Awaited<ReturnType<Connection["viem"]["getWalletClients"]>>[number];
  owner: PrivateKeyAccount; // "the agent": a Safe owner key
  attestor: PrivateKeyAccount; // "the Signhold host"
  approver: PrivateKeyAccount; // "the human's device" (secp256k1)
  stranger: PrivateKeyAccount; // an unregistered key
  safe: Address;
  guard: Address;
  token: Address;
  recipient: Address;
}

export const APPROVAL_WINDOW = 900n;
export const ATTESTATION_TTL = 3600n;

export async function deployFixture(opts: { p256Keys?: { qx: Hex; qy: Hex }[]; p256Enabled?: boolean; network?: "hardhatMainnet" | "hardhatCancun"; conn?: Connection; installGuard?: boolean } = {}): Promise<Fixture> {
  // Every `network.connect()` is a fresh chain; pass `conn` to deploy onto an existing one.
  const conn = opts.conn ?? (await network.create({ network: opts.network ?? "hardhatMainnet" }));
  const { viem } = conn;
  const publicClient = (await viem.getPublicClient()) as unknown as PublicClient;
  const [relayer] = await viem.getWalletClients();
  const chainId = BigInt(await publicClient.getChainId());

  const owner = privateKeyToAccount(generatePrivateKey());
  const attestor = privateKeyToAccount(generatePrivateKey());
  const approver = privateKeyToAccount(generatePrivateKey());
  const stranger = privateKeyToAccount(generatePrivateKey());

  // ---- Real Safe 1.5.0: singleton + factory + proxy with a 1-of-1 owner ----
  const singletonTx = await relayer.deployContract({ abi: SAFE_ARTIFACT.abi, bytecode: SAFE_ARTIFACT.bytecode });
  const singleton = (await publicClient.waitForTransactionReceipt({ hash: singletonTx })).contractAddress!;
  const factoryTx = await relayer.deployContract({ abi: SAFE_PROXY_FACTORY_ARTIFACT.abi, bytecode: SAFE_PROXY_FACTORY_ARTIFACT.bytecode });
  const factory = (await publicClient.waitForTransactionReceipt({ hash: factoryTx })).contractAddress!;
  const initializer = encodeFunctionData({
    abi: SAFE_ARTIFACT.abi,
    functionName: "setup",
    args: [[owner.address], 1n, "0x0000000000000000000000000000000000000000", "0x", "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", 0n, "0x0000000000000000000000000000000000000000"],
  });
  const proxyTx = await relayer.writeContract({ address: factory, abi: SAFE_PROXY_FACTORY_ARTIFACT.abi, functionName: "createProxyWithNonce", args: [singleton, initializer, 1n] });
  const proxyReceipt = await publicClient.waitForTransactionReceipt({ hash: proxyTx });
  const created = parseEventLogs({ abi: SAFE_PROXY_FACTORY_ARTIFACT.abi, logs: proxyReceipt.logs, eventName: "ProxyCreation" })[0];
  const safe = getAddress((created as unknown as { args: { proxy: Address } }).args.proxy);

  // ---- Guard + a token to move + an ETH balance in the Safe ----
  const deployTx = await deployGuard(relayer as unknown as Parameters<typeof deployGuard>[0], {
    safe,
    attestor: attestor.address,
    approvers: [approver.address],
    p256Approvers: opts.p256Keys,
    p256Enabled: opts.p256Enabled ?? false,
    approvalWindowSeconds: APPROVAL_WINDOW,
    attestationTtlSeconds: ATTESTATION_TTL,
  });
  const deployReceipt = await publicClient.waitForTransactionReceipt({ hash: deployTx });
  if (deployReceipt.status !== "success") throw new Error("guard deployment reverted");
  recordGas("deploy SignholdGuard", deployReceipt);
  const guard = getAddress(deployReceipt.contractAddress!);
  const tokenContract = await viem.deployContract("ERC20Mock");
  const token = getAddress(tokenContract.address);
  await tokenContract.write.mint([safe, 1_000_000_000_000n]);
  await relayer.sendTransaction({ to: safe, value: 10n ** 18n });
  const recipient = privateKeyToAccount(generatePrivateKey()).address;

  const fx: Fixture = { conn, publicClient, chainId, relayer, owner, attestor, approver, stranger, safe, guard, token, recipient };
  // Baseline for the gas report: the same ERC-20 transfer through the Safe before any guard is set
  // (the first transfer warms the recipient's balance slot so the measured one is comparable to the
  // guarded transfers later in the suite, which also pay no first-touch cost for that slot).
  await execSafeTx(fx, plainSafeTx({ to: token, data: erc20Transfer(recipient, 1n), nonce: await safeNonce(fx) }));
  recordGas("execTransaction (no guard, ERC-20 transfer)", await execSafeTx(fx, plainSafeTx({ to: token, data: erc20Transfer(recipient, 2n), nonce: await safeNonce(fx) })));
  // Install the guard with an ordinary (not yet guarded) owner-signed Safe transaction.
  if (opts.installGuard !== false) {
    recordGas("execTransaction (setGuard install, unguarded)", await execSafeTx(fx, plainSafeTx({ to: safe, data: encodeFunctionData({ abi: SAFE_ARTIFACT.abi, functionName: "setGuard", args: [guard] }), nonce: await safeNonce(fx) })));
  }
  return fx;
}

export async function safeNonce(fx: Fixture): Promise<bigint> {
  return (await fx.publicClient.readContract({ address: fx.safe, abi: SAFE_ARTIFACT.abi, functionName: "nonce" })) as bigint;
}

/** Owner signature over the Safe tx hash: `r || s || v` with v in {27, 28} (an EIP-712 owner signature in Safe terms). */
export async function ownerSignature(fx: Fixture, tx: SafeTransaction, signer: PrivateKeyAccount = fx.owner): Promise<Hex> {
  const hash = computeSafeTxHash(fx.chainId, fx.safe, tx);
  return signer.sign({ hash });
}

export function execArgs(tx: SafeTransaction, signatures: Hex) {
  return [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, signatures] as const;
}

/** Execute a Safe transaction signed by the owner, relayed by the funded hardhat account. Resolves with the receipt. */
export async function execSafeTx(fx: Fixture, tx: SafeTransaction, signer: PrivateKeyAccount = fx.owner) {
  const signatures = await ownerSignature(fx, tx, signer);
  const hash = await fx.relayer.writeContract({ address: fx.safe, abi: SAFE_ABI_WITH_GUARD_ERRORS, functionName: "execTransaction", args: execArgs(tx, signatures) });
  const receipt = await fx.publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("execTransaction reverted on-chain");
  return receipt;
}

/** Like `execSafeTx` but expects a revert; returns the decoded custom error name (or the raw message). */
export async function execSafeTxExpectRevert(fx: Fixture, tx: SafeTransaction, signer: PrivateKeyAccount = fx.owner): Promise<string> {
  const signatures = await ownerSignature(fx, tx, signer);
  try {
    await fx.relayer.writeContract({ address: fx.safe, abi: SAFE_ABI_WITH_GUARD_ERRORS, functionName: "execTransaction", args: execArgs(tx, signatures) });
  } catch (err) {
    return revertName(err);
  }
  throw new Error("expected execTransaction to revert, but it succeeded");
}

/** Extract the custom error name (or the Safe's string reason) from a viem error. */
export function revertName(err: unknown): string {
  let e: unknown = err;
  for (let i = 0; i < 8 && e && typeof e === "object"; i++) {
    const o = e as { data?: { errorName?: string }; reason?: string; cause?: unknown; details?: string; shortMessage?: string; message?: string };
    if (o.data?.errorName) return o.data.errorName;
    if (o.reason) return o.reason;
    // Reverts during contract creation reach viem as an opaque RPC error whose details name the custom error.
    const m = /reverted with custom error '([A-Za-z0-9_]+)\(/.exec(o.details ?? "") ?? /reverted with reason string '([^']*)'/.exec(o.details ?? "");
    if (m) return m[1];
    e = o.cause;
  }
  const o = err as { shortMessage?: string; message?: string };
  return o.shortMessage ?? o.message ?? String(err);
}

export const guardAt = (fx: Fixture, client: Fixture["relayer"] = fx.relayer) =>
  getContract({ address: fx.guard, abi: SIGNHOLD_GUARD_ABI, client: { public: fx.publicClient, wallet: client } });

export function erc20Transfer(to: Address, amount: bigint): Hex {
  return encodeFunctionData({
    abi: [{ type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] }],
    functionName: "transfer",
    args: [to, amount],
  });
}

export function erc20Approve(spender: Address, amount: bigint): Hex {
  return encodeFunctionData({
    abi: [{ type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] }],
    functionName: "approve",
    args: [spender, amount],
  });
}

export async function readGuardSlot(fx: Fixture): Promise<Address> {
  const raw = await fx.publicClient.getStorageAt({ address: fx.safe, slot: GUARD_STORAGE_SLOT });
  return getAddress(`0x${(raw ?? "0x").slice(-40)}`);
}

export async function now(fx: Fixture): Promise<bigint> {
  return (await fx.publicClient.getBlock()).timestamp;
}

export const b32 = (s: string): Hex => keccak256(toHex(s));
export { concatHex };

// ---- Gas report ----
const gasRows: Array<{ op: string; gas: bigint }> = [];
export function recordGas(op: string, receipt: { gasUsed: bigint }): void {
  gasRows.push({ op, gas: receipt.gasUsed });
}
export function gasReportRows(): ReadonlyArray<{ op: string; gas: bigint }> {
  return gasRows;
}
let gasReportPrinted = false;
export function printGasReport(): void {
  if (gasRows.length === 0 || gasReportPrinted) return;
  gasReportPrinted = true;
  const byOp = new Map<string, bigint[]>();
  for (const r of gasRows) byOp.set(r.op, [...(byOp.get(r.op) ?? []), r.gas]);
  const width = Math.max(...[...byOp.keys()].map((k) => k.length));
  console.log(`\nGas report (hardhat EDR, solc 0.8.28 optimizer 1000 runs, Safe 1.5.0):\n${"operation".padEnd(width)}  min      avg      max      n`);
  for (const [op, list] of byOp) {
    const min = list.reduce((a, b) => (a < b ? a : b));
    const max = list.reduce((a, b) => (a > b ? a : b));
    const avg = list.reduce((a, b) => a + b, 0n) / BigInt(list.length);
    console.log(`${op.padEnd(width)}  ${String(min).padEnd(8)} ${String(avg).padEnd(8)} ${String(max).padEnd(8)} ${list.length}`);
  }
}

// Print once, after every suite in the process has run.
process.on("beforeExit", printGasReport);
