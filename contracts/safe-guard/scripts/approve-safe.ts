#!/usr/bin/env tsx
/**
 * Approver device CLI for on-chain (SignholdGuard) approvals. Mirrors
 * `packages/api/scripts/approve.ts`: the human sees the sealed audit record AND the exact Safe
 * transaction on this display, confirms, and only then the device signs the EIP-712 `Approval`.
 *
 *   npx tsx contracts/safe-guard/scripts/approve-safe.ts \
 *       --key ./ops-wallet.key --audit-id <auditId> --url https://signhold --api-key <device api key> \
 *       --chain-id 8453 --safe 0xSAFE --guard 0xGUARD --safe-tx ./safe-tx.json \
 *       [--expected-hash 0x...] [--rpc-url https://... --relayer-key ./relayer.key] [--submit-api] [--key-id ops-wallet] [--yes]
 *
 *   # owner escape hatch: approve removal of the guard without the service
 *   npx tsx contracts/safe-guard/scripts/approve-safe.ts --recovery --key ./ops-wallet.key \
 *       --chain-id 8453 --safe 0xSAFE --guard 0xGUARD --safe-tx ./setguard-zero.json [--rpc-url ... --relayer-key ...]
 *
 * `--safe-tx` is a JSON file with the Safe transaction fields (to, value, data, operation, safeTxGas,
 * baseGas, gasPrice, gasToken, refundReceiver, nonce; integers as decimal strings). The hash is
 * computed HERE: a hash relayed by the agent is at most cross-checked (`--expected-hash`).
 * `--key` is a secp256k1 private key (0x-hex) file; `--p256-key` a P-256 private key (hex) file.
 * The private key never leaves this process. `--yes` skips the confirmation and exists for tests.
 */
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { stdin, stdout, stderr } from "node:process";
import { createPublicClient, createWalletClient, http, isAddress, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  RECOVERY_AUDIT_ID,
  approveGuardRemoval,
  approveSafeTransaction,
  parsePrivateKeyHex,
  parseSecp256k1PrivateKey,
  recordLoaderFromApi,
  submitApproval,
  submitApprovalP256,
  type DeviceSigner,
  type SafeTransaction,
} from "../src/index.js";

interface Args {
  key?: string;
  p256Key?: string;
  keyId?: string;
  auditId?: string;
  url?: string;
  apiKey?: string;
  record?: string;
  chainId?: string;
  safe?: string;
  guard?: string;
  safeTx?: string;
  expectedHash?: string;
  rpcUrl?: string;
  relayerKey?: string;
  submitApi?: boolean;
  recovery?: boolean;
  yes?: boolean;
}

function usage(code: number, msg?: string): never {
  if (msg) console.error(`error: ${msg}`);
  console.error(
    "usage: approve-safe.ts (--key <secp256k1 key file> | --p256-key <p256 key file>) --chain-id <id> --safe <addr> --guard <addr> --safe-tx <json>\n" +
      "       --audit-id <uuid> (--url <api> --api-key <key> | --record <audit-record.json>) [--expected-hash <0x..>] [--key-id <id> --submit-api]\n" +
      "       [--rpc-url <url> --relayer-key <file>] [--yes]   |   --recovery (no audit id / record)",
  );
  process.exit(code);
}

function parseArgs(argv: string[]): Args {
  const a: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    const next = () => argv[++i] ?? usage(2, `missing value for ${x}`);
    if (x === "--key") a.key = next();
    else if (x === "--p256-key") a.p256Key = next();
    else if (x === "--key-id") a.keyId = next();
    else if (x === "--audit-id") a.auditId = next();
    else if (x === "--url") a.url = next();
    else if (x === "--api-key") a.apiKey = next();
    else if (x === "--record") a.record = next();
    else if (x === "--chain-id") a.chainId = next();
    else if (x === "--safe") a.safe = next();
    else if (x === "--guard") a.guard = next();
    else if (x === "--safe-tx") a.safeTx = next();
    else if (x === "--expected-hash") a.expectedHash = next();
    else if (x === "--rpc-url") a.rpcUrl = next();
    else if (x === "--relayer-key") a.relayerKey = next();
    else if (x === "--submit-api") a.submitApi = true;
    else if (x === "--recovery") a.recovery = true;
    else if (x === "--yes") a.yes = true;
    else if (x === "-h" || x === "--help") usage(0);
    else usage(2, `unexpected argument '${x}'`);
  }
  if ((a.key ? 1 : 0) + (a.p256Key ? 1 : 0) !== 1) usage(2, "exactly one of --key / --p256-key is required");
  if (!a.chainId || !/^\d+$/.test(a.chainId)) usage(2, "--chain-id must be a decimal integer");
  if (!a.safe || !isAddress(a.safe)) usage(2, "--safe must be an EVM address");
  if (!a.guard || !isAddress(a.guard)) usage(2, "--guard must be an EVM address");
  if (!a.safeTx) usage(2, "--safe-tx is required");
  if (a.expectedHash !== undefined && !/^0x[0-9a-fA-F]{64}$/.test(a.expectedHash)) usage(2, "--expected-hash must be 32 bytes of hex");
  if ((a.url && !a.apiKey) || (!a.url && a.apiKey)) usage(2, "--url and --api-key go together");
  if ((a.rpcUrl && !a.relayerKey) || (!a.rpcUrl && a.relayerKey)) usage(2, "--rpc-url and --relayer-key go together");
  if (a.submitApi && (!a.url || !a.keyId)) usage(2, "--submit-api needs --url/--api-key and --key-id");
  if (a.submitApi && a.p256Key) usage(2, "--submit-api is only available for secp256k1 keys (the API verifies EIP-712 secp256k1 approvals)");
  if (!a.recovery) {
    if (!a.auditId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(a.auditId)) usage(2, "--audit-id must be a UUID");
    if (!a.url && !a.record) usage(2, "REFUSING TO SIGN without the sealed audit record: pass --url/--api-key or --record");
  }
  return a;
}

async function loadSafeTx(path: string): Promise<SafeTransaction> {
  const raw = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  const big = (k: string) => BigInt(String(raw[k] ?? "0"));
  const addr = (k: string, fallback = "0x0000000000000000000000000000000000000000"): Address => {
    const v = String(raw[k] ?? fallback);
    if (!isAddress(v)) throw new Error(`safe-tx: ${k} is not an address`);
    return v;
  };
  return {
    to: addr("to"),
    value: big("value"),
    data: String(raw.data ?? "0x") as Hex,
    operation: Number(raw.operation ?? 0),
    safeTxGas: big("safeTxGas"),
    baseGas: big("baseGas"),
    gasPrice: big("gasPrice"),
    gasToken: addr("gasToken"),
    refundReceiver: addr("refundReceiver"),
    nonce: big("nonce"),
  };
}

async function confirm(args: Args): Promise<boolean> {
  if (args.yes) {
    console.error("warning: --yes given; interactive confirmation skipped (not for production approvers)");
    return true;
  }
  if (!stdin.isTTY) throw new Error("REFUSING TO SIGN: no interactive terminal to confirm on (pass --yes only for tests)");
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const answer = await rl.question("Type APPROVE to sign this Safe transaction, anything else to abort: ");
    return answer.trim() === "APPROVE";
  } finally {
    rl.close();
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const signer: DeviceSigner = args.key
    ? { kind: "secp256k1", signer: privateKeyToAccount(parseSecp256k1PrivateKey(await readFile(args.key, "utf8"))) }
    : { kind: "p256", privateKey: parsePrivateKeyHex(await readFile(args.p256Key!, "utf8")) };
  const safeTx = await loadSafeTx(args.safeTx!);
  const common = { chainId: BigInt(args.chainId!), guard: args.guard as Address, safe: args.safe as Address, safeTx, signer, confirm: () => confirm(args), display: (lines: string[]) => stderr.write(`${lines.join("\n")}\n`) };

  const result = args.recovery
    ? await approveGuardRemoval(common)
    : await approveSafeTransaction({
        ...common,
        auditId: args.auditId!,
        loadRecord: args.url ? recordLoaderFromApi(args.url, args.apiKey!, args.auditId!) : async () => JSON.parse(await readFile(args.record!, "utf8")),
        expectedSafeTxHash: args.expectedHash as Hex | undefined,
      });

  const out = {
    safeTxHash: result.safeTxHash,
    auditId: result.message.auditId,
    recovery: result.message.auditId === RECOVERY_AUDIT_ID,
    approvedAt: result.message.approvedAt.toString(),
    ...(result.secp256k1 ? { approver: result.secp256k1.approver, signature: result.secp256k1.signature } : {}),
    ...(result.p256 ? { qx: result.p256.publicKey.qx, qy: result.p256.publicKey.qy, r: result.p256.signature.r, s: result.p256.signature.s } : {}),
  };
  console.log(JSON.stringify(out, null, 2));

  if (args.rpcUrl) {
    const relayer = privateKeyToAccount(parseSecp256k1PrivateKey(await readFile(args.relayerKey!, "utf8")));
    const wallet = createWalletClient({ account: relayer, transport: http(args.rpcUrl) });
    const publicClient = createPublicClient({ transport: http(args.rpcUrl) });
    const hash = result.secp256k1
      ? await submitApproval(wallet, { guard: args.guard as Address, message: result.message, approver: result.secp256k1.approver, signature: result.secp256k1.signature })
      : await submitApprovalP256(wallet, { guard: args.guard as Address, message: result.message, publicKey: result.p256!.publicKey, signature: result.p256!.signature });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    console.error(`on-chain: submitApproval ${hash} ${receipt.status} (gas ${receipt.gasUsed})`);
    if (receipt.status !== "success") process.exit(1);
  }

  if (args.submitApi && result.secp256k1) {
    const res = await fetch(`${args.url!.replace(/\/+$/, "")}/v1/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "x-api-key": args.apiKey! },
      body: JSON.stringify({ auditId: args.auditId, keyId: args.keyId, signature: result.secp256k1.signature, approvedAt: new Date(Number(result.message.approvedAt) * 1000).toISOString(), scheme: "eip712" }),
    });
    console.error(`api: ${res.status} ${await res.text()}`);
    if (!res.ok) process.exit(1);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
