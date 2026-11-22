import type { AgentContext, TransactionIntent } from "@signhold/core";
import { guard, type CheckOptions, type EscalationInfo, type Guarded, type SignholdClient, type WaitForApprovalOptions } from "@signhold/sdk";
import { DecisionLog } from "./decisions.js";
import { nativeTransferToIntent, transactionRequestToIntent } from "./intent.js";
import type { EvmWalletProviderLike, TransactionRequestLike } from "./types.js";

/**
 * Methods of an AgentKit `EvmWalletProvider` that produce a signed or broadcast
 * transaction and are therefore checked (`POST /v1/check`) before they run. Enumerated
 * from `@coinbase/agentkit@0.10.4` (`evmWalletProvider.d.ts`, `walletProvider.d.ts`).
 */
export const GUARDED_WALLET_METHODS = ["sendTransaction", "signTransaction", "nativeTransfer"] as const;
export type GuardedWalletMethod = (typeof GUARDED_WALLET_METHODS)[number];

/**
 * Members that would let a signature or a transaction out without a check, refused by
 * default (`GuardUncheckableError` on call; data members read as `undefined`). Enumerated
 * from the EVM wallet providers shipped in `@coinbase/agentkit@0.10.4`:
 *
 * On every `EvmWalletProvider`:
 * - `sign(hash)`: a raw secp256k1 signature over an arbitrary 32-byte hash, i.e. over any
 *   transaction hash. Nothing to decode or simulate.
 * - `signTypedData(typedData)`: EIP-712. ERC-2612 permits, Permit2, x402 `transferWithAuthorization`
 *   and exchange orders are token approvals or transfers expressed as signatures; Signhold
 *   checks transactions, not signatures.
 * - `signMessage(message)`: EIP-191. Rarely moves funds by itself, but some protocols accept
 *   it as an order signature; it is opt-in.
 *
 * Provider-specific escape hatches:
 * - `getClient()` (CdpEvmWalletProvider, CdpSmartWalletProvider): the `CdpClient`;
 *   `client.evm.sendTransaction(...)` / `account.swap(...)` / `useSpendPermission(...)` bypass the wrapper.
 * - `exportWallet()` (CDP and Privy providers): key / account export.
 * - `smartAccount`, `ownerAccount` (CdpSmartWalletProvider): the account objects themselves,
 *   which can send user operations and sign.
 * - `getWallet()`, `gaslessERC20Transfer()`, `createTrade()`, `deployToken()`, `deployContract()`,
 *   `deployNFT()` (LegacyCdpWalletProvider): broadcast through the legacy CDP SDK without
 *   passing `sendTransaction`.
 * - `getKernelAccount()`, `getIntentClient()` (ZeroDevWalletProvider): the kernel account and
 *   intent client send user operations / intents directly.
 *
 * `toSigner()` is NOT in this list: it stays available, but is invoked so that the viem
 * `LocalAccount` it returns calls back into the guarded methods (`reentrant`), i.e. its
 * `signTransaction` is checked and its `sign` / `signTypedData` are refused.
 */
export const UNCHECKED_BY_DEFAULT = [
  "sign",
  "signMessage",
  "signTypedData",
  "getClient",
  "exportWallet",
  "smartAccount",
  "ownerAccount",
  "getWallet",
  "gaslessERC20Transfer",
  "createTrade",
  "deployToken",
  "deployContract",
  "deployNFT",
  "getKernelAccount",
  "getIntentClient",
] as const;
export type UncheckableMember = (typeof UNCHECKED_BY_DEFAULT)[number];

export interface GuardWalletProviderOptions {
  /** Static agent context or a function computing it per intent (agent id, spend window, lists). */
  context: AgentContext | ((intent: TransactionIntent) => AgentContext | Promise<AgentContext>);
  /**
   * On `escalate`: `false` / absent throws `GuardEscalatedError` (carrying `auditId` and the
   * human's `challenge`); `true` or options blocks the call, polling the server, until a
   * registered approver device has signed and the server has verified it. Only a
   * server-verified approval ever lets the call proceed.
   */
  waitForApproval?: boolean | WaitForApprovalOptions;
  /** Route `auditId` + `challenge` to the human. Its return value cannot approve anything; a throw aborts the call. */
  onEscalationPending?: (info: EscalationInfo) => void | Promise<void>;
  /** Observability for every verdict. A throw aborts the call (fail closed). */
  onDecision?: (info: EscalationInfo) => void | Promise<void>;
  checkOptions?: CheckOptions;
  generateId?: () => string;
  /**
   * Members from `UNCHECKED_BY_DEFAULT` that may run unchecked. Default: none. Every entry
   * is a bypass of Signhold for whatever that member does; list it only when the agent's
   * tools need it and the risk is understood (e.g. `signMessage` for sign-in flows).
   */
  allowUnchecked?: readonly UncheckableMember[];
  /** Free-text purpose for the intent (`description`), per call. Default: none. */
  describe?: (method: GuardedWalletMethod, args: readonly unknown[]) => string | undefined;
  /** Where decisions are remembered for `signholdActionProvider`. Default: a new `DecisionLog`. */
  decisions?: DecisionLog;
}

export type GuardedEvmWalletProvider<P extends EvmWalletProviderLike> = Guarded<P>;

const logs = new WeakMap<object, DecisionLog>();

/** The `DecisionLog` a guarded provider writes to (for `signholdActionProvider({ wallet })`). */
export function getDecisionLog(guarded: object): DecisionLog | undefined {
  return logs.get(guarded);
}

/**
 * Wrap an AgentKit `EvmWalletProvider` so that `sendTransaction`, `signTransaction` and
 * `nativeTransfer` are submitted to Signhold first and run only on a literal `allow` (or,
 * on `escalate`, after a server-verified human approval when `waitForApproval` is set).
 * `block` throws `GuardBlockedError`; any failure of the check itself (network, 4xx/5xx,
 * malformed response, a throwing hook, an unmappable request) throws and the provider is
 * never called. Read-only methods (`getAddress`, `getNetwork`, `getBalance`, `readContract`,
 * `getPublicClient`, `waitForTransactionReceipt`, ...) pass through untouched, bound to the
 * real instance. Members listed in `UNCHECKED_BY_DEFAULT` are refused unless allowed.
 *
 * Approval is always server mode: there is no in-process approval callback to configure,
 * because the agent process is exactly what must not be able to approve.
 */
export function guardWalletProvider<P extends EvmWalletProviderLike>(provider: P, client: SignholdClient, options: GuardWalletProviderOptions): GuardedEvmWalletProvider<P> {
  if (!provider || typeof provider !== "object") throw new TypeError("guardWalletProvider(): provider must be an object");
  if (typeof provider.getAddress !== "function" || typeof provider.getNetwork !== "function") {
    throw new TypeError("guardWalletProvider(): provider must implement getAddress() and getNetwork()");
  }
  if (!options || typeof options !== "object" || options.context === undefined) throw new TypeError("guardWalletProvider(): options.context is required");
  for (const forbidden of ["approval", "onEscalate"]) {
    if (forbidden in options) throw new TypeError(`guardWalletProvider(): '${forbidden}' is not supported; approval is always server-verified`);
  }
  const allow = new Set<string>(options.allowUnchecked ?? []);
  for (const name of allow) {
    if (!(UNCHECKED_BY_DEFAULT as readonly string[]).includes(name)) throw new TypeError(`guardWalletProvider(): '${name}' is not an unchecked-by-default member`);
  }
  const deny = UNCHECKED_BY_DEFAULT.filter((m) => !allow.has(m));
  const decisions = options.decisions ?? new DecisionLog();
  const describe = options.describe;

  const guarded = guard(provider, client, {
    toIntent: () => {
      // Every guarded method has its own mapper below; reaching this means a bug, so fail closed.
      throw new Error("guardWalletProvider(): no intent mapper for this method");
    },
    methods: [
      { name: "sendTransaction", toIntent: (tx: TransactionRequestLike) => transactionRequestToIntent(provider, tx, "sendTransaction", { description: describe?.("sendTransaction", [tx]) }) },
      { name: "signTransaction", toIntent: (tx: TransactionRequestLike) => transactionRequestToIntent(provider, tx, "signTransaction", { description: describe?.("signTransaction", [tx]) }) },
      { name: "nativeTransfer", toIntent: (to: unknown, value: unknown) => nativeTransferToIntent(provider, to, value, { description: describe?.("nativeTransfer", [to, value]) }) },
    ],
    deny,
    bindPassthrough: true,
    reentrant: ["toSigner"],
    context: options.context,
    checkOptions: options.checkOptions,
    approval: "server",
    waitForApproval: options.waitForApproval,
    onEscalationPending: options.onEscalationPending,
    onDecision: async (info) => {
      decisions.record(info);
      await options.onDecision?.(info);
    },
    generateId: options.generateId,
  });
  logs.set(guarded, decisions);
  return guarded;
}
