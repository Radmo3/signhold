/**
 * Structural (duck-typed) views of the Coinbase AgentKit types this package touches.
 *
 * They mirror `@coinbase/agentkit@0.10.4` (`dist/wallet-providers/walletProvider.d.ts`,
 * `dist/wallet-providers/evmWalletProvider.d.ts`, `dist/network/types.d.ts`,
 * `dist/action-providers/actionProvider.d.ts`) closely enough that a real
 * `EvmWalletProvider` satisfies `EvmWalletProviderLike` and a `SignholdActionProvider`
 * satisfies AgentKit's `ActionProvider` (see `probe/agentkit-types.probe.ts`). They exist so
 * that this package has no runtime or compile-time dependency on `@coinbase/agentkit` (993
 * transitive packages) and so that the tests run against a mock provider without network.
 */
import type { z } from "zod";

/** `Network` from `@coinbase/agentkit` (`dist/network/types.d.ts`). */
export interface NetworkLike {
  protocolFamily: string;
  networkId?: string;
  /** Decimal chain id as a string, e.g. "8453". */
  chainId?: string;
}

/**
 * The fields of viem's `TransactionRequest` that matter for a Signhold check. AgentKit
 * action providers pass `{ to, data, value }` objects (see `erc20ActionProvider`,
 * `wethActionProvider`, the CDP swap approval); the other fields (gas, nonce, fees, type,
 * `authorizationList`, blobs) are read only to refuse what cannot be checked.
 */
export interface TransactionRequestLike {
  to?: string | null;
  from?: string;
  value?: bigint | number | string;
  data?: string;
  /** EIP-7702: a non-empty list delegates the account's code; refused (cannot be simulated). */
  authorizationList?: readonly unknown[];
  [extra: string]: unknown;
}

/**
 * `EvmWalletProvider` from `@coinbase/agentkit` (abstract methods only; `toSigner()` is a
 * concrete base-class method). Everything is optional on the input side because the
 * wrapper is duck-typed; what the provider has is what gets guarded.
 */
export interface EvmWalletProviderLike {
  getAddress(): string;
  getNetwork(): NetworkLike;
  getName?(): string;
  getBalance?(): Promise<bigint>;
  nativeTransfer?(to: string, value: string): Promise<string>;
  sendTransaction?(transaction: TransactionRequestLike): Promise<string>;
  signTransaction?(transaction: TransactionRequestLike): Promise<string>;
  sign?(hash: string): Promise<string>;
  signMessage?(message: string | Uint8Array): Promise<string>;
  signTypedData?(typedData: unknown): Promise<string>;
  toSigner?(): unknown;
  waitForTransactionReceipt?(txHash: string): Promise<unknown>;
  readContract?(params: unknown): Promise<unknown>;
  getPublicClient?(): unknown;
}

/** `Action` from `@coinbase/agentkit` (`dist/action-providers/actionProvider.d.ts`). */
export interface ActionLike<TArgs = unknown> {
  name: string;
  description: string;
  schema: z.ZodSchema;
  invoke: (args: TArgs) => Promise<string>;
}

/**
 * The surface `AgentKit.getActions()` uses from an action provider (`agentkit.js`:
 * `supportsNetwork(network)`, `getActions(walletProvider)`, `name`), plus the
 * `actionProviders` field the abstract class declares.
 */
export interface ActionProviderLike<TWalletProvider = unknown> {
  readonly name: string;
  readonly actionProviders: ActionProviderLike<TWalletProvider>[];
  getActions(walletProvider: TWalletProvider): ActionLike[];
  supportsNetwork(network: NetworkLike): boolean;
}
