import type { SignholdClientError } from "@signhold/sdk";
import type { IntentInput } from "@signhold/sdk";
import type { EvmWalletProviderLike, TransactionRequestLike } from "./types.js";

/**
 * Thrown when an AgentKit call cannot be turned into a `TransactionIntent` the API would
 * accept. Raised before any network call; the wallet provider is never reached (the SDK's
 * `guard()` treats a throwing mapper as a failed check).
 */
export class IntentMappingError extends Error implements Pick<SignholdClientError, "code"> {
  readonly code = "intent_mapping";
  constructor(message: string) {
    super(`cannot build a Signhold intent from the AgentKit request: ${message}`);
    this.name = "IntentMappingError";
  }
}

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_DATA_RE = /^0x([0-9a-fA-F]{2})*$/;
const DECIMAL_RE = /^\d{1,78}$/;
const HEX_QUANTITY_RE = /^0x[0-9a-fA-F]{1,64}$/;

export function assertAddress(value: unknown, what: string): string {
  if (typeof value !== "string" || !ADDRESS_RE.test(value)) throw new IntentMappingError(`${what} is not a 0x-prefixed 20-byte address`);
  return value;
}

/** Atomic-unit amounts as AgentKit passes them: bigint (viem), decimal string (`nativeTransfer`), or a non-negative safe integer. */
export function toAmount(value: unknown, what: string): bigint {
  if (value === undefined || value === null) return 0n;
  let out: bigint;
  if (typeof value === "bigint") out = value;
  else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new IntentMappingError(`${what} must be a safe integer when given as a number`);
    out = BigInt(value);
  } else if (typeof value === "string") {
    const s = value.trim();
    if (DECIMAL_RE.test(s)) out = BigInt(s);
    else if (HEX_QUANTITY_RE.test(s)) out = BigInt(s);
    else throw new IntentMappingError(`${what} must be a decimal or 0x-hex integer string`);
  } else throw new IntentMappingError(`${what} has unsupported type ${typeof value}`);
  if (out < 0n) throw new IntentMappingError(`${what} must not be negative`);
  return out;
}

export function toCalldata(value: unknown): `0x${string}` {
  if (value === undefined || value === null) return "0x";
  if (typeof value !== "string" || !HEX_DATA_RE.test(value)) throw new IntentMappingError("data must be 0x-prefixed even-length hex");
  return value as `0x${string}`;
}

/** The chain id from `getNetwork()`: must be an EVM network with a decimal chain id. Fail closed otherwise. */
export function chainIdOf(provider: Pick<EvmWalletProviderLike, "getNetwork">): number | string {
  const network = provider.getNetwork();
  if (!network || typeof network !== "object") throw new IntentMappingError("getNetwork() returned nothing");
  if (network.protocolFamily !== "evm") throw new IntentMappingError(`network protocol family '${String(network.protocolFamily)}' is not evm`);
  const raw = network.chainId;
  if (typeof raw === "number") {
    if (!Number.isInteger(raw) || raw <= 0) throw new IntentMappingError("network chainId is not a positive integer");
    return raw;
  }
  if (typeof raw !== "string" || !/^\d{1,20}$/.test(raw) || /^0+$/.test(raw)) throw new IntentMappingError("network chainId is missing or not a positive decimal string");
  const n = Number(raw);
  return Number.isSafeInteger(n) ? n : raw;
}

export interface MappingOptions {
  /** Free-text purpose attached to the intent (`description`, ≤ 2 KB). */
  description?: string;
}

/** `sendTransaction(tx)` / `signTransaction(tx)` → intent. */
export function transactionRequestToIntent(provider: EvmWalletProviderLike, tx: TransactionRequestLike, method: string, opts: MappingOptions = {}): IntentInput {
  if (!tx || typeof tx !== "object") throw new IntentMappingError(`${method}() expects a transaction request object`);
  const from = assertAddress(provider.getAddress(), "wallet address");
  if (tx.from !== undefined && tx.from !== null) {
    const declared = assertAddress(tx.from, "transaction.from");
    if (declared.toLowerCase() !== from.toLowerCase()) throw new IntentMappingError("transaction.from differs from the wallet address");
  }
  if (Array.isArray(tx.authorizationList) && tx.authorizationList.length > 0) {
    throw new IntentMappingError("EIP-7702 authorizationList is present; delegation of the account's code cannot be checked");
  }
  const to = tx.to === undefined || tx.to === null ? undefined : assertAddress(tx.to, "transaction.to");
  return {
    chain: "evm",
    chainId: chainIdOf(provider),
    from,
    to,
    value: toAmount(tx.value, "transaction.value"),
    data: toCalldata(tx.data),
    description: opts.description,
    metadata: { integration: "@signhold/agentkit", method },
  };
}

/** `nativeTransfer(to, value)` → intent (`value` is a string of atomic units in AgentKit). */
export function nativeTransferToIntent(provider: EvmWalletProviderLike, to: unknown, value: unknown, opts: MappingOptions = {}): IntentInput {
  return {
    chain: "evm",
    chainId: chainIdOf(provider),
    from: assertAddress(provider.getAddress(), "wallet address"),
    to: assertAddress(to, "nativeTransfer to"),
    value: toAmount(value, "nativeTransfer value"),
    data: "0x",
    description: opts.description,
    metadata: { integration: "@signhold/agentkit", method: "nativeTransfer" },
  };
}
