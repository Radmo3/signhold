/**
 * Safe transaction hashing, mirroring `Safe.getTransactionHash` of
 * `@safe-global/safe-smart-account@1.5.0` (identical in `@safe-global/safe-contracts@1.4.1`):
 *
 *   EIP712Domain(uint256 chainId,address verifyingContract)
 *   SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,
 *          uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)
 *
 * Parity with the on-chain function is asserted in `test/guard.test.ts`.
 */
import { encodeFunctionData, getAddress, hashTypedData, isAddress, isHex, type Address, type Hex } from "viem";

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

export enum SafeOperation {
  Call = 0,
  DelegateCall = 1,
}

export interface SafeTransaction {
  to: Address;
  value: bigint;
  data: Hex;
  operation: SafeOperation;
  safeTxGas: bigint;
  baseGas: bigint;
  gasPrice: bigint;
  gasToken: Address;
  refundReceiver: Address;
  nonce: bigint;
}

export const SAFE_TX_TYPES = {
  SafeTx: [
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "data", type: "bytes" },
    { name: "operation", type: "uint8" },
    { name: "safeTxGas", type: "uint256" },
    { name: "baseGas", type: "uint256" },
    { name: "gasPrice", type: "uint256" },
    { name: "gasToken", type: "address" },
    { name: "refundReceiver", type: "address" },
    { name: "nonce", type: "uint256" },
  ],
} as const;

/** A plain call with no gas refund: the only shape the Signhold service attests. */
export function plainSafeTx(input: { to: Address; value?: bigint; data?: Hex; nonce: bigint }): SafeTransaction {
  return {
    to: input.to,
    value: input.value ?? 0n,
    data: input.data ?? "0x",
    operation: SafeOperation.Call,
    safeTxGas: 0n,
    baseGas: 0n,
    gasPrice: 0n,
    gasToken: ZERO_ADDRESS,
    refundReceiver: ZERO_ADDRESS,
    nonce: input.nonce,
  };
}

export function safeDomain(chainId: bigint | number, safe: Address) {
  return { chainId: BigInt(chainId), verifyingContract: getAddress(safe) } as const;
}

/** `Safe.getTransactionHash(...)` computed off-chain. */
export function computeSafeTxHash(chainId: bigint | number, safe: Address, tx: SafeTransaction): Hex {
  assertSafeTransaction(tx);
  return hashTypedData({
    domain: safeDomain(chainId, safe),
    types: SAFE_TX_TYPES,
    primaryType: "SafeTx",
    message: {
      to: getAddress(tx.to),
      value: tx.value,
      data: tx.data,
      operation: tx.operation,
      safeTxGas: tx.safeTxGas,
      baseGas: tx.baseGas,
      gasPrice: tx.gasPrice,
      gasToken: getAddress(tx.gasToken),
      refundReceiver: getAddress(tx.refundReceiver),
      nonce: tx.nonce,
    },
  });
}

export function assertSafeTransaction(tx: SafeTransaction): void {
  if (!isAddress(tx.to) || !isAddress(tx.gasToken) || !isAddress(tx.refundReceiver)) throw new TypeError("SafeTransaction: invalid address");
  if (!isHex(tx.data) || tx.data.length % 2 !== 0) throw new TypeError("SafeTransaction: data must be even-length hex");
  if (tx.operation !== SafeOperation.Call && tx.operation !== SafeOperation.DelegateCall) throw new TypeError("SafeTransaction: invalid operation");
  for (const [k, v] of Object.entries({ value: tx.value, safeTxGas: tx.safeTxGas, baseGas: tx.baseGas, gasPrice: tx.gasPrice, nonce: tx.nonce })) {
    if (typeof v !== "bigint" || v < 0n || v >= 1n << 256n) throw new TypeError(`SafeTransaction: ${k} must be a uint256 bigint`);
  }
}

/** True when the transaction is a plain call with no gas refund (what the service is willing to attest). */
export function isPlainSafeTx(tx: SafeTransaction): boolean {
  return tx.operation === SafeOperation.Call && tx.gasPrice === 0n && tx.gasToken.toLowerCase() === ZERO_ADDRESS && tx.refundReceiver.toLowerCase() === ZERO_ADDRESS;
}

export const SAFE_SET_GUARD_ABI = [
  { type: "function", name: "setGuard", stateMutability: "nonpayable", inputs: [{ name: "guard", type: "address" }], outputs: [] },
] as const;

/** Calldata for `Safe.setGuard(guard)`; `setGuard(address(0))` removes the guard. */
export function encodeSetGuard(guard: Address): Hex {
  return encodeFunctionData({ abi: SAFE_SET_GUARD_ABI, functionName: "setGuard", args: [guard] });
}

/** Whether `tx` is exactly the guard-removal transaction the guard's owner escape hatch accepts. */
export function isGuardRemovalTx(safe: Address, tx: SafeTransaction): boolean {
  return tx.to.toLowerCase() === safe.toLowerCase() && tx.value === 0n && isPlainSafeTx(tx) && tx.data.toLowerCase() === encodeSetGuard(ZERO_ADDRESS).toLowerCase();
}
