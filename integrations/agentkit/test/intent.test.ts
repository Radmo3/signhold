import { describe, expect, it } from "vitest";
import { IntentMappingError, chainIdOf, nativeTransferToIntent, transactionRequestToIntent } from "../src/index.js";
import { AGENT, BOB, MockEvmWalletProvider, USDC } from "./helpers.js";

describe("intent mapping", () => {
  const p = new MockEvmWalletProvider();

  it("maps a viem-style TransactionRequest (bigint value, 0x data) and defaults value/data", () => {
    expect(transactionRequestToIntent(p, { to: USDC, value: 5n, data: "0xabcd" }, "sendTransaction")).toEqual({
      chain: "evm", chainId: 8453, from: AGENT, to: USDC, value: 5n, data: "0xabcd", description: undefined, metadata: { integration: "@signhold/agentkit", method: "sendTransaction" },
    });
    expect(transactionRequestToIntent(p, { to: BOB }, "signTransaction")).toMatchObject({ value: 0n, data: "0x" });
    expect(transactionRequestToIntent(p, { to: null, data: "0x60016002" }, "sendTransaction").to).toBeUndefined(); // contract creation
  });

  it("accepts decimal / hex string and safe-integer values; refuses the rest", () => {
    expect(transactionRequestToIntent(p, { to: BOB, value: "1000" }, "sendTransaction").value).toBe(1000n);
    expect(transactionRequestToIntent(p, { to: BOB, value: "0x10" }, "sendTransaction").value).toBe(16n);
    expect(transactionRequestToIntent(p, { to: BOB, value: 42 }, "sendTransaction").value).toBe(42n);
    for (const value of [-1n, -1, 1.5, "1e18", "", "abc", {}, true, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => transactionRequestToIntent(p, { to: BOB, value: value as never }, "sendTransaction")).toThrow(IntentMappingError);
    }
  });

  it("refuses bad addresses, from mismatches, odd calldata and EIP-7702 delegations", () => {
    expect(() => transactionRequestToIntent(p, { to: "0xabc" }, "sendTransaction")).toThrow(/transaction.to/);
    expect(() => transactionRequestToIntent(p, { to: BOB, from: BOB }, "sendTransaction")).toThrow(/differs from the wallet address/);
    expect(() => transactionRequestToIntent(p, { to: BOB, data: "0xabc" }, "sendTransaction")).toThrow(/even-length hex/);
    expect(() => transactionRequestToIntent(p, { to: BOB, data: "abcd" }, "sendTransaction")).toThrow(/even-length hex/);
    expect(() => transactionRequestToIntent(p, { to: BOB, authorizationList: [{}] }, "sendTransaction")).toThrow(/EIP-7702/);
    expect(transactionRequestToIntent(p, { to: BOB, authorizationList: [] }, "sendTransaction")).toBeTruthy();
    expect(() => transactionRequestToIntent(p, "tx" as never, "sendTransaction")).toThrow(/expects a transaction request object/);
    expect(() => transactionRequestToIntent(new MockEvmWalletProvider(undefined, "0xnope"), { to: BOB }, "sendTransaction")).toThrow(/wallet address/);
  });

  it("nativeTransfer(to, value) uses atomic-unit strings and empty calldata", () => {
    expect(nativeTransferToIntent(p, BOB, "123456789012345678901234567890")).toMatchObject({ to: BOB, value: 123456789012345678901234567890n, data: "0x", from: AGENT, chainId: 8453 });
    expect(() => nativeTransferToIntent(p, BOB, "1.5")).toThrow(IntentMappingError);
    expect(() => nativeTransferToIntent(p, 5 as never, "1")).toThrow(IntentMappingError);
  });

  it("chainIdOf: EVM only, decimal string or integer, big ids stay strings", () => {
    expect(chainIdOf({ getNetwork: () => ({ protocolFamily: "evm", chainId: "1" }) })).toBe(1);
    expect(chainIdOf({ getNetwork: () => ({ protocolFamily: "evm", chainId: 10 as never }) })).toBe(10);
    expect(chainIdOf({ getNetwork: () => ({ protocolFamily: "evm", chainId: "99999999999999999999" }) })).toBe("99999999999999999999");
    for (const network of [{ protocolFamily: "svm", chainId: "1" }, { protocolFamily: "evm" }, { protocolFamily: "evm", chainId: "0" }, { protocolFamily: "evm", chainId: "0x1" }, { protocolFamily: "evm", chainId: -5 as never }, null as never]) {
      expect(() => chainIdOf({ getNetwork: () => network })).toThrow(IntentMappingError);
    }
  });
});
