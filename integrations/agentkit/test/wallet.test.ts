import { describe, expect, it, vi } from "vitest";
import { SignholdClient, type EscalationInfo } from "@signhold/sdk";
import {
  ApprovalDeniedError,
  GuardBlockedError,
  GuardEscalatedError,
  GuardUncheckableError,
  IntentMappingError,
  UNCHECKED_BY_DEFAULT,
  getDecisionLog,
  guardWalletProvider,
} from "../src/index.js";
import { AGENT, BOB, CHALLENGE, MockEvmWalletProvider, USDC, checkBody, clientWith, jsonResponse, mockFetch, posts } from "./helpers.js";

const transfer = { to: USDC, data: "0xa9059cbb" + "00".repeat(12) + BOB.slice(2) + "00".repeat(31) + "05", value: 0n };
const ctx = { context: { agentId: "agentkit-agent", windowSeconds: 3600 } };
const ID = "00000000-0000-4000-8000-000000000001";

describe("guardWalletProvider: verdicts", () => {
  it("allow: sendTransaction / signTransaction / nativeTransfer are checked with an intent built from the request and the provider, then run", async () => {
    const p = new MockEvmWalletProvider();
    const { client, calls } = clientWith(jsonResponse(200, checkBody("allow")));
    const w = guardWalletProvider(p, client, { ...ctx, generateId: () => ID, describe: (m) => `via ${m}` });

    expect(await w.sendTransaction(transfer)).toBe("0xhash");
    expect(await w.signTransaction({ ...transfer, from: AGENT })).toBe("0xsignedtx");
    expect(await w.nativeTransfer(BOB, "1000")).toBe("0xhash");
    expect(p.calls.map((c) => c.method)).toEqual(["sendTransaction", "signTransaction", "nativeTransfer", "sendTransaction"]);

    const bodies = posts(calls).map((c) => JSON.parse(c.init.body as string));
    expect(bodies).toHaveLength(3); // nativeTransfer re-enters sendTransaction on the inner instance: one check, not two
    expect(bodies[0].intent).toEqual({ id: ID, chain: "evm", chainId: 8453, from: AGENT, to: USDC, value: "0", data: transfer.data, description: "via sendTransaction", metadata: { integration: "@signhold/agentkit", method: "sendTransaction" } });
    expect(bodies[1].intent.metadata.method).toBe("signTransaction");
    expect(bodies[2].intent).toMatchObject({ to: BOB, value: "1000", data: "0x", metadata: { method: "nativeTransfer" } });
    expect(bodies[0].context).toMatchObject({ agentId: "agentkit-agent", windowSeconds: 3600 });
    for (const c of posts(calls)) expect(c.url).toBe("http://gw/v1/check");
  });

  it("block: throws GuardBlockedError and never calls the provider", async () => {
    const p = new MockEvmWalletProvider();
    const { client } = clientWith(jsonResponse(200, checkBody("block")));
    const w = guardWalletProvider(p, client, ctx);
    for (const run of [() => w.sendTransaction(transfer), () => w.signTransaction(transfer), () => w.nativeTransfer(BOB, "1")]) {
      const err = await run().catch((e) => e);
      expect(err).toBeInstanceOf(GuardBlockedError);
      expect(err.decision.verdict).toBe("block");
    }
    expect(p.calls).toHaveLength(0);
  });

  it("escalate (default): throws GuardEscalatedError carrying auditId + challenge; provider untouched", async () => {
    const p = new MockEvmWalletProvider();
    const { client } = clientWith(jsonResponse(200, checkBody("escalate")));
    const pending = vi.fn();
    const w = guardWalletProvider(p, client, { ...ctx, onEscalationPending: pending });
    const err = await w.sendTransaction(transfer).catch((e) => e);
    expect(err).toBeInstanceOf(GuardEscalatedError);
    expect(err.challenge).toBe(CHALLENGE);
    expect(err.auditId).toMatch(/aude$/);
    expect(pending).toHaveBeenCalledOnce();
    expect((pending.mock.calls[0][0] as EscalationInfo).method).toBe("sendTransaction");
    expect(p.calls).toHaveLength(0);
  });

  it("escalate + waitForApproval: runs only once the server reports `approved`", async () => {
    const p = new MockEvmWalletProvider();
    const auditId = "00000000-0000-4000-8000-00000000aude";
    const { client, calls } = clientWith(
      jsonResponse(200, checkBody("escalate")),
      jsonResponse(200, { auditId, status: "pending" }),
      jsonResponse(200, { auditId, status: "approved", approvedBy: "ops-phone", approvalId: "ap-1" }),
    );
    const w = guardWalletProvider(p, client, { ...ctx, waitForApproval: { intervalMs: 50, timeoutMs: 5_000 } });
    expect(await w.sendTransaction(transfer)).toBe("0xhash");
    expect(p.calls).toHaveLength(1);
    expect(calls.map((c) => c.init.method)).toEqual(["POST", "GET", "GET"]);
    expect(calls[1].url).toBe(`http://gw/v1/approvals/${auditId}`);
  });

  it("escalate + waitForApproval: rejected / expired / timeout never reach the provider", async () => {
    const auditId = "00000000-0000-4000-8000-00000000aude";
    for (const terminal of ["rejected", "expired", "unknown"]) {
      const p = new MockEvmWalletProvider();
      const { client } = clientWith(jsonResponse(200, checkBody("escalate")), jsonResponse(200, { auditId, status: terminal }));
      const w = guardWalletProvider(p, client, { ...ctx, waitForApproval: { intervalMs: 20, timeoutMs: 500 } });
      await expect(w.nativeTransfer(BOB, "1")).rejects.toBeInstanceOf(ApprovalDeniedError);
      expect(p.calls).toHaveLength(0);
    }
    const p = new MockEvmWalletProvider();
    const { client } = clientWith(jsonResponse(200, checkBody("escalate")), jsonResponse(200, { auditId, status: "pending" }));
    const w = guardWalletProvider(p, client, { ...ctx, waitForApproval: { intervalMs: 20, timeoutMs: 100 } });
    await expect(w.sendTransaction(transfer)).rejects.toMatchObject({ code: "approval_timeout" });
    expect(p.calls).toHaveLength(0);
  });
});

describe("guardWalletProvider: read-only members pass through untouched", () => {
  it("getAddress / getNetwork / getBalance / readContract / getPublicClient / waitForTransactionReceipt work (bound to the real instance) and hit no network", async () => {
    const p = new MockEvmWalletProvider();
    const { client, calls } = clientWith(jsonResponse(200, checkBody("block")));
    const w = guardWalletProvider(p, client, ctx);
    expect(w.getAddress()).toBe(AGENT);
    expect(w.getNetwork()).toEqual({ protocolFamily: "evm", networkId: "base-mainnet", chainId: "8453" });
    expect(w.getName()).toBe("mock_evm_wallet_provider");
    expect(await w.getBalance()).toBe(10n ** 18n);
    expect(await w.readContract({ abi: [], functionName: "decimals" })).toBe(6);
    expect(w.getPublicClient()).toEqual({ chain: { id: 8453 } });
    expect(await w.waitForTransactionReceipt("0xabc")).toMatchObject({ status: "success" });
    expect(calls).toHaveLength(0);
    expect(w).toBeInstanceOf(MockEvmWalletProvider);
    expect(w.__signholdInner).toBe(p);
  });
});

describe("guardWalletProvider: fails closed", () => {
  const unreachable = () => clientWith(new Error("ECONNREFUSED"));

  it("network error, 5xx, 4xx: provider never called", async () => {
    for (const { client } of [unreachable(), clientWith(jsonResponse(503, { error: "x" })), clientWith(jsonResponse(401, { error: "unauthorized" })), clientWith(jsonResponse(400, { error: "bad_request" }))]) {
      const p = new MockEvmWalletProvider();
      const w = guardWalletProvider(p, client, ctx);
      await expect(w.sendTransaction(transfer)).rejects.toMatchObject({ name: expect.stringMatching(/^Signhold/) });
      await expect(w.nativeTransfer(BOB, "1")).rejects.toBeTruthy();
      expect(p.calls).toHaveLength(0);
    }
  });

  it("malformed responses (bad verdict, missing decision, missing auditId, non-JSON, bad challenge) are not permission", async () => {
    const bodies: unknown[] = [
      { decision: { ...checkBody("allow").decision as object, verdict: "ALLOW" }, auditId: "a" },
      { decision: { verdict: "allow" } },
      { auditId: "a" },
      "allow",
      null,
      { ...checkBody("escalate"), approval: { challenge: "nope", expiresAt: "x" } },
    ];
    for (const body of bodies) {
      const { fetch } = mockFetch(() => new Response(typeof body === "string" ? body : JSON.stringify(body), { status: 200 }));
      const p = new MockEvmWalletProvider();
      const w = guardWalletProvider(p, new SignholdClient({ baseUrl: "http://gw", fetch, retries: 0 }), ctx);
      await expect(w.sendTransaction(transfer)).rejects.toMatchObject({ code: "protocol_error" });
      expect(p.calls).toHaveLength(0);
    }
  });

  it("a throwing hook (onDecision, onEscalationPending, context, describe) aborts the call", async () => {
    const p = new MockEvmWalletProvider();
    const { client } = clientWith(jsonResponse(200, checkBody("allow")));
    await expect(guardWalletProvider(p, client, { ...ctx, onDecision: () => { throw new Error("metrics down"); } }).sendTransaction(transfer)).rejects.toThrow("metrics down");
    await expect(guardWalletProvider(p, client, { context: () => { throw new Error("no ctx"); } }).sendTransaction(transfer)).rejects.toThrow("no ctx");
    await expect(guardWalletProvider(p, client, { ...ctx, describe: () => { throw new Error("desc"); } }).sendTransaction(transfer)).rejects.toThrow("desc");
    const { client: esc } = clientWith(jsonResponse(200, checkBody("escalate")));
    await expect(guardWalletProvider(p, esc, { ...ctx, waitForApproval: true, onEscalationPending: () => { throw new Error("pager down"); } }).sendTransaction(transfer)).rejects.toThrow("pager down");
    expect(p.calls).toHaveLength(0);
  });

  it("an unmappable request is refused before any network call", async () => {
    const { client, calls } = clientWith(jsonResponse(200, checkBody("allow")));
    const p = new MockEvmWalletProvider();
    const w = guardWalletProvider(p, client, ctx);
    const bad: Array<() => Promise<unknown>> = [
      () => w.sendTransaction({ to: "0x123" }),
      () => w.sendTransaction({ ...transfer, from: BOB }),
      () => w.sendTransaction({ ...transfer, value: -1n }),
      () => w.sendTransaction({ ...transfer, value: 1.5 }),
      () => w.sendTransaction({ ...transfer, value: "1e18" }),
      () => w.sendTransaction({ ...transfer, data: "0xabc" }),
      () => w.sendTransaction({ ...transfer, authorizationList: [{ address: BOB }] }),
      () => w.sendTransaction(undefined as never),
      () => w.nativeTransfer("bob", "1"),
      () => w.nativeTransfer(BOB, "-1"),
      () => w.nativeTransfer(BOB, 1.2 as never),
    ];
    for (const run of bad) await expect(run()).rejects.toBeInstanceOf(IntentMappingError);
    // Non-EVM or chain-id-less networks: refused.
    for (const network of [{ protocolFamily: "svm", chainId: "1" }, { protocolFamily: "evm" }, { protocolFamily: "evm", chainId: "0" }, { protocolFamily: "evm", chainId: "abc" }]) {
      const q = new MockEvmWalletProvider(network);
      await expect(guardWalletProvider(q, client, ctx).sendTransaction(transfer)).rejects.toBeInstanceOf(IntentMappingError);
      expect(q.calls).toHaveLength(0);
    }
    expect(calls).toHaveLength(0);
    expect(p.calls).toHaveLength(0);
  });
});

describe("guardWalletProvider: uncheckable members", () => {
  it("sign / signMessage / signTypedData / getClient / exportWallet are refused; smartAccount / ownerAccount read as undefined", async () => {
    const p = new MockEvmWalletProvider();
    const { client, calls } = clientWith(jsonResponse(200, checkBody("allow")));
    const w = guardWalletProvider(p, client, ctx);
    expect(() => w.sign("0x" + "00".repeat(32))).toThrow(GuardUncheckableError);
    expect(() => w.signMessage("hello")).toThrow(GuardUncheckableError);
    expect(() => w.signTypedData({ primaryType: "Permit" })).toThrow(GuardUncheckableError);
    expect(() => w.getClient()).toThrow(GuardUncheckableError);
    expect(() => w.exportWallet()).toThrow(GuardUncheckableError);
    expect(w.smartAccount).toBeUndefined();
    expect(w.ownerAccount).toBeUndefined();
    expect(p.calls).toHaveLength(0);
    expect(calls).toHaveLength(0);
    expect([...UNCHECKED_BY_DEFAULT]).toEqual([
      "sign", "signMessage", "signTypedData", "getClient", "exportWallet", "smartAccount", "ownerAccount",
      "getWallet", "gaslessERC20Transfer", "createTrade", "deployToken", "deployContract", "deployNFT", "getKernelAccount", "getIntentClient",
    ]);
    // Provider-specific escape hatches of the legacy CDP / ZeroDev providers, when present, are refused too.
    const legacy = Object.assign(new MockEvmWalletProvider(), {
      gaslessERC20Transfer: async () => "0xgasless",
      createTrade: async () => ({}),
      deployToken: async () => ({}),
      getWallet: () => ({}),
      getKernelAccount: () => ({}),
      getIntentClient: () => ({}),
    });
    const wl = guardWalletProvider(legacy, client, ctx);
    for (const m of ["gaslessERC20Transfer", "createTrade", "deployToken", "getWallet", "getKernelAccount", "getIntentClient"] as const) {
      expect(() => (wl as unknown as Record<string, () => unknown>)[m]!()).toThrow(GuardUncheckableError);
    }
    expect(wl.getAddress()).toBe(AGENT);
  });

  it("allowUnchecked opts a member back in (and only that member); unknown names are rejected", async () => {
    const p = new MockEvmWalletProvider();
    const { client } = clientWith(jsonResponse(200, checkBody("allow")));
    const w = guardWalletProvider(p, client, { ...ctx, allowUnchecked: ["signMessage"] });
    expect(await w.signMessage("sign in")).toBe("0xmsgsig");
    expect(() => w.sign("0x00")).toThrow(GuardUncheckableError);
    expect(() => guardWalletProvider(p, client, { ...ctx, allowUnchecked: ["sendTransaction" as never] })).toThrow(/not an unchecked-by-default member/);
  });

  it("toSigner(): the returned account signs transactions through the guard and cannot sign hashes or typed data", async () => {
    const p = new MockEvmWalletProvider();
    const { client, calls } = clientWith(jsonResponse(200, checkBody("block")));
    const w = guardWalletProvider(p, client, ctx);
    const account = w.toSigner();
    expect(account.address).toBe(AGENT);
    await expect(account.signTransaction(transfer)).rejects.toBeInstanceOf(GuardBlockedError);
    await expect(account.sign({ hash: "0x00" })).rejects.toBeInstanceOf(GuardUncheckableError);
    await expect(account.signTypedData({})).rejects.toBeInstanceOf(GuardUncheckableError);
    expect(posts(calls)).toHaveLength(1);
    expect(p.calls).toHaveLength(0);
  });
});

describe("guardWalletProvider: configuration", () => {
  it("rejects in-process approval options and malformed providers", () => {
    const { client } = clientWith(jsonResponse(200, checkBody("allow")));
    const p = new MockEvmWalletProvider();
    expect(() => guardWalletProvider(p, client, { ...ctx, approval: "callback", onEscalate: () => true } as never)).toThrow(/not supported/);
    expect(() => guardWalletProvider(p, client, { ...ctx, onEscalate: () => true } as never)).toThrow(/not supported/);
    expect(() => guardWalletProvider({} as never, client, ctx)).toThrow(/getAddress/);
    expect(() => guardWalletProvider(p, client, {} as never)).toThrow(/context/);
  });

  it("records every decision in the DecisionLog retrievable from the guarded provider", async () => {
    const p = new MockEvmWalletProvider();
    const { client } = clientWith(jsonResponse(200, checkBody("allow")), jsonResponse(200, checkBody("block")));
    const w = guardWalletProvider(p, client, { ...ctx, generateId: () => ID });
    await w.sendTransaction(transfer);
    await w.nativeTransfer(BOB, "7").catch(() => undefined);
    const log = getDecisionLog(w)!;
    expect(log.size).toBe(2);
    expect(log.last).toMatchObject({ method: "nativeTransfer", verdict: "block", intent: { to: BOB, value: 7n } });
    expect(log.all()[0]).toMatchObject({ method: "sendTransaction", verdict: "allow", intentId: ID });
    expect(getDecisionLog(p)).toBeUndefined();
  });
});
