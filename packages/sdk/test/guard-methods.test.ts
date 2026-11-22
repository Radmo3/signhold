import { describe, expect, it, vi } from "vitest";
import { SignholdClient, GuardBlockedError, GuardUncheckableError, guard } from "../src/index.js";
import { decisionJson, jsonResponse, mockFetch } from "./helpers.js";

/**
 * `GuardOptions.methods`, `deny` and `bindPassthrough`: the hooks `@signhold/agentkit` needs
 * to guard a wallet provider whose transaction methods are not just signTransaction /
 * sendTransaction, whose raw-hash / typed-data signing cannot be checked, and whose class
 * keeps `#private` state that a Proxy `this` cannot read.
 */

interface Tx { to: string; value: bigint }
const toIntent = (tx: Tx) => ({ chain: "evm" as const, chainId: 1, from: "0x1111111111111111111111111111111111111111", to: tx.to, value: tx.value });
const tx: Tx = { to: "0x2222222222222222222222222222222222222222", value: 1n };

function clientWith(verdict: "allow" | "block" | "escalate") {
  const { fetch, calls } = mockFetch(jsonResponse(200, { decision: decisionJson(verdict), auditId: `aud-${verdict}` }));
  return { client: new SignholdClient({ baseUrl: "http://gw", fetch, retries: 0 }), calls };
}

/** A provider in the shape of an AgentKit EvmWalletProvider, with a WeakMap-backed private field like the compiled CDP providers. */
class PrivateProvider {
  #address = "0x1111111111111111111111111111111111111111";
  sendTransaction = vi.fn(async (_t: Tx) => "0xhash");
  signTransaction = vi.fn(async (_t: Tx) => "0xsigned");
  nativeTransfer = vi.fn(async (_to: string, _value: string) => "0xnative");
  sign = vi.fn(async (_hash: string) => "0xrawsig");
  signTypedData = vi.fn(async (_d: unknown) => "0xtyped");
  getAddress() {
    return this.#address; // throws TypeError when `this` is a Proxy
  }
  getNetwork() {
    return { protocolFamily: "evm", chainId: "1" };
  }
  /** Mirrors EvmWalletProvider.toSigner(): a signer whose methods call back into `this`. */
  toSigner() {
    return { signTransaction: (t: Tx) => this.signTransaction(t) };
  }
}

describe("guard() methods / deny / bindPassthrough", () => {
  it("guards the listed methods with per-method mappers and leaves the default pair unguarded when not listed", async () => {
    const p = new PrivateProvider();
    const { client, calls } = clientWith("allow");
    const g = guard(p, client, {
      toIntent,
      methods: [
        "sendTransaction",
        { name: "nativeTransfer", toIntent: (to: string, value: string) => ({ chain: "evm" as const, chainId: 1, from: "0x1111111111111111111111111111111111111111", to, value: BigInt(value), data: "0x" as const }) },
      ],
      context: { agentId: "a" },
      generateId: () => "00000000-0000-4000-8000-000000000001",
    });
    expect(await g.nativeTransfer("0x3333333333333333333333333333333333333333", "5")).toBe("0xnative");
    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0].init.body as string);
    expect(body.intent).toMatchObject({ to: "0x3333333333333333333333333333333333333333", value: "5", data: "0x" });
    expect(await g.sendTransaction(tx)).toBe("0xhash");
    expect(calls).toHaveLength(2);
    // signTransaction was not listed, so it is a plain pass-through here.
    expect(await g.signTransaction(tx)).toBe("0xsigned");
    expect(calls).toHaveLength(2);
  });

  it("a listed method the signer lacks is simply absent (no synthetic method is created)", () => {
    const s = { sendTransaction: vi.fn(async () => "h") };
    const { client } = clientWith("allow");
    const g = guard(s, client, { toIntent, methods: ["sendTransaction", "nativeTransfer"], context: { agentId: "a" } });
    expect((g as { nativeTransfer?: unknown }).nativeTransfer).toBeUndefined();
  });

  it("block / escalate on a custom method never reach the signer", async () => {
    for (const verdict of ["block", "escalate"] as const) {
      const p = new PrivateProvider();
      const { client } = clientWith(verdict);
      const g = guard(p, client, { toIntent: (to: string, value: string) => ({ chain: "evm" as const, from: "0x1111111111111111111111111111111111111111", to, value: BigInt(value) }), methods: ["nativeTransfer"], context: { agentId: "a" } });
      const err = await g.nativeTransfer("0x2222222222222222222222222222222222222222", "1").catch((e) => e);
      expect(err.code).toBe(verdict === "block" ? "blocked" : "escalated");
      if (verdict === "block") expect(err).toBeInstanceOf(GuardBlockedError);
      expect(p.nativeTransfer).not.toHaveBeenCalled();
    }
  });

  it("denied methods throw GuardUncheckableError synchronously, before any network call, and never reach the signer", async () => {
    const p = new PrivateProvider();
    const { client, calls } = clientWith("allow");
    const g = guard(p, client, { toIntent, deny: ["sign", "signTypedData"], context: { agentId: "a" } });
    expect(() => g.sign("0xabcd")).toThrow(GuardUncheckableError);
    expect(() => g.signTypedData({})).toThrow(/signTypedData\(\) is refused/);
    try {
      g.sign("0xabcd");
    } catch (e) {
      expect((e as GuardUncheckableError).method).toBe("sign");
      expect((e as GuardUncheckableError).code).toBe("uncheckable");
    }
    expect(p.sign).not.toHaveBeenCalled();
    expect(p.signTypedData).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("a denied non-function property reads as undefined", () => {
    const s = { sendTransaction: vi.fn(async () => "h"), smartAccount: { secret: "x" } };
    const { client } = clientWith("allow");
    const g = guard(s, client, { toIntent, deny: ["smartAccount"], context: { agentId: "a" } });
    expect((g as { smartAccount?: unknown }).smartAccount).toBeUndefined();
    expect(s.smartAccount.secret).toBe("x"); // the inner object is untouched
  });

  it("refuses a method that is both guarded and denied", () => {
    const { client } = clientWith("allow");
    expect(() => guard(new PrivateProvider(), client, { toIntent, methods: ["sendTransaction"], deny: ["sendTransaction"], context: { agentId: "a" } })).toThrow(/both guarded and denied/);
  });

  it("mutating `methods` / `deny` after construction changes nothing (captured once)", async () => {
    const p = new PrivateProvider();
    const { client, calls } = clientWith("allow");
    const methods: string[] = ["sendTransaction"];
    const deny: string[] = ["sign"];
    const g = guard(p, client, { toIntent, methods, deny, context: { agentId: "a" } });
    methods.length = 0;
    deny.length = 0;
    await g.sendTransaction(tx);
    expect(calls).toHaveLength(1);
    expect(() => g.sign("0x00")).toThrow(GuardUncheckableError);
  });

  it("without bindPassthrough, a #private-field class breaks on pass-through calls (documents why the option exists)", () => {
    const { client } = clientWith("allow");
    const g = guard(new PrivateProvider(), client, { toIntent, context: { agentId: "a" } });
    expect(() => g.getAddress()).toThrow(TypeError);
  });

  it("with bindPassthrough, pass-through methods run on the inner instance and guarded ones are still checked", async () => {
    const p = new PrivateProvider();
    const { client, calls } = clientWith("allow");
    const g = guard(p, client, { toIntent, bindPassthrough: true, context: { agentId: "a" } });
    expect(g.getAddress()).toBe("0x1111111111111111111111111111111111111111");
    expect(g.getNetwork()).toEqual({ protocolFamily: "evm", chainId: "1" });
    expect(g.getAddress).toBe(g.getAddress); // bound functions are cached
    expect(await g.sendTransaction(tx)).toBe("0xhash");
    expect(calls).toHaveLength(1);
    expect(g.__signholdInner).toBe(p);
  });

  it("with bindPassthrough, a pass-through that re-enters `this.signTransaction` bypasses the check (so callers must wrap or deny it)", async () => {
    const p = new PrivateProvider();
    const { client, calls } = clientWith("block");
    const g = guard(p, client, { toIntent, bindPassthrough: true, context: { agentId: "a" } });
    // toSigner() is bound to the inner instance: its signTransaction is the unguarded one.
    expect(await g.toSigner().signTransaction(tx)).toBe("0xsigned");
    expect(calls).toHaveLength(0);
    // Denying it closes the hole.
    const g2 = guard(new PrivateProvider(), client, { toIntent, bindPassthrough: true, deny: ["toSigner"], context: { agentId: "a" } });
    expect(() => g2.toSigner()).toThrow(GuardUncheckableError);
  });

  it("without bindPassthrough, toSigner() re-enters through the proxy and is checked", async () => {
    const p = new PrivateProvider();
    const { client, calls } = clientWith("block");
    // getAddress() would throw on this class, but toSigner() does not touch the private field.
    const g = guard(p, client, { toIntent, context: { agentId: "a" } });
    await expect(g.toSigner().signTransaction(tx)).rejects.toBeInstanceOf(GuardBlockedError);
    expect(calls).toHaveLength(1);
    expect(p.signTransaction).not.toHaveBeenCalled();
  });

  it("the EscalationInfo.method reports the custom method name", async () => {
    const p = new PrivateProvider();
    const { client } = clientWith("allow");
    const onDecision = vi.fn();
    const g = guard(p, client, { toIntent: (to: string) => ({ chain: "evm" as const, from: "0x1111111111111111111111111111111111111111", to }), methods: ["nativeTransfer"], context: { agentId: "a" }, onDecision });
    await g.nativeTransfer("0x2222222222222222222222222222222222222222", "1");
    expect(onDecision.mock.calls[0][0]).toMatchObject({ method: "nativeTransfer" });
  });
});

describe("guard() reentrant", () => {
  it("a reentrant factory sees the proxy as `this` under bindPassthrough, so the signer it returns is guarded", async () => {
    const p = new PrivateProvider();
    const { client, calls } = clientWith("block");
    const g = guard(p, client, { toIntent, bindPassthrough: true, reentrant: ["toSigner"], deny: ["sign", "signTypedData"], context: { agentId: "a" } });
    const signer = g.toSigner();
    await expect(signer.signTransaction(tx)).rejects.toBeInstanceOf(GuardBlockedError);
    expect(calls).toHaveLength(1);
    expect(p.signTransaction).not.toHaveBeenCalled();
    expect(g.getAddress()).toBe("0x1111111111111111111111111111111111111111"); // other pass-throughs are still bound
  });

  it("rejects a reentrant name that is also guarded or denied", () => {
    const { client } = clientWith("allow");
    expect(() => guard(new PrivateProvider(), client, { toIntent, bindPassthrough: true, reentrant: ["sendTransaction"], context: { agentId: "a" } })).toThrow(/reentrant/);
    expect(() => guard(new PrivateProvider(), client, { toIntent, bindPassthrough: true, reentrant: ["sign"], deny: ["sign"], context: { agentId: "a" } })).toThrow(/reentrant/);
  });
});
