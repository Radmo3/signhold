import { describe, expect, it } from "vitest";
import { SIGNHOLD_ACTION_NAMES, SignholdActionProvider, guardWalletProvider, signholdActionProvider } from "../src/index.js";
import { BOB, MockEvmWalletProvider, USDC, checkBody, clientWith, jsonResponse, posts } from "./helpers.js";

const AUDIT = "00000000-0000-4000-8000-00000000aaaa";

/** A wallet provider that explodes on any access: proves the actions never touch the wallet. */
const explosiveWallet = new Proxy({}, { get: (_t, prop) => { throw new Error(`wallet member '${String(prop)}' accessed`); } });

describe("signholdActionProvider", () => {
  it("has the AgentKit action-provider shape and exactly two read-only actions", () => {
    const { client } = clientWith(jsonResponse(200, {}));
    const ap = signholdActionProvider({ client });
    expect(ap).toBeInstanceOf(SignholdActionProvider);
    expect(ap.name).toBe("signhold");
    expect(ap.actionProviders).toEqual([]);
    expect(ap.supportsNetwork({ protocolFamily: "evm", chainId: "8453" })).toBe(true);
    expect(ap.supportsNetwork({ protocolFamily: "svm" })).toBe(true);
    const actions = ap.getActions(explosiveWallet);
    expect(actions.map((a) => a.name)).toEqual([...SIGNHOLD_ACTION_NAMES]);
    for (const a of actions) {
      expect(typeof a.description).toBe("string");
      expect(typeof a.invoke).toBe("function");
      expect(a.schema).toBeDefined();
      expect(a.name.replace(/^signhold_/, "")).not.toMatch(/approv|sign|send|submit|grant/);
    }
  });

  it("has no approval surface: no action can POST, every invocation only reads, and hostile arguments are ignored", async () => {
    const { client, calls } = clientWith(jsonResponse(200, { auditId: AUDIT, status: "pending", expiresAt: "2026-01-01T00:15:00.000Z" }));
    const ap = signholdActionProvider({ client });
    const [status, explain] = ap.getActions(explosiveWallet);
    for (const args of [{ auditId: AUDIT }, { auditId: AUDIT, approve: true, signature: "x", keyId: "ops-phone" }]) {
      const out = JSON.parse(await status.invoke(args));
      expect(out).toMatchObject({ auditId: AUDIT, status: "pending" });
    }
    await explain.invoke({ approve: true });
    expect(posts(calls)).toHaveLength(0);
    for (const c of calls) {
      expect(c.init.method).toBe("GET");
      expect(c.url).toBe(`http://gw/v1/approvals/${AUDIT}`);
    }
    // Nothing on the provider's own surface mentions an approval operation.
    const members = Object.getOwnPropertyNames(Object.getPrototypeOf(ap)).concat(Object.keys(ap));
    expect(members.filter((m) => /approve|submit|sign(?!hold)/i.test(m))).toEqual([]);
  });

  it("signhold_check_status: validates the audit id and reports lookup failures as data, never throwing", async () => {
    const { client, calls } = clientWith(new Error("ECONNREFUSED"));
    const [status] = signholdActionProvider({ client }).getActions(explosiveWallet);
    expect(JSON.parse(await status.invoke({ auditId: "not-a-uuid" }))).toMatchObject({ error: "invalid_arguments" });
    expect(JSON.parse(await status.invoke({}))).toMatchObject({ error: "invalid_arguments" });
    expect(calls).toHaveLength(0);
    expect(JSON.parse(await status.invoke({ auditId: AUDIT }))).toMatchObject({ error: "status_unavailable" });
    const { client: c2 } = clientWith(jsonResponse(200, { auditId: AUDIT, status: "approved", approvedBy: "ops-phone", approvalId: "ap", approvedAt: "t" }));
    expect(JSON.parse(await signholdActionProvider({ client: c2 }).getActions(explosiveWallet)[0].invoke({ auditId: AUDIT }))).toEqual({ auditId: AUDIT, status: "approved", approvedBy: "ops-phone", approvedAt: "t" });
    const { client: c3 } = clientWith(jsonResponse(200, { auditId: AUDIT, status: "approved" })); // malformed: approved without approver
    expect(JSON.parse(await signholdActionProvider({ client: c3 }).getActions(explosiveWallet)[0].invoke({ auditId: AUDIT }))).toMatchObject({ status: "approved" });
  });

  it("signhold_explain_last_decision: explains the guarded wallet's last verdict without the challenge", async () => {
    const p = new MockEvmWalletProvider();
    const { client } = clientWith(jsonResponse(200, checkBody("escalate")));
    const wallet = guardWalletProvider(p, client, { context: { agentId: "a" } });
    const ap = signholdActionProvider({ client, wallet });
    const [, explain] = ap.getActions(wallet);
    expect(JSON.parse(await explain.invoke({}))).toMatchObject({ error: "no_decisions" });
    await wallet.nativeTransfer(BOB, "5").catch(() => undefined);
    const out = JSON.parse(await explain.invoke({}));
    expect(out).toMatchObject({ method: "nativeTransfer", verdict: "escalate", riskScore: 60, findings: [{ ruleId: "new-contracts" }], transaction: { to: BOB, value: "5", from: p.getAddress() }, approval: { expiresAt: "2026-01-01T00:15:00.000Z" } });
    expect(JSON.stringify(out)).not.toContain("a".repeat(64));
    expect(out.auditId).toMatch(/aude$/);
  });

  it("without a wallet or log it reports that nothing was recorded; with an explicit log it reads that log", async () => {
    const p = new MockEvmWalletProvider();
    const { client } = clientWith(jsonResponse(200, checkBody("block")));
    const { DecisionLog } = await import("../src/index.js");
    const decisions = new DecisionLog(2);
    const wallet = guardWalletProvider(p, client, { context: { agentId: "a" }, decisions });
    for (let i = 0; i < 3; i++) await wallet.sendTransaction({ to: USDC, data: "0x" }).catch(() => undefined);
    expect(decisions.size).toBe(2);
    const [, explain] = signholdActionProvider({ client, decisions }).getActions(explosiveWallet);
    expect(JSON.parse(await explain.invoke({}))).toMatchObject({ verdict: "block", findings: [{ ruleId: "no-unlimited-approvals" }] });
    expect(JSON.parse(await signholdActionProvider({ client }).getActions(explosiveWallet)[1].invoke({}))).toMatchObject({ error: "no_decisions" });
  });
});
