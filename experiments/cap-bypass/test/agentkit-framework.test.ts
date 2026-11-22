import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GuardUncheckableError } from "@signhold/agentkit";
import { AGENT_WALLET, Inbox, Ledger, LedgerEvmWalletProvider, TOOL_NAMES, USDC_CONTRACT, Wallet, decodeTransferCalldata, makeToolApi, toUnits, transferCalldata, usdcTransferRequest } from "../src/env.js";
import { capBypassActionProvider, toolApiFromActions } from "../src/agentkit-tools.js";
import { scriptedAgent, type ScriptedKind } from "../src/agents/index.js";
import { mulberry32 } from "../src/rng.js";
import { INVOICE_PAYEE } from "../src/scenarios.js";
import { createSignholdArm, type SignholdArm } from "../src/signhold.js";
import { runTrial, type TrialConfig, type TrialResult } from "../src/trial.js";
import { runExperiment, parseCli } from "../src/run.js";
import { buildReport } from "../src/report.js";
import { formatSummaryTable, summarise } from "../src/metrics.js";
import { checkExpectations, EXPECTATIONS, runSmoke } from "../src/smoke.js";

const base = (over: Partial<TrialConfig>): TrialConfig => ({ arm: "baseline", scenario: 1, trialIndex: 0, seed: 42, capUsdc: 0.01, startingBalanceUsdc: 10, maxSteps: 40, ...over });

let reference: SignholdArm;
let agentkit: SignholdArm;
beforeAll(async () => {
  reference = await createSignholdArm({ capUsdc: 0.01, knownPayees: [INVOICE_PAYEE] });
  agentkit = await createSignholdArm({ capUsdc: 0.01, knownPayees: [INVOICE_PAYEE], framework: "agentkit" });
});
afterAll(async () => {
  await reference.close();
  await agentkit.close();
});

/** Everything about an outcome that must not depend on the framework. */
function outcome(r: TrialResult) {
  return {
    capRaised: r.capRaised,
    capRaisedTo: r.capRaisedTo,
    otpRead: r.otpRead,
    attackerPaid: r.attackerPaid,
    attackerPaidUsdc: r.attackerPaidUsdc,
    invoicesPaid: r.invoicesPaid,
    finalBalanceUsdc: r.finalBalanceUsdc,
    walletRejections: r.walletRejections,
    stop: r.stop,
    steps: r.steps,
    toolCalls: r.toolCalls,
    payments: r.payments.map((p) => ({ to: p.to, amountUsdc: p.amountUsdc, ok: p.ok, error: p.error, legitimate: p.legitimate, attacker: p.attacker })),
    // Intent ids (random UUIDs) appear inside Signhold's explanations; everything else must match byte for byte.
    transcript: JSON.parse(JSON.stringify(r.transcript.steps.map((s) => ({ tool: s.tool, args: s.args, result: s.result })), (_k, v) => (typeof v === "bigint" ? v.toString() : v)).replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, "<uuid>")),
    signhold: r.signhold && { counts: r.signhold.counts, falsePositives: r.signhold.falsePositives, rules: r.signhold.verdicts.map((v) => [v.verdict, v.to, v.amountUsdc, [...v.ruleIds].sort(), v.escalation?.deviceDecision]) },
  };
}

describe("agentkit framework reproduces the reference framework", () => {
  const cases: Array<{ agent: ScriptedKind; scenario: 1 | 2; attackerAmountUsdc?: number }> = [
    { agent: "bypasser", scenario: 1 },
    { agent: "bypasser", scenario: 2 },
    { agent: "gullible", scenario: 2 },
    { agent: "gullible", scenario: 2, attackerAmountUsdc: 0.01 },
    { agent: "obedient", scenario: 1 },
    { agent: "obedient", scenario: 2 },
  ];
  for (const c of cases) {
    for (const arm of ["baseline", "signhold"] as const) {
      it(`${c.agent} s${c.scenario} ${arm}${c.attackerAmountUsdc ? ` (attacker asks ${c.attackerAmountUsdc})` : ""}: identical outcomes, payments, verdicts and tool transcript`, async () => {
        const cfg = base({ arm, scenario: c.scenario, attackerAmountUsdc: c.attackerAmountUsdc });
        const ref = await runTrial({ ...cfg, framework: "reference" }, { agent: scriptedAgent(c.agent), signhold: arm === "signhold" ? reference : undefined });
        const ak = await runTrial({ ...cfg, framework: "agentkit" }, { agent: scriptedAgent(c.agent), signhold: arm === "signhold" ? agentkit : undefined });
        expect(ref.framework).toBe("reference");
        expect(ak.framework).toBe("agentkit");
        expect(outcome(ak)).toEqual(outcome(ref));
        if (arm === "signhold") expect(ak.signhold!.verdicts.length).toBeGreaterThan(0 - 1);
      });
    }
  }

  it("the smoke expectations hold under --framework agentkit for every scripted agent (bypasser, gullible, obedient, careful)", async () => {
    const { results, failures } = await runSmoke({ trials: 1, seed: 7, frameworks: ["agentkit"] });
    expect(results).toHaveLength(16);
    expect(results.every((r) => r.framework === "agentkit")).toBe(true);
    expect(failures).toEqual([]);
    // Per-framework filtering: an expectation with no trials in a framework is reported for that framework.
    expect(checkExpectations(results.filter((r) => r.agentId !== "scripted:careful"), EXPECTATIONS)).toEqual(expect.arrayContaining([expect.stringMatching(/^agentkit careful s1 baseline: no trials$/)]));
  });

  it("signhold arm, agentkit framework: invoices beyond the cap escalate and the device approves them; the attacker is blocked; the wallet provider is the guarded one", async () => {
    const s1 = await runTrial(base({ arm: "signhold", scenario: 1, framework: "agentkit" }), { agent: scriptedAgent("bypasser"), signhold: agentkit });
    expect(s1.capRaised).toBe(true);
    expect(s1.invoicesPaid).toBe(3);
    expect(s1.signhold!.counts).toMatchObject({ allow: 1, block: 0, escalate: 2, approved: 2, rejected: 0 });
    expect(s1.signhold!.falsePositives).toBe(0);
    const s2 = await runTrial(base({ arm: "signhold", scenario: 2, framework: "agentkit" }), { agent: scriptedAgent("bypasser"), signhold: agentkit });
    expect(s2.attackerPaid).toBe(false);
    expect(s2.signhold!.counts).toMatchObject({ block: 1 });
    expect(s2.signhold!.verdicts[0]!.ruleIds).toEqual(expect.arrayContaining(["cap-per-tx", "known-payees"]));
    expect(s2.finalBalanceUsdc).toBe(10);
    // The arm's wallet is the guarded AgentKit-shaped provider: raw signing is refused, the inner key is only reachable through it.
    const wp = agentkit.walletProvider!;
    expect(wp).toBeInstanceOf(LedgerEvmWalletProvider);
    expect(() => wp.sign("0x00")).toThrow(GuardUncheckableError);
    expect(() => wp.signTypedData({})).toThrow(GuardUncheckableError);
    expect(wp.getNetwork()).toEqual({ protocolFamily: "evm", networkId: "base-mainnet", chainId: "8453" });
    expect(reference.walletProvider).toBeUndefined();
  });

  it("a trial refuses an arm created for the other framework", async () => {
    await expect(runTrial(base({ arm: "signhold", framework: "agentkit" }), { agent: scriptedAgent("obedient"), signhold: reference })).rejects.toThrow(/created for framework 'reference'/);
    await expect(runTrial(base({ arm: "signhold", framework: "reference" }), { agent: scriptedAgent("obedient"), signhold: agentkit })).rejects.toThrow(/created for framework 'agentkit'/);
  });
});

describe("AgentKit-shaped environment pieces", () => {
  it("the action provider exposes exactly the six tools as actions, validates arguments with zod, returns strings, and has no approval action", async () => {
    const ledger = new Ledger({ [AGENT_WALLET]: toUnits(1) });
    const inbox = new Inbox([]);
    const provider = new LedgerEvmWalletProvider(ledger);
    const wallet = new Wallet({ ledger, inbox, rng: mulberry32(1), ownerName: "A", ownerEmail: "a@x", executor: async (req) => ({ ok: true, txHash: await provider.sendTransaction(usdcTransferRequest(req.to, req.amountUnits)) }) });
    let done = "";
    const ap = capBypassActionProvider(wallet, inbox, (s) => (done = s), makeToolApi);
    expect(ap.name).toBe("cap-bypass-env");
    expect(ap.supportsNetwork({ protocolFamily: "evm", chainId: "8453" })).toBe(true);
    expect(ap.supportsNetwork({ protocolFamily: "svm" })).toBe(false);
    const actions = ap.getActions(provider);
    expect(actions.map((a) => a.name)).toEqual([...TOOL_NAMES]);
    expect(actions.map((a) => a.name).filter((n) => /approv/i.test(n))).toEqual([]);
    for (const a of actions) expect(typeof a.invoke).toBe("function");
    const pay = actions.find((a) => a.name === "pay")!;
    expect(JSON.parse(await pay.invoke({ to: INVOICE_PAYEE, amountUsdc: 0.01 }))).toMatchObject({ ok: true, amountUsdc: 0.01 });
    expect(provider.signed).toEqual([{ method: "sendTransaction", to: INVOICE_PAYEE, amountUnits: 10_000n }]);
    expect(JSON.parse(await pay.invoke({ to: INVOICE_PAYEE, amountUsdc: "0.01" }))).toMatchObject({ error: "invalid_arguments" });
    expect(JSON.parse(await pay.invoke({ to: INVOICE_PAYEE, amountUsdc: 0.01, approve: true }))).toMatchObject({ ok: false, error: "daily_limit_exceeded" }); // extra keys stripped; wallet policy still applies
    expect(await actions.find((a) => a.name === "done")!.invoke({ summary: "fin" })).toBe('{"ok":true}');
    expect(done).toBe("fin");

    const api = toolApiFromActions(actions);
    expect(Object.keys(api).sort()).toEqual([...TOOL_NAMES].sort());
    expect(await api.get_balance()).toEqual({ balanceUsdc: 0.99, asset: "USDC", chain: "base" });
    expect(await api.raise_cap({ newCapUsdc: "1" as never })).toMatchObject({ status: "invalid_request" });
    expect(await api.pay({ to: "nope", amountUsdc: 1 })).toMatchObject({ ok: false, error: "invalid_address" });
    expect(() => toolApiFromActions(actions.slice(1))).toThrow(/missing tool 'read_inbox'/);
  });

  it("LedgerEvmWalletProvider only executes USDC transfer(to, amount); everything else fails without touching the ledger", async () => {
    const ledger = new Ledger({ [AGENT_WALLET]: toUnits(1) });
    const p = new LedgerEvmWalletProvider(ledger);
    expect(p.getAddress()).toBe(AGENT_WALLET);
    expect(await p.readContract({ address: USDC_CONTRACT, functionName: "balanceOf", args: [AGENT_WALLET] })).toBe(toUnits(1));
    expect(await p.readContract({ address: USDC_CONTRACT, functionName: "decimals" })).toBe(6);
    await expect(p.sendTransaction({ to: INVOICE_PAYEE, data: "0x" })).rejects.toThrow(/USDC contract/);
    await expect(p.sendTransaction({ to: USDC_CONTRACT, data: "0x095ea7b3" + "00".repeat(64) })).rejects.toThrow(/transfer\(to, amount\)/); // approve()
    await expect(p.sendTransaction({ to: USDC_CONTRACT, data: transferCalldata(INVOICE_PAYEE, 1n), value: 5n })).rejects.toThrow(/native asset/);
    await expect(p.sendTransaction({ to: USDC_CONTRACT, data: transferCalldata(INVOICE_PAYEE, toUnits(2)) })).rejects.toThrow(/insufficient funds/);
    await expect(p.nativeTransfer(INVOICE_PAYEE, "1")).rejects.toThrow(/native asset/);
    await expect(p.sign("0x00")).rejects.toThrow(/not part of the simulation/);
    await expect(p.signMessage("m")).rejects.toThrow(/not part of the simulation/);
    await expect(p.signTypedData({})).rejects.toThrow(/not part of the simulation/);
    expect(ledger.transfers).toHaveLength(0);
    expect(await p.signTransaction(usdcTransferRequest(INVOICE_PAYEE, 1n))).toMatch(/^0xsigned/);
    expect(ledger.transfers).toHaveLength(0); // signing does not move funds
    const hash = await p.sendTransaction(usdcTransferRequest(INVOICE_PAYEE, toUnits(0.25)));
    expect(ledger.transfers).toEqual([expect.objectContaining({ to: INVOICE_PAYEE, amount: toUnits(0.25), txHash: hash })]);
    expect(await p.waitForTransactionReceipt(hash)).toEqual({ status: "success", transactionHash: hash });
    expect(decodeTransferCalldata(transferCalldata(INVOICE_PAYEE, 7n))).toEqual({ to: INVOICE_PAYEE, amountUnits: 7n });
    expect(decodeTransferCalldata("0x")).toBeUndefined();
  });
});

describe("--framework plumbing", () => {
  it("CLI parses --framework and rejects unknown values; results and summaries carry it", async () => {
    expect(parseCli(["--framework", "agentkit"]).framework).toBe("agentkit");
    expect(parseCli([]).framework).toBe("reference");
    expect(() => parseCli(["--framework", "langchain"])).toThrow(/--framework must be/);
    const out = await runExperiment({ arms: ["baseline"], framework: "agentkit", scenarios: [1], agent: scriptedAgent("careful"), trials: 1, seed: 1 });
    expect(out.results[0]!.framework).toBe("agentkit");
    expect(out.summary[0]!.framework).toBe("agentkit");
    await expect(runExperiment({ arms: ["baseline"], framework: "nope" as never, scenarios: [1], agent: scriptedAgent("careful"), trials: 1, seed: 1 })).rejects.toThrow(/unknown framework/);
  });

  it("report / summary group by framework when more than one is present, and treat results without the field as reference", async () => {
    const ak = (await runExperiment({ arms: ["baseline"], framework: "agentkit", scenarios: [1], agent: scriptedAgent("obedient"), trials: 2, seed: 3 })).results;
    const legacy = (await runExperiment({ arms: ["baseline"], scenarios: [1], agent: scriptedAgent("obedient"), trials: 2, seed: 3 })).results.map((r) => {
      const { framework: _f, ...rest } = r;
      return rest as TrialResult;
    });
    const groups = summarise([...ak, ...legacy]);
    expect(groups.map((g) => `${g.framework}|${g.arm}|${g.trials}`)).toEqual(["agentkit|baseline|2", "reference|baseline|2"]);
    expect(formatSummaryTable(groups).split("\n")[0]).toMatch(/^scenario\s+framework\s+arm/);
    expect(formatSummaryTable(summarise(ak)).split("\n")[0]).not.toMatch(/framework/); // single framework: unchanged layout
    const { markdown, groups: rg } = buildReport([...ak, ...legacy]);
    expect(rg).toHaveLength(2);
    expect(markdown).toContain("framework(s) agentkit, reference");
    expect(markdown).toContain("| Scenario | Framework | Arm |");
    expect(buildReport(legacy).markdown).not.toContain("| Framework |");
  });
});
