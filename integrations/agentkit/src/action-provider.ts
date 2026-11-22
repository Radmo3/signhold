import { z } from "zod";
import type { SignholdClient } from "@signhold/sdk";
import { DecisionLog } from "./decisions.js";
import { getDecisionLog } from "./wallet.js";
import type { ActionLike, ActionProviderLike, NetworkLike } from "./types.js";

export const SIGNHOLD_ACTION_NAMES = ["signhold_check_status", "signhold_explain_last_decision"] as const;

export const CheckStatusSchema = z.object({
  auditId: z.string().uuid().describe("The audit id of an escalated transaction, as reported when it was escalated."),
});
export const ExplainLastDecisionSchema = z.object({});

export interface SignholdActionProviderOptions {
  client: SignholdClient;
  /** The guarded wallet provider (from `guardWalletProvider`) whose decisions to explain. */
  wallet?: object;
  /** Or the `DecisionLog` directly. Takes precedence over `wallet`. */
  decisions?: DecisionLog;
  /** Per-call timeout for the status lookup. Default: the client's. */
  timeoutMs?: number;
}

/**
 * Read-only AgentKit action provider for Signhold.
 *
 * Why there is no approve action: the agent process is the party that must not be able to
 * approve. An approval is an Ed25519 signature by a registered device over a challenge the
 * server sealed into the audit record, submitted to `POST /v1/approvals`; nothing in this
 * process holds such a key, and `@signhold/sdk` deliberately has no method that posts to
 * that route. These actions can only *observe*: `GET /v1/approvals/:auditId` reports the
 * state the device created, and the decision log is written by the wrapper's `onDecision`
 * hook. Reading either cannot change a verdict, create an approval or extend a challenge.
 */
export class SignholdActionProvider implements ActionProviderLike {
  readonly name = "signhold";
  readonly actionProviders: ActionProviderLike[] = [];
  private readonly client: SignholdClient;
  private readonly decisions: DecisionLog | undefined;
  private readonly timeoutMs: number | undefined;

  constructor(opts: SignholdActionProviderOptions) {
    if (!opts || typeof opts !== "object" || !opts.client) throw new TypeError("signholdActionProvider(): client is required");
    this.client = opts.client;
    this.decisions = opts.decisions ?? (opts.wallet ? getDecisionLog(opts.wallet) : undefined);
    this.timeoutMs = opts.timeoutMs;
  }

  supportsNetwork(_network: NetworkLike): boolean {
    return true;
  }

  /** The wallet provider is deliberately unused: these actions never sign or send. */
  getActions(_walletProvider?: unknown): ActionLike[] {
    return [
      {
        name: "signhold_check_status",
        description:
          "Check whether a transaction that Signhold escalated for human approval has been approved. Returns the server-side status " +
          "(pending | approved | expired | rejected | unknown). This only reads the status: approval happens on a separate device that you cannot reach. " +
          "If the status is approved, retry the original transaction once; a new check is needed and it may be approved again, or not.",
        schema: CheckStatusSchema,
        invoke: (args) => this.checkStatus(args as z.infer<typeof CheckStatusSchema>),
      },
      {
        name: "signhold_explain_last_decision",
        description:
          "Explain the most recent Signhold verdict (allow, block or escalate) on a transaction this wallet attempted: which policy rules fired, " +
          "the risk score and the audit id. Use it to understand why a transaction was refused or needs a human. It cannot change the verdict.",
        schema: ExplainLastDecisionSchema,
        invoke: () => this.explainLastDecision(),
      },
    ];
  }

  async checkStatus(args: z.infer<typeof CheckStatusSchema>): Promise<string> {
    const parsed = CheckStatusSchema.safeParse(args);
    if (!parsed.success) return JSON.stringify({ error: "invalid_arguments", message: "auditId must be a UUID" });
    try {
      const st = await this.client.getApprovalStatus(parsed.data.auditId, this.timeoutMs ? { timeoutMs: this.timeoutMs } : {});
      return JSON.stringify({ auditId: st.auditId, status: st.status, expiresAt: st.expiresAt, approvedBy: st.approvedBy, approvedAt: st.approvedAt });
    } catch (err) {
      return JSON.stringify({ error: "status_unavailable", message: safeMessage(err) });
    }
  }

  async explainLastDecision(): Promise<string> {
    const last = this.decisions?.last;
    if (!last) return JSON.stringify({ error: "no_decisions", message: "no Signhold decision has been recorded for this wallet yet" });
    return JSON.stringify(
      {
        at: last.at,
        method: last.method,
        auditId: last.auditId,
        verdict: last.verdict,
        riskScore: last.riskScore,
        explanation: last.explanation,
        findings: last.findings,
        transaction: last.intent,
        approval: last.approval
          ? { expiresAt: last.approval.expiresAt, howToProceed: "a registered approver device must sign the challenge; poll signhold_check_status with the auditId" }
          : undefined,
      },
      (_k, v) => (typeof v === "bigint" ? v.toString() : v),
    );
  }
}

export function signholdActionProvider(opts: SignholdActionProviderOptions): SignholdActionProvider {
  return new SignholdActionProvider(opts);
}

function safeMessage(err: unknown): string {
  const m = err instanceof Error ? err.message : String(err);
  return m.replace(/[\u0000-\u001f]/g, " ").slice(0, 300);
}
