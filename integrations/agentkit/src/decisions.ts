import type { Decision, TransactionIntent } from "@signhold/core";
import type { EscalationInfo } from "@signhold/sdk";

/** One checked AgentKit call, as remembered for `signhold_explain_last_decision`. */
export interface DecisionRecord {
  at: string;
  /** Wallet-provider method that was checked. */
  method: string;
  intentId: string;
  auditId: string;
  verdict: Decision["verdict"];
  riskScore: number;
  explanation: string;
  findings: Array<{ ruleId: string; verdict: string; message: string }>;
  /** Present on `escalate` when the server has approver keys: the human's challenge and its expiry. */
  approval?: { challenge: string; expiresAt: string };
  intent: Pick<TransactionIntent, "chain" | "chainId" | "from" | "to" | "value" | "data" | "description">;
}

/**
 * Bounded, in-memory log of the decisions a guarded wallet provider received. It is read
 * by the action provider and written by `guardWalletProvider`'s `onDecision` hook. It
 * holds verdicts only: nothing in it can change an outcome.
 */
export class DecisionLog {
  private readonly items: DecisionRecord[] = [];
  constructor(private readonly capacity = 50) {
    if (!Number.isInteger(capacity) || capacity < 1) throw new TypeError("DecisionLog capacity must be a positive integer");
  }

  record(info: EscalationInfo): DecisionRecord {
    const { decision, intent } = info;
    const rec: DecisionRecord = {
      at: new Date().toISOString(),
      method: info.method,
      intentId: intent.id,
      auditId: info.auditId,
      verdict: decision.verdict,
      riskScore: decision.riskScore,
      explanation: decision.explanation,
      findings: decision.findings.map((f) => ({ ruleId: f.ruleId, verdict: f.verdict, message: f.message })),
      approval: info.approval ? { challenge: info.approval.challenge, expiresAt: info.approval.expiresAt } : undefined,
      intent: { chain: intent.chain, chainId: intent.chainId, from: intent.from, to: intent.to, value: intent.value, data: intent.data, description: intent.description },
    };
    this.items.push(rec);
    if (this.items.length > this.capacity) this.items.splice(0, this.items.length - this.capacity);
    return rec;
  }

  get last(): DecisionRecord | undefined {
    return this.items.at(-1);
  }

  byAuditId(auditId: string): DecisionRecord | undefined {
    return this.items.find((r) => r.auditId === auditId);
  }

  get size(): number {
    return this.items.length;
  }

  all(): readonly DecisionRecord[] {
    return [...this.items];
  }
}
