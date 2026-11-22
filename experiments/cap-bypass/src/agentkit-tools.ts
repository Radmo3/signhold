/**
 * The `agentkit` framework: the same six tools as the reference framework, exposed the
 * way a Coinbase AgentKit action provider exposes them (`{ name, description, schema (zod),
 * invoke(args) => Promise<string> }`, grouped by an object with `name`, `supportsNetwork`,
 * `getActions(walletProvider)`), and an adapter that turns those actions back into the
 * `ToolApi` the agents consume. Every tool call in this framework therefore goes through an
 * AgentKit-shaped `Action`: zod validation of the arguments, a string result.
 *
 * `pay` is the equivalent of AgentKit's `erc20ActionProvider.transfer`: it ends in
 * `walletProvider.sendTransaction({ to: USDC, data: transfer(to, amount) })`. The wallet
 * policy gate (`Wallet.pay`: per-tx / daily caps, OTP raise) sits in front of it, exactly
 * as in the reference framework, because that gate models the wallet platform's own policy,
 * not the agent framework. In the `signhold` arm the wallet provider is the one returned by
 * `guardWalletProvider`, so the payment is checked by Signhold before the key is used.
 *
 * Types are structural: this file does not import `@coinbase/agentkit` (see
 * `integrations/agentkit/README.md`: the real package was not driven here, only its type
 * definitions were compiled against).
 */
import { z } from "zod";
import type { ActionLike, ActionProviderLike, EvmWalletProviderLike, NetworkLike } from "@signhold/agentkit";
import { TOOL_DEFINITIONS, TOOL_NAMES, type Inbox, type ToolApi, type ToolName, type Wallet } from "./env.js";

const schemas: Record<ToolName, z.ZodSchema> = {
  read_inbox: z.object({}),
  pay: z.object({
    to: z.string().describe("0x-prefixed recipient address"),
    amountUsdc: z.number().describe("Amount in USDC, e.g. 0.01"),
    memo: z.string().optional().describe("Short note for the payment record"),
  }),
  raise_cap: z.object({
    newCapUsdc: z.number().describe("New per-transaction and daily limit in USDC"),
    otp: z.string().optional().describe("One-time passcode from the verification e-mail"),
  }),
  get_balance: z.object({}),
  get_policy: z.object({}),
  done: z.object({ summary: z.string() }),
};

export const bigintSafe = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);

/**
 * AgentKit-shaped action provider over the simulated environment. `getActions` ignores the
 * wallet provider it is handed, as the real `AgentKit.getActions()` would hand it the same
 * provider the `Wallet`'s executor already uses; it is accepted for shape fidelity only.
 */
export class CapBypassActionProvider implements ActionProviderLike<EvmWalletProviderLike> {
  readonly name = "cap-bypass-env";
  readonly actionProviders: ActionProviderLike<EvmWalletProviderLike>[] = [];
  constructor(private readonly tools: ToolApi) {}

  supportsNetwork(network: NetworkLike): boolean {
    return network.protocolFamily === "evm";
  }

  getActions(_walletProvider?: EvmWalletProviderLike): ActionLike[] {
    return TOOL_DEFINITIONS.map((def) => ({
      name: def.name,
      description: def.description,
      schema: schemas[def.name],
      invoke: async (args: unknown): Promise<string> => {
        const parsed = schemas[def.name].safeParse(args ?? {});
        if (!parsed.success) return JSON.stringify({ error: "invalid_arguments", message: parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ") });
        const fn = this.tools[def.name] as (a?: unknown) => Promise<unknown>;
        return JSON.stringify((await fn(parsed.data)) ?? null, bigintSafe);
      },
    }));
  }
}

export function capBypassActionProvider(wallet: Wallet, inbox: Inbox, onDone: (summary: string) => void, makeToolApi: (w: Wallet, i: Inbox, d: (s: string) => void) => ToolApi): CapBypassActionProvider {
  return new CapBypassActionProvider(makeToolApi(wallet, inbox, onDone));
}

/**
 * Turn AgentKit actions back into the `ToolApi` the agents and the LLM adapters consume.
 * Each method invokes the action (string in, string out) and parses the JSON result, which
 * is what a LangChain / Vercel tool built by `getLangChainTools` / `getVercelAiTools` hands
 * the model. Unknown names are not exposed: the agent sees exactly the six tools.
 */
export function toolApiFromActions(actions: readonly ActionLike[]): ToolApi {
  const byName = new Map(actions.map((a) => [a.name, a] as const));
  for (const name of TOOL_NAMES) if (!byName.has(name)) throw new Error(`action provider is missing tool '${name}'`);
  const api = Object.fromEntries(
    TOOL_NAMES.map((name) => [
      name,
      async (args?: unknown) => {
        const raw = await byName.get(name)!.invoke(args ?? {});
        const parsed = JSON.parse(raw) as unknown;
        if (parsed && typeof parsed === "object" && "error" in parsed && (parsed as { error: unknown }).error === "invalid_arguments") {
          // Mirror the reference ToolApi, whose validation errors are `{ ok: false, error, message }` for pay / raise_cap-style tools.
          const p = parsed as unknown as { message: string };
          return name === "raise_cap" ? { status: "invalid_request", message: p.message } : { ok: false, error: "invalid_arguments", message: p.message };
        }
        return parsed;
      },
    ]),
  ) as unknown as ToolApi;
  return api;
}
