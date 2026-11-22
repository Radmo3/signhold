import { vi } from "vitest";
import type { Decision } from "@signhold/core";
import { SignholdClient, type FetchLike } from "@signhold/sdk";
import type { EvmWalletProviderLike, NetworkLike, TransactionRequestLike } from "../src/types.js";

export const AGENT = "0x1111111111111111111111111111111111111111";
export const BOB = "0x2222222222222222222222222222222222222222";
export const USDC = "0x3333333333333333333333333333333333333333";
export const CHALLENGE = "a".repeat(64);

export function decisionJson(verdict: Decision["verdict"], intentId = "00000000-0000-4000-8000-000000000001") {
  return {
    intentId,
    verdict,
    findings: verdict === "allow" ? [] : [{ ruleId: verdict === "block" ? "no-unlimited-approvals" : "new-contracts", kind: "custom", verdict, message: `rule fired: ${verdict}` }],
    riskScore: verdict === "allow" ? 2 : verdict === "block" ? 95 : 60,
    explanation: `explanation for ${verdict}`,
    simulation: { ok: true, deltas: [], approvals: [], contractsTouched: [], newContracts: [], gasEstimate: "21000", warnings: [] },
    policyId: "p",
    policyVersion: 1,
    evaluatedAt: "2026-01-01T00:00:00.000Z",
  };
}

export function checkBody(verdict: Decision["verdict"], auditId = `00000000-0000-4000-8000-00000000aud${verdict === "allow" ? "a" : verdict === "block" ? "b" : "e"}`) {
  const body: Record<string, unknown> = { decision: decisionJson(verdict), auditId };
  if (verdict === "escalate") body.approval = { challenge: CHALLENGE, expiresAt: "2026-01-01T00:15:00.000Z" };
  return body;
}

export function jsonResponse(status: number, body: unknown): () => Response {
  return () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

export function mockFetch(...responses: Array<Response | Error | (() => Response | Error | Promise<Response>)>) {
  let i = 0;
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fn = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const next = responses[Math.min(i++, responses.length - 1)];
    const v = typeof next === "function" ? await next() : next;
    if (v instanceof Error) throw v;
    return v;
  }) as unknown as FetchLike;
  return { fetch: fn, calls };
}

export function clientWith(...responses: Parameters<typeof mockFetch>) {
  const { fetch, calls } = mockFetch(...responses);
  return { client: new SignholdClient({ baseUrl: "http://gw", apiKey: "k", fetch, retries: 0 }), calls };
}

export const posts = (calls: Array<{ url: string; init: RequestInit }>) => calls.filter((c) => c.init.method === "POST");

/**
 * A wallet provider in the exact shape of AgentKit's `EvmWalletProvider` (0.10.4), with
 * WeakMap-style `#private` state like the compiled CDP providers, plus the escape hatches
 * of `CdpEvmWalletProvider` / `CdpSmartWalletProvider` (`getClient`, `exportWallet`,
 * `smartAccount`, `ownerAccount`) so the tests can prove they are refused.
 */
export class MockEvmWalletProvider implements EvmWalletProviderLike {
  #address: string;
  #network: NetworkLike;
  readonly calls: Array<{ method: string; args: unknown[] }> = [];
  smartAccount = { sendUserOperation: vi.fn(async () => "0xuserop") };
  ownerAccount = { address: AGENT, type: "local", signTransaction: vi.fn(async () => "0xowner") };

  constructor(network: NetworkLike = { protocolFamily: "evm", networkId: "base-mainnet", chainId: "8453" }, address = AGENT) {
    this.#address = address;
    this.#network = network;
  }
  private rec(method: string, args: unknown[]) {
    this.calls.push({ method, args });
  }
  getAddress() {
    return this.#address;
  }
  getNetwork() {
    return this.#network;
  }
  getName() {
    return "mock_evm_wallet_provider";
  }
  async getBalance() {
    return 10n ** 18n;
  }
  async nativeTransfer(to: string, value: string) {
    this.rec("nativeTransfer", [to, value]);
    // Like ViemWalletProvider: re-enters this.sendTransaction (must not be double-checked).
    return this.sendTransaction({ to, value: BigInt(value) });
  }
  async sendTransaction(tx: TransactionRequestLike) {
    this.rec("sendTransaction", [tx]);
    return "0xhash";
  }
  async signTransaction(tx: TransactionRequestLike) {
    this.rec("signTransaction", [tx]);
    return "0xsignedtx";
  }
  async sign(hash: string) {
    this.rec("sign", [hash]);
    return "0xrawsig";
  }
  async signMessage(message: string | Uint8Array) {
    this.rec("signMessage", [message]);
    return "0xmsgsig";
  }
  async signTypedData(typedData: unknown) {
    this.rec("signTypedData", [typedData]);
    return "0xtypedsig";
  }
  /** Mirrors EvmWalletProvider.toSigner(): closures over `this`. */
  toSigner() {
    return {
      address: this.getAddress(),
      sign: async ({ hash }: { hash: string }) => this.sign(hash),
      signMessage: async ({ message }: { message: string }) => this.signMessage(message),
      signTransaction: async (tx: TransactionRequestLike) => this.signTransaction(tx),
      signTypedData: async (td: unknown) => this.signTypedData(td),
    };
  }
  async waitForTransactionReceipt(txHash: string) {
    this.rec("waitForTransactionReceipt", [txHash]);
    return { status: "success", transactionHash: txHash };
  }
  async readContract(params: unknown) {
    this.rec("readContract", [params]);
    return 6;
  }
  getPublicClient() {
    return { chain: { id: 8453 } };
  }
  getClient() {
    return { evm: { sendTransaction: vi.fn(async () => "0xbypass") } };
  }
  async exportWallet() {
    return { name: "w", address: this.#address };
  }
}
