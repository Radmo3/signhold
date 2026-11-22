# @signhold/agentkit

Coinbase [AgentKit](https://github.com/coinbase/agentkit) integration for Signhold: a wrapper that puts Signhold's check in front of an AgentKit `EvmWalletProvider`, and a read-only action provider that lets the agent see what Signhold decided and whether a human has approved an escalation.

```
AgentKit action (erc20 transfer, swap, wow, morpho, ...)
   └─ walletProvider.sendTransaction({ to, data, value })
        └─ @signhold/agentkit  guardWalletProvider  ──POST /v1/check──▶  Signhold API (simulate + policy + audit)
             allow            ──▶ the real provider signs / broadcasts
             block            ──▶ GuardBlockedError, provider never called
             escalate         ──▶ GuardEscalatedError (auditId + challenge for a human), or, with waitForApproval,
                                  blocks until an approver device has signed and the server has verified it
             anything else    ──▶ throws, provider never called (fail closed)
```

Apache-2.0. Part of the [Signhold](../../README.md) monorepo.

## Install

```bash
npm install @signhold/agentkit @signhold/sdk @coinbase/agentkit
```

`@coinbase/agentkit` is an optional peer dependency (`>=0.10.4 <0.11.0`): this package imports nothing from it at runtime and wraps the provider duck-typed, so the tests run with a mock provider and no network. The shapes it relies on were taken from `@coinbase/agentkit@0.10.4` (see [What this was built against](#what-this-was-built-against)).

## Usage

```ts
import { AgentKit, CdpEvmWalletProvider, erc20ActionProvider, walletActionProvider } from "@coinbase/agentkit";
import { getLangChainTools } from "@coinbase/agentkit-langchain";
import { SignholdClient } from "@signhold/sdk";
import { guardWalletProvider, signholdActionProvider } from "@signhold/agentkit";

const client = new SignholdClient({ baseUrl: "https://signhold.internal", apiKey: process.env.SIGNHOLD_KEY, signRequests: true });
const wallet = guardWalletProvider(await CdpEvmWalletProvider.configureWithWallet({ apiKeyId, apiKeySecret, walletSecret, networkId: "base-mainnet" }), client, {
  context: { agentId: "ops-agent-1", windowSeconds: 3600 },
  waitForApproval: { timeoutMs: 10 * 60_000 },                       // block on escalate until a human device has signed
  onEscalationPending: ({ auditId, approval }) => page(auditId, approval?.challenge), // route to the human; cannot approve
});
const agentkit = await AgentKit.from({
  walletProvider: wallet,
  actionProviders: [walletActionProvider(), erc20ActionProvider(), signholdActionProvider({ client, wallet })],
});
const tools = await getLangChainTools(agentkit); // or getVercelAiTools(agentkit)
```

`guardWalletProvider(provider, client, options)` returns the same provider type (a `Proxy`; `wallet instanceof CdpEvmWalletProvider` still holds, `wallet.__signholdInner` is the original). Options:

| Option | Meaning |
| --- | --- |
| `context` | `AgentContext` (agent id, rolling spend, allow/deny lists) or a function of the intent. Required. |
| `waitForApproval` | `false` (default): `escalate` throws `GuardEscalatedError` with `auditId` and `challenge`. `true` / `{ timeoutMs, intervalMs }`: block, polling `GET /v1/approvals/:auditId`, until the server reports a verified approval; expiry, rejection or timeout throw and the provider is never called. |
| `onEscalationPending` | Called on `escalate` with the audit id and the challenge, to hand them to a human. Its return value cannot approve. A throw aborts the call. |
| `onDecision` | Observability for every verdict. A throw aborts the call. |
| `allowUnchecked` | Members from `UNCHECKED_BY_DEFAULT` that may run unchecked (see [What is covered](#what-is-and-is-not-covered)). Default none. |
| `describe` | Free text attached to each intent as the agent's stated purpose. |
| `decisions` | A `DecisionLog` to write to (default: a new one; `getDecisionLog(wallet)` returns it). |
| `checkOptions`, `generateId` | Forwarded to `@signhold/sdk`. |

There is no in-process approval callback and no option to enable one: the agent process is the thing that must not be able to approve, so approval is always the server-verified kind (an Ed25519 signature by a registered device over a challenge sealed into the audit record; see the root README, *Human approval (I-HITL)*).

## What is and is not covered

**Checked before they run** (`GUARDED_WALLET_METHODS`): every method of `EvmWalletProvider` that produces a signed or broadcast transaction, enumerated from `@coinbase/agentkit@0.10.4`'s `evmWalletProvider.d.ts` / `walletProvider.d.ts`:

| Method | Intent built | Used by (0.10.4 action providers) |
| --- | --- | --- |
| `sendTransaction(tx)` | `{ chain: "evm", chainId: getNetwork().chainId, from: getAddress(), to, value, data }` | erc20 (transfer, approve), weth, wow, zora, morpho, moonwell, compound, superfluid, across, enso, sushi, zeroX, flaunch, yelay, vaultsfyi, basename, erc721, baseAccount, the Permit2 approval of the CDP swap actions |
| `signTransaction(tx)` | same | the account from `toSigner()` (used by x402, clanker) when it signs a transaction |
| `nativeTransfer(to, value)` | `{ ..., to, value: BigInt(value), data: "0x" }` | wallet (`native_transfer`) |

`toSigner()` keeps working: the viem `LocalAccount` it returns is built so that its `signTransaction` goes through the guard and its `sign` / `signTypedData` are refused (the wrapper invokes `toSigner` with the guarded provider as `this`).

**Refused by default** (`UNCHECKED_BY_DEFAULT`; a call throws `GuardUncheckableError` before any network request, a data member reads as `undefined`), because what they produce cannot be expressed as a transaction intent or because they reach the key without passing the methods above:

| Member | Why | Where it matters |
| --- | --- | --- |
| `sign(hash)` | raw secp256k1 signature over an arbitrary hash, i.e. over any transaction hash | `toSigner()` consumers |
| `signTypedData(typedData)` | EIP-712: permits (ERC-2612, Permit2), x402 `transferWithAuthorization`, exchange orders are approvals or transfers expressed as signatures | x402 payments, zeroX, flaunch |
| `signMessage(message)` | EIP-191; some protocols accept it as an order signature | sign-in flows (none of the 0.10.4 action providers call it) |
| `getClient()` | the `CdpClient`: `client.evm.sendTransaction`, `account.swap`, `account.useSpendPermission` bypass the wrapper | CDP swap and spend-permission actions, faucet |
| `exportWallet()` | key / account export | CDP, Privy providers |
| `smartAccount`, `ownerAccount` | account objects that send user operations and sign | CdpSmartWalletProvider (also read by `get_wallet_details` for the owner address) |
| `getWallet()`, `gaslessERC20Transfer()`, `createTrade()`, `deployToken()`, `deployContract()`, `deployNFT()` | broadcast through the legacy CDP SDK without `sendTransaction` | LegacyCdpWalletProvider (the erc20 transfer action uses `gaslessERC20Transfer` for USDC/cbBTC/EURC on Base with that provider) |
| `getKernelAccount()`, `getIntentClient()` | send user operations / intents directly | ZeroDevWalletProvider |

Each of these can be re-enabled with `allowUnchecked: [...]`, which is a documented bypass of Signhold for whatever that member does; do it only for members the agent's tools need and whose risk is understood (`signMessage` for a sign-in flow is the typical case).

**Not covered at all**, and worth knowing:

- Transactions that never touch the wallet provider: anything an action provider does with its own credentials (the CDP API action provider, Twitter, Farcaster, ...), and anything the CDP platform executes server-side from a `CdpClient` the agent obtained elsewhere.
- EIP-7702 requests (`authorizationList` present) are refused rather than checked: a delegation of the account's code is not something Signhold simulates.
- Solana (`SvmWalletProvider`): not wrapped by this package. `@signhold/sdk`'s `guard()` can wrap a Solana signer directly with a `raw` intent.
- Code running in the agent process can reach the unwrapped provider: `wallet.__signholdInner` (the SDK's handle on the original, kept for tests and composition) and, of course, the original reference before it was wrapped. This wrapper raises the bar for an action provider that uses the documented interface; it is not a sandbox. The server-side controls (the operator's policy, the approver device) are what a compromised host cannot get around.
- The check is only as good as what the API can see: simulation runs against the RPC the API is configured with, the policy is the operator's, and an `escalate` can only be approved by a registered device.
- AgentKit 0.10.4 has no hook of its own between an action and the wallet provider: framework extensions (`@coinbase/agentkit-langchain@0.3.0` `getLangChainTools`, `@coinbase/agentkit-vercel-ai-sdk@0.1.0` `getVercelAiTools`) map each `Action` to a tool whose handler is `action.invoke(args)`, and `AgentKit.getActions()` hands the same wallet provider to every action provider. Wrapping the wallet provider is therefore the one place that covers every action at once, and the only one short of forking action providers.

## How escalations surface

To the **agent**: the guarded call rejects with `GuardEscalatedError` (`auditId`, `challenge`, `decision.explanation`), or, with `waitForApproval`, blocks and then either proceeds (the human signed) or rejects with `ApprovalDeniedError` / `ApprovalTimeoutError`. Action providers turn thrown errors into tool error strings, so the model sees the explanation and can call the read-only actions below. Nothing the model can call changes the outcome.

To the **human**: `onEscalationPending` receives the audit id and the challenge; forward them to the approver device (a phone, an HSM, `packages/api/scripts/approve.ts` on an ops laptop). The device fetches the sealed audit record, recomputes the challenge, shows the decoded transaction, signs with its own Ed25519 key and posts the signature to `POST /v1/approvals` with its own API key. The server verifies it; the SDK's poll then sees `approved`. The agent host holds no approver key and `@signhold/sdk` has no method that posts to that route.

### `signholdActionProvider({ client, wallet })`

Two actions, both read-only:

- `signhold_check_status({ auditId })`: `GET /v1/approvals/:auditId`, returns `{ auditId, status: pending | approved | expired | rejected | unknown, expiresAt?, approvedBy?, approvedAt? }`. The agent can learn that a human approved and retry; it cannot cause the approval.
- `signhold_explain_last_decision({})`: the last verdict the guarded wallet received (method, verdict, risk score, explanation, rule findings, the decoded transaction, the approval's expiry when escalated). Read from the `DecisionLog` the wrapper writes; the challenge itself is not included.

Why there is no approval action: an approval is a signature by a key the agent process does not have, submitted by the device that has it. Giving the agent an "approve" tool, or any in-process callback that returns `true`, would put the human back inside the agent's reach, which is the failure the I-HITL paper (arXiv:2610.35835) describes and the whole point of server-verified approval. The tests assert that no action name, description or invocation produces anything but `GET` requests, and that hostile arguments (`{ approve: true, signature: ... }`) are ignored.

## Comparison with CDP's own controls

Taken from Coinbase's documentation (fetched 21 Nov 2026); check the linked pages for the current state.

- **CDP Policy Engine** ([overview](https://docs.cdp.coinbase.com/wallets/security-and-policies/policy-engine/overview.md), [EVM policies](https://docs.cdp.coinbase.com/wallets/security-and-policies/policy-engine/evm-policies), [types](https://docs.cdp.coinbase.com/sdks/cdp-sdks-v2/typescript/policies/Types)): project- or account-scoped rules evaluated server-side by CDP before it signs for a CDP wallet. A rule is `{ action: "accept" | "reject", operation, criteria }` over operations such as `signEvmTransaction`, `sendEvmTransaction`, `signEvmHash`, `signEvmMessage`, `signEvmTypedData`, `prepareUserOperation`, `sendUserOperation` and the Solana equivalents, with criteria such as `ethValue`, `evmAddress`, `evmData` (ABI function + parameter conditions), `evmNetwork`, `netUSDChange` (mainnet only), `evmMessage`, `evmTypedDataField`, `evmTypedDataVerifyingContract`. A matching `reject` wins over `accept`; an operation with rules but no match is rejected; an operation with no rules is accepted. The two actions are accept and reject: the documentation describes no approval, escalation or human-in-the-loop action and no simulation of effects (`netUSDChange` is a value criterion). It applies to CDP wallets only.
- **Spend Permissions** ([CDP docs](https://docs.cdp.coinbase.com/server-wallets/v2/evm-features/spend-permissions)): an on-chain standing allowance granted by a smart account to a spender (token, allowance, period, start/end), enforced by the Spend Permission Manager contract on Base and other EVM networks. The owner signs once; the spender then calls `useSpendPermission` within the limits without a per-spend approval. It governs token spending from a smart account, not arbitrary transactions.
- **AgentKit itself** (0.10.4): no transaction policy and no approval hook in the core package or in the framework extensions.

Signhold is complementary rather than a replacement: it simulates the transaction and evaluates the effects (deltas, approvals, counterparties, new contracts, slippage, reputation, behaviour), produces a third verdict (`escalate`) whose resolution is a server-verified human signature, keeps a hash-chained signed audit trail, and works with any wallet provider, not only CDP's. CDP policies sit at the signer and cannot be bypassed by code on the agent host, which this wrapper, running on that host, can be (by using the escape hatches above, if allowed, or by not wrapping the provider); using both is reasonable, with CDP rejecting what should never be signed and Signhold deciding what needs a human.

## What this was built against

- `@coinbase/agentkit@0.10.4` (npm `latest` at the time of writing; released 2025-12-19), read from the published `dist/*.d.ts` and `dist/*.js`: `EvmWalletProvider` and `WalletProvider` (abstract methods, `toSigner()`), `CdpEvmWalletProvider`, `CdpSmartWalletProvider`, `LegacyCdpWalletProvider`, `LegacyCdpSmartWalletProvider`, `ViemWalletProvider`, `PrivyEvmDelegatedEmbeddedWalletProvider`, `ZeroDevWalletProvider`, `ActionProvider` / `Action` / `CreateAction`, `AgentKit.from` / `getActions`, and the action providers listed above. Observations that shaped the design: the compiled providers keep private state in WeakMaps (`#private`), so pass-through methods must run with the real instance as `this` (hence the `bindPassthrough` hook in `@signhold/sdk`); `ViemWalletProvider.nativeTransfer` calls `this.sendTransaction` internally (so the wrapper checks once, not twice); the CDP swap action approves Permit2 for `maxUint256` through `sendTransaction` before swapping through `getClient()` (the approval is checked and, under the default policy, blocked; the swap itself is an escape hatch).
- `@coinbase/agentkit-langchain@0.3.0` and `@coinbase/agentkit-vercel-ai-sdk@0.1.0` (npm `latest`): tool mapping only, no hooks.
- `@coinbase/cdp-sdk@1.62.0` was the current CDP SDK; it is not used here.
- Type compatibility is verified by compiling `probe/agentkit-types.probe.ts` against the installed package (`npm run typecheck:agentkit -w integrations/agentkit` with `@coinbase/agentkit` installed). It was run against 0.10.4 for this release; it is not part of CI because the package pulls ~1,000 transitive dependencies. **Live AgentKit was not exercised**: every test and the demo (`npm run demo:agentkit`) drive a mock `EvmWalletProvider` of the same shape against the in-process Signhold API.

## Tests

`npm test -w integrations/agentkit` (vitest, no network): allow / block / escalate / wait-for-approval paths for all three guarded methods, read-only members untouched, fail-closed on network errors, 4xx/5xx, malformed responses, throwing hooks and unmappable requests, every refused member and `allowUnchecked`, `toSigner()` re-entrancy, and the action provider's absence of any approval surface. The SDK hooks this package relies on (`methods`, `deny`, `bindPassthrough`, `reentrant`) are tested in `packages/sdk/test/guard-methods.test.ts`.
