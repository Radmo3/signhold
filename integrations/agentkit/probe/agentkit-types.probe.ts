/**
 * Compile-time probe against the real `@coinbase/agentkit` type definitions. Not part of
 * the normal build or CI (the package has no dependency on AgentKit); run it with
 * `@coinbase/agentkit` installed next to this package:
 *
 *   npm run typecheck:agentkit -w integrations/agentkit
 *
 * It proves that (1) every shipped EVM wallet provider satisfies the duck type
 * `guardWalletProvider` accepts, (2) the guarded provider is still an `EvmWalletProvider`
 * and can be handed to `AgentKit.from`, (3) `signholdActionProvider()` is accepted as an
 * `ActionProvider`, and (4) the list of guarded / refused members matches the abstract
 * class. Last verified against @coinbase/agentkit@0.10.4.
 */
import type { AgentKit, ActionProvider, CdpEvmWalletProvider, CdpSmartWalletProvider, EvmWalletProvider, LegacyCdpWalletProvider, LegacyCdpSmartWalletProvider, ViemWalletProvider, PrivyEvmWalletProvider, ZeroDevWalletProvider, WalletProvider } from "@coinbase/agentkit";
import type { SignholdClient } from "@signhold/sdk";
import { guardWalletProvider, signholdActionProvider, GUARDED_WALLET_METHODS, UNCHECKED_BY_DEFAULT, type EvmWalletProviderLike } from "../src/index.js";

declare const client: SignholdClient;
declare const cdp: CdpEvmWalletProvider;
declare const smart: CdpSmartWalletProvider;
declare const viem: ViemWalletProvider;
declare const privy: PrivyEvmWalletProvider;
declare const zerodev: ZeroDevWalletProvider;
declare const legacy: LegacyCdpWalletProvider;
declare const legacySmart: LegacyCdpSmartWalletProvider;
declare const abstractEvm: EvmWalletProvider;

// (1) Every EVM wallet provider AgentKit ships is accepted.
const guardedCdp = guardWalletProvider(cdp, client, { context: { agentId: "a" } });
const guardedSmart = guardWalletProvider(smart, client, { context: { agentId: "a" } });
const guardedViem = guardWalletProvider(viem, client, { context: { agentId: "a" }, waitForApproval: true });
const guardedPrivy = guardWalletProvider(privy, client, { context: { agentId: "a" } });
const guardedZeroDev = guardWalletProvider(zerodev, client, { context: { agentId: "a" } });
const guardedLegacy = guardWalletProvider(legacy, client, { context: { agentId: "a" } });
const guardedLegacySmart = guardWalletProvider(legacySmart, client, { context: { agentId: "a" } });
const guardedAbstract = guardWalletProvider(abstractEvm, client, { context: { agentId: "a" } });
const asLike: EvmWalletProviderLike = abstractEvm;

// (2) The result is still an EvmWalletProvider / WalletProvider and goes where AgentKit expects one.
const stillEvm: EvmWalletProvider[] = [guardedCdp, guardedSmart, guardedViem, guardedPrivy, guardedZeroDev, guardedLegacy, guardedLegacySmart, guardedAbstract];
const stillWallet: WalletProvider = guardedCdp;
declare function from(opts: Parameters<typeof AgentKit.from>[0]): ReturnType<typeof AgentKit.from>;
void from({ walletProvider: guardedCdp, actionProviders: [signholdActionProvider({ client, wallet: guardedCdp })] });

// (3) The action provider satisfies the abstract class structurally.
const ap: ActionProvider = signholdActionProvider({ client });
const apTyped: ActionProvider<WalletProvider> = signholdActionProvider({ client });

// (4) Guarded / refused members exist on the abstract class (or the CDP providers) with the expected shapes.
type Guarded = (typeof GUARDED_WALLET_METHODS)[number];
const guardedKeys: Record<Guarded, keyof EvmWalletProvider> = { sendTransaction: "sendTransaction", signTransaction: "signTransaction", nativeTransfer: "nativeTransfer" };
type Refused = (typeof UNCHECKED_BY_DEFAULT)[number];
type AnyProviderKey = keyof EvmWalletProvider | keyof CdpEvmWalletProvider | keyof CdpSmartWalletProvider | keyof LegacyCdpWalletProvider | keyof LegacyCdpSmartWalletProvider | keyof ZeroDevWalletProvider;
const refusedKeys: Record<Refused, AnyProviderKey> = {
  sign: "sign", signMessage: "signMessage", signTypedData: "signTypedData", getClient: "getClient", exportWallet: "exportWallet", smartAccount: "smartAccount", ownerAccount: "ownerAccount",
  getWallet: "getWallet", gaslessERC20Transfer: "gaslessERC20Transfer", createTrade: "createTrade", deployToken: "deployToken", deployContract: "deployContract", deployNFT: "deployNFT",
  getKernelAccount: "getKernelAccount", getIntentClient: "getIntentClient",
};
// The transaction methods take viem's TransactionRequest; our mapper reads a structural subset of it.
type SendArg = Parameters<EvmWalletProvider["sendTransaction"]>[0];
const argCheck: SendArg = { to: "0x0000000000000000000000000000000000000000", value: 0n, data: "0x" };

void [stillEvm, stillWallet, ap, apTyped, guardedKeys, refusedKeys, argCheck, asLike];
