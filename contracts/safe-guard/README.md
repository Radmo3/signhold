# @signhold/safe-guard

A [Safe](https://docs.safe.global/smart-account-guards) (Gnosis Safe) **transaction guard** that moves Signhold's enforcement on-chain. A Safe with `SignholdGuard` set cannot execute a transaction unless

1. the Signhold service has signed an attestation of its verdict for **that exact Safe transaction hash**, and
2. when the verdict is `escalate` (or the transaction touches the Safe's own configuration or the guard), a registered human **approver device** has signed it too.

`block` verdicts are never attested, so for the guard their absence is what blocks them. Three keys, three holders, and an escalated payment needs all three:

| Key | Holder | Signs |
| --- | --- | --- |
| Safe owner key(s) | agent host | the Safe transaction (as before) |
| attestor key (secp256k1) | Signhold host (`SIGNHOLD_ATTESTOR_KEY`) | EIP-712 `Attestation{safe, safeTxHash, verdict, expiresAt, auditId}` |
| approver key (secp256k1, or P-256 via RIP-7212) | the human's device | EIP-712 `Approval{safe, safeTxHash, auditId, approvedAt}` |

This closes the "agent-side bypass" residual of the SDK-only design (docs/THREAT_MODEL.md, residual 1): with the SDK, a compromised agent process can call its signer directly; with the guard, the signer's signature is necessary but no longer sufficient. It also removes the "service-side verification trusts the service" residual for escalations: a compromised Signhold host can attest, but it cannot approve, because the guard verifies the device's signature itself.

Apache-2.0. Part of the [Signhold](../../README.md) monorepo. **Unaudited** (see [Audit status](#audit-status)).

```
                 agent host                      Signhold host                      approver device
                 (owner key, API key)            (attestor key, audit key)          (approver key)
                        │                                │                                 │
  1. POST /v1/check ────┼───────────────────────────────►│ simulate + policy -> allow|block|escalate
  2. POST /v1/attestations {auditId, safe, guard, safeTx}│ verify safeTx == audited intent; sign
     ◄──────────────────┼─────── Attestation signature ──┤ (never for block)                │
  3. guard.submitAttestation(hash, verdict, exp, id, sig)│                                 │
  4. (escalate) hand auditId + safeTx to the human ──────┼────────────────────────────────►│ fetch record, recompute hash,
                        │                                │   POST /v1/approvals (eip712)   │ display, confirm, sign Approval
                        │  guard.submitApproval(hash, auditId, approver, approvedAt, sig) ◄┤ (anyone may relay)
  5. Safe.execTransaction(...) ─► checkTransaction: hash == attested? unexpired? escalate/sensitive => approval present, unused? => consume
                                  checkAfterExecution: clear entries
```

## Contract surface (`contracts/SignholdGuard.sol`)

Solidity 0.8.28, OpenZeppelin 5.6.1 (`ECDSA`, `EIP712`, `P256.isValidPublicKey`, `IERC165`). Implements Safe's `ITransactionGuard` (interface id `0xe6d7a83a`, identical in safe-contracts 1.4.1 and safe-smart-account 1.5.0).

**Configuration** (set in the constructor; changeable only by the Safe itself, i.e. through a Safe transaction that passes this guard with a device approval):

- `safe` (immutable): the one Safe this guard serves. Hooks called by any other address revert `OnlySafe`.
- `attestor`: the service's secp256k1 address. `setAttestor` refuses the Safe and any registered approver.
- `approvers[address]`: secp256k1 approver devices. `setApprover` refuses the attestor and the Safe.
- `p256Approvers[keccak256(abi.encode(qx, qy))]` and `p256Enabled`: P-256 devices, verified **only** through the RIP-7212 precompile at `0x100`. Enabling P-256 probes the precompile with a known-valid vector and reverts `P256PrecompileUnavailable` where it is absent; there is no Solidity fallback.
- `approvalWindow` (seconds, default 900): how long an approval is valid after its `approvedAt`; device clocks may run at most 5 minutes ahead (`MAX_CLOCK_SKEW`).
- `attestationTtl` (seconds, default 3600): the furthest `expiresAt` accepted when an attestation is submitted.
- `paused`: nothing executes except guard administration and guard removal (both still need a device), so a pause can always be lifted.

**Submissions** (anyone may relay; authority comes from the signatures):

- `submitAttestation(safeTxHash, verdict, expiresAt, auditId, attestorSig)`: `verdict` is 1 (allow) or 2 (escalate); `expiresAt` must be in the future and within `attestationTtl`; `auditId` is non-zero and not the recovery sentinel; the signature must recover to `attestor` over this guard's EIP-712 domain. A re-attestation of the same hash may only tighten: allow → escalate is accepted, escalate → allow reverts `AttestationDowngrade`.
- `submitApproval(safeTxHash, auditId, approver, approvedAt, sig)` / `submitApprovalP256(safeTxHash, auditId, qx, qy, approvedAt, r, s)`: `auditId` must be the id of an unexpired attestation already stored for the hash (or `RECOVERY_AUDIT_ID`, below); `approvedAt` must be within the window; the signer must be registered; an unused, unexpired approval cannot be replaced (`ApprovalAlreadySubmitted`). P-256 signatures must have low `s`.

**Safe hooks**:

- `checkTransaction(...)`: recomputes the hash with `ISafe(safe).getTransactionHash(..., nonce() - 1)`. The Safe increments `nonce` *before* it calls the guard (`nonce++` precedes `checkTransaction` in `Safe.execTransaction`, 1.3.0 through 1.5.0), which is why `nonce() - 1` is the nonce of the transaction being checked, exactly as Safe's own `DebugTransactionGuard` does. Then: attestation present and unexpired, else `NotAttested` / `AttestationExpired`; if the verdict is escalate **or the transaction is sensitive** (below), an approval bound to the attestation's `auditId` must be present and unexpired, else `ApprovalRequired` / `ApprovalMismatch` / `ApprovalExpired`; the approval is deleted before execution (single use). The accepted hash is parked in `_executing`, which doubles as a reentrancy lock (a nested `execTransaction` reverts `Reentrancy`).
- `checkAfterExecution(hash, success)`: must see the parked hash (`UnexpectedAfterExecution` otherwise), clears it and deletes the attestation and approval entries.
- `supportsInterface`: `ITransactionGuard` and `IERC165`. There is deliberately **no permissive fallback**: a future Safe version calling a hook this guard does not implement reverts rather than passing.

**Sensitive transactions** always need a device approval, whatever the attested verdict. The choice is the stricter of the two the task allowed (attestation-only vs. attestation + approval) for guard administration, and is extended to everything that can change who controls the Safe:

- `to == guard` (`setAttestor`, `setApprover`, `setP256Approver`, `setP256Enabled`, `setApprovalWindow`, `setAttestationTtl`, `setPaused`), so an attestation alone can never re-key, disable or pause the guard;
- `to == safe` (`setGuard`, `enableModule`, `addOwnerWithThreshold`, `swapOwner`, `changeThreshold`, `setFallbackHandler`, `setModuleGuard`, ...);
- `operation == DelegateCall`, because a delegatecall can `sstore` the guard storage slot directly without ever calling `setGuard`;
- `gasPrice != 0`, because a gas refund (`gasToken` → `refundReceiver`) moves funds the service never simulated. The service refuses to attest these and delegatecalls in the first place (`unsupported_safe_tx`), so this is belt and braces.

**Owner escape hatch.** Owners can always remove the guard with an approved transaction: `setGuard(address(0))` is a self-call, so it needs an attestation plus a device approval like any other. If the Signhold service is down or its attestor key is lost, exactly one transaction is accepted **without** an attestation: `setGuard(address(0))`, as a plain call with no value and no refund, approved by a registered device under the sentinel `RECOVERY_AUDIT_ID = keccak256("signhold.safe-guard.recovery.v1")` (`approveGuardRemoval` in `src/device.ts`, `--recovery` in `scripts/approve-safe.ts`). A recovery approval satisfies nothing else (`NotAttested` for any other transaction). Neither the agent host nor the Signhold host can take this path alone: it needs the owners' Safe signatures *and* the device. Re-keying the attestor after such a recovery is "remove the guard, deploy a new one, `setGuard` it".

**Safe's `checkAfterExecution` semantics**: the Safe calls it after `execute` returns, whether the inner call succeeded or not; with `safeTxGas == 0 && gasPrice == 0` a failed inner call reverts the whole `execTransaction` (and with it the guard's state changes, so the attestation and approval survive and the nonce is not consumed); otherwise the Safe records `success = false`, the nonce is consumed and the guard's entries are cleared. Either way the same hash can never execute twice because the nonce is part of it.

**Events** for every state change: `AttestationSubmitted`, `ApprovalSubmitted`, `TransactionChecked(safeTxHash, verdict, approvalConsumed, approverId)`, `TransactionExecuted(safeTxHash, success)`, `AttestorChanged`, `ApproverSet`, `P256ApproverSet`, `P256EnabledSet`, `ApprovalWindowSet`, `AttestationTtlSet`, `PausedSet`. Typed errors for every failure path (see the `error` declarations in the contract).

**External calls**: `ISafe(safe).nonce()`, `ISafe(safe).getTransactionHash(...)` (both views), and `staticcall` to the `0x100` precompile. Nothing else; no ETH is ever held.

## EIP-712

Domain: `{ name: "SignholdGuard", version: "1", chainId, verifyingContract: <guard> }`, so a signature is bound to one guard on one chain; `safe` inside each struct binds it to the Safe as well.

```
Attestation(address safe,bytes32 safeTxHash,uint8 verdict,uint64 expiresAt,bytes32 auditId)
Approval(address safe,bytes32 safeTxHash,bytes32 auditId,uint64 approvedAt)
```

`auditId` is `sha256(utf8(<Signhold audit record id>))` (`auditIdToBytes32`), `expiresAt` / `approvedAt` are unix seconds. `safeTxHash` is `Safe.getTransactionHash(...)`: `SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)` under `EIP712Domain(uint256 chainId,address verifyingContract)` of the Safe (`computeSafeTxHash` in `src/safeTx.ts`; parity with the contract is asserted in the tests).

## TypeScript (`src/`)

```ts
import {
  computeSafeTxHash, plainSafeTx, encodeSetGuard,          // Safe tx hashing
  attestationTypedData, approvalTypedData, auditIdToBytes32, // EIP-712 builders
  createAttestor,                                           // server side: { address, signAttestation }
  signApproval, signApprovalP256, p256PublicKeyFromPrivate, // device side
  deployGuard, submitAttestation, submitApproval, submitApprovalP256, readAttestation, readApproval, // viem writeContract helpers
  approveSafeTransaction, approveGuardRemoval, recordLoaderFromApi, // trusted-display device flow
  SIGNHOLD_GUARD_ABI, SIGNHOLD_GUARD_BYTECODE,
} from "@signhold/safe-guard";
```

`approveSafeTransaction()` mirrors the rules of `packages/api/scripts/approve.ts`: it loads the sealed audit record itself (never a summary from the agent), recomputes the server challenge and refuses a tampered record, checks that the Safe transaction it is shown *is* the audited intent (chain id, `from` = Safe, `to`, `value`, `data`, plain call, no refund), computes the Safe transaction hash locally (a hash relayed by the agent is at most cross-checked), displays everything, requires a literal `true` from `confirm`, and only then signs. It refuses `block` records, and refuses `allow` records unless the transaction touches the Safe or the guard (where the guard needs a device anyway). `scripts/approve-safe.ts` is the CLI around it (`--url/--api-key` or `--record`, `--safe-tx <json>`, `--key` or `--p256-key`, optional `--rpc-url/--relayer-key` to relay on-chain and `--submit-api` to close the server-side escalation with the same signature, `--recovery` for the escape hatch).

## Service integration (`packages/api`)

- `ServerOptions.attestor: { privateKey, guards?, ttlMs? }` / `SIGNHOLD_ATTESTOR_KEY` (+ `SIGNHOLD_ATTESTOR_GUARDS`, `SIGNHOLD_ATTESTATION_TTL_MS`). The attestor address is refused as an approver at boot.
- `POST /v1/attestations` `{ auditId, safe, guard, chainId, safeTx: { to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce }, safeTxHash? }` → `200 { verdict, verdictCode, safeTxHash, expiresAtUnix, auditIdBytes32, attestor, signature, attestationAuditId, ... }` only when the record is a `check` with verdict allow or escalate, `safe` is the intent's `from`, chain id / `to` / `value` / `data` match byte for byte, the transaction is a plain call without gas refund, the guard is on the allowlist (if one is set) and the optional `safeTxHash` cross-check matches. Anything else is a generic `403 attestation_refused` with the reason in the log and an `attestation_refused` audit record; `block` is `403` too. Every issued attestation is an `attestation` audit record (chained, signed) carrying what was signed, and `verify-audit.ts` checks that each attested verdict code matches its check (`summarizeAttestations`).
- `SIGNHOLD_APPROVER_KEYS` accepts `id:0x<address>` / `id:secp256k1:0x<address>` next to Ed25519 entries. `POST /v1/approvals` with `scheme: "eip712"` and a 65-byte `0x` signature verifies the device's EIP-712 `Approval` against the attestation the service issued for that audit id, so one device signature closes the server-side escalation and satisfies the guard.

## Deployment

1. Deploy the guard: `deployGuard(wallet, { safe, attestor, approvers, p256Approvers?, p256Enabled?, approvalWindowSeconds?, attestationTtlSeconds? })` (or the constructor with the same arguments). Check `attestor` is the address printed by the service at boot and that each approver address/P-256 key is the device's.
2. Install it with an ordinary Safe transaction from the owners: `setGuard(<guard>)`. Safe checks `supportsInterface(0xe6d7a83a)` (`GS300` otherwise). From this transaction on, every `execTransaction` goes through the guard: make sure the service and at least one device are ready first, and keep the owner escape hatch in mind.
3. Run the service with `SIGNHOLD_ATTESTOR_KEY` (and `SIGNHOLD_ATTESTOR_GUARDS=<guard>`), the device addresses in `SIGNHOLD_APPROVER_KEYS`, and the agent behind `@signhold/sdk` as before. The agent's loop becomes: `check` → `requestAttestation` → `submitAttestation` → (escalate: wait for the device) → `execTransaction`.
4. To change keys or windows: a Safe transaction `to = guard` (attested by the service, approved by a device). To remove the guard: `setGuard(address(0))` under the same rule, or the recovery path.

Safe versions: built and tested against `@safe-global/safe-smart-account@1.5.0` (a real Safe is deployed from its artifacts in the tests and the demo); the guard interface, the nonce ordering and `getTransactionHash` are identical in `@safe-global/safe-contracts@1.4.1`. Safe 1.3.0 has the same guard interface but was not exercised.

## Threat model delta

What each key compromise can and cannot do once a Safe is behind the guard:

| Compromised | Can | Cannot |
| --- | --- | --- |
| Agent host (owner key + API key) | propose transactions; execute what the service attests `allow`; spam checks | execute anything the service did not attest (block, or no attestation); execute an escalation; re-key, pause or remove the guard; add owners or modules; delegatecall; take the recovery path |
| Signhold host (attestor key + audit key) | attest `allow` for anything the agent proposes, as long as it is a plain call (so, together with the agent, drain within whatever the agent can propose that is *not* sensitive) | approve an escalation; re-key, pause or remove the guard; change Safe configuration; forge a device signature; take the recovery path (needs owners and a device) |
| Approver device (approver key) | sign approvals for hashes it is shown | execute anything by itself: it holds no owner key, and an approval is only useful for a hash the owners signed and (recovery aside) the service attested |
| Agent host + Signhold host | drain through non-sensitive transactions attested `allow` | re-key / remove the guard, change owners / modules, delegatecall: all need a device |
| Agent host + device | the device can approve what the agent proposes, but without an attestation only guard removal is accepted | execute an arbitrary transaction while the service is honest |

Residuals that remain: a compromised service can turn escalations into `allow`s for non-sensitive transactions (mitigate with small caps on the policy side, and with the window/TTL bounds; the attestation record makes it attributable); Safe **modules** bypass transaction guards entirely in 1.4.1 (1.5.0 has a separate module guard this contract does not implement), so the guard only protects a Safe that has no modules enabled, and `enableModule` is itself gated; the guard protects only `execTransaction`, not signatures the owners produce for other purposes (EIP-1271 messages, permits), which is the SDK's job; a stolen device key is bounded by the single-use, time-boxed approvals and revocable through `setApprover` (an approved transaction); the on-chain `approvedAt` / `expiresAt` checks trust the chain's timestamp like every time-bound contract.

## Chain support and P-256

The secp256k1 path works on every EVM chain. The P-256 path needs the RIP-7212 / EIP-7951 precompile at `0x100` (`P256VERIFY`: 160-byte input `hash || r || s || qx || qy`, 32-byte `1` on success, empty output on failure); `setP256Enabled(true)` probes it and refuses where it is absent, and a P-256 approval where the precompile has disappeared reverts `P256PrecompileUnavailable` instead of failing open. As of the research for this release (see sources): Ethereum L1 since the Fusaka upgrade (EIP-7951, 3 Dec 2025, 6900 gas); Base and OP Mainnet since Fjord (Base mainnet 10 Jul 2024; RIP-7212, 3450 gas); Polygon PoS since Napoli (PIP-27, March 2024); Arbitrum One/Nova since ArbOS 32 "Bianca"; zkSync Era since protocol v24. Check your chain's precompile list before enabling P-256; the secp256k1 path needs nothing.

The tests run the P-256 path against Hardhat EDR's native Osaka-rules precompile, against a mock installed at `0x100` with `hardhat_setCode` (real P-256 math in Solidity behind the RIP-7212 ABI) on a Cancun-rules network, and with the precompile removed again.

## Gas

Measured with Hardhat EDR (solc 0.8.28, optimizer 1000 runs, evm `cancun`, Safe 1.5.0, hardfork `osaka`); `npm run test -w contracts/safe-guard` prints the table.

| Operation | Gas |
| --- | ---: |
| deploy `SignholdGuard` (1 approver, no P-256) | ≈ 2.76 M |
| `Safe.execTransaction`, ERC-20 transfer, no guard (baseline) | 65 066 |
| `Safe.execTransaction`, attested allow | 96 878 (+≈ 32 k) |
| `Safe.execTransaction`, escalate + approval consumed | 104 524 (+≈ 40 k) |
| `submitAttestation` (first write) | ≈ 81 k |
| `submitApproval` (secp256k1) | ≈ 108 k |
| `submitApprovalP256` (native precompile, 6900 gas) | ≈ 112 k |
| `execTransaction` `setAttestor` / `setGuard(0)` (approved) | ≈ 99.5 k / ≈ 95.8 k |

## Tests

`npm run test -w contracts/safe-guard` (Hardhat 3 + viem + `node:test`, no network; solc is the pinned `solc` npm package, so builds are offline and reproducible): 27 cases covering parity with the Safe (`getTransactionHash`, interface id, EIP-712 digests, the committed ABI vs. the artifact), allow / block / escalate paths, replay, expiry (attestation and approval, at submission and at execution), wrong attestor, unregistered and mis-claimed approvers, approval re-binding across hashes and audit ids, the no-downgrade rule, guard and Safe self-protection, delegatecall and refund gating, `OnlySafe`, key separation, a misconfigured (foreign) Safe being able only to remove the guard, pause and unpause, guard removal (attested + approved, and the recovery path), and P-256 with the native precompile, a mocked precompile and no precompile.

`npm run slither -w contracts/safe-guard` runs [Slither](https://github.com/crytic/slither) 0.11.6 against the Hardhat artifacts (`hardhat_ignore_compile`): 0 findings with `slither.config.json`, which excludes the by-design informationals `timestamp` (expiry windows), `assembly` (memory-safe selector decode in `_isGuardRemoval`), `low-level-calls` (the precompile `staticcall`), `too-many-digits` (curve constants, probe vector) and `unused-return` (the third value of `ECDSA.tryRecover`).

## Limitations

- Safe only, EVM only. The Solana program (verifying the approver signature over the challenge on-chain) is the next item; non-Safe signers keep the SDK-level residual (docs/THREAT_MODEL.md).
- The service attests plain calls only (no delegatecall, no gas refund, no `gasToken`); batching via MultiSend delegatecall is therefore not attestable and always needs a device approval.
- Modules bypass transaction guards (see above). Do not enable modules on a guarded Safe; the guard makes `enableModule` a device-approved transaction but cannot see module executions.
- One guard per Safe (the Safe is immutable in the guard). A Safe that mistakenly installs a guard deployed for another Safe can do exactly one thing through it, `setGuard(address(0))`, so the mistake is recoverable; nothing is attested or approved for such a Safe.
- Pending attestations and approvals are not garbage-collected if a transaction is never executed; they are cheap to leave behind and expire by time.
- `approvedAt` and `expiresAt` are compared with `block.timestamp`.

## Audit status

**Unaudited.** The contract is small (≈ 450 lines, two external view calls, one precompile call), covered by the tests above and clean under Slither, but it has not been reviewed by a third party. Do not put funds behind it that you cannot afford to lose until it has been.

## Sources relied on

- Safe guard interface, `setGuard` (`authorized`, `GS300`), `GUARD_STORAGE_SLOT`, `nonce++` before `checkTransaction`, `getTransactionHash`: `@safe-global/safe-smart-account@1.5.0` (`contracts/base/GuardManager.sol`, `contracts/Safe.sol`, `contracts/examples/guards/DebugTransactionGuard.sol`), also published at https://cdn.jsdelivr.net/npm/@safe-global/safe-smart-account@1.5.0/contracts/base/GuardManager.sol, and `@safe-global/safe-contracts@1.4.1-2` (same files). Guard concept and the "a broken guard can lock a Safe" warning: https://docs.safe.global/smart-account-guards.
- RIP-7212 (precompile at `0x100`, 160-byte input, 32-byte `1` / empty output, 3450 gas): https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md. EIP-7951 (L1 variant, 6900 gas, explicit input validation): https://eips.ethereum.org/EIPS/eip-7951; Fusaka mainnet activation (epoch 411392, 3 Dec 2025) and EIP list: https://blog.ethereum.org/2025/11/06/fusaka-mainnet-announcement.
- OP Stack Fjord includes RIP-7212: https://specs.optimism.io/protocol/fjord/overview.html; Base Fjord activation timestamps: https://docs.base.org/base-chain/specs/upgrades/fjord/overview. Polygon PoS (PIP-27, Napoli): https://forum.polygon.technology/t/pip-27-precompiled-for-secp256r1-curve-support/13049. Arbitrum ArbOS 32 "Bianca": https://docs.arbitrum.io/run-arbitrum-node/arbos-releases/arbos32. zkSync v24 and deployment overview: https://ethereum-magicians.org/t/eip-7212-precompiled-for-secp256r1-curve-support/14789/92.
- The P-256 probe vector is the Wycheproof `ecdsa_secp256r1_sha256_p1363` case used by OpenZeppelin's `P256._tryVerifyNative` (`@openzeppelin/contracts@5.6.1`).
- Pinned: `hardhat@3.21.2`, `@nomicfoundation/hardhat-viem@3.1.0`, `@nomicfoundation/hardhat-node-test-runner@3.1.2`, `@nomicfoundation/hardhat-network-helpers@3.0.12`, `viem@2.57.15`, `@openzeppelin/contracts@5.6.1`, `@safe-global/safe-smart-account@1.5.0`, `@noble/curves@1.9.7` (P-256 signing on the device side), `solc@0.8.28`.
