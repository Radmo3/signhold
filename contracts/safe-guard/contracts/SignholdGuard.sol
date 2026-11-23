// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @dev Minimal view of the Safe the guard reads from. Only view functions are used.
 *      Layout follows the `ISafe` interface of safe-smart-account 1.5.0 (identical in safe-contracts 1.4.1).
 */
interface ISafeView {
    function nonce() external view returns (uint256);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        SignholdGuard.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);
}

/**
 * @dev Safe transaction guard interface (`ITransactionGuard` in safe-smart-account 1.5.0,
 *      `Guard` in safe-contracts 1.4.1; both have interface id 0xe6d7a83a). `Operation` is
 *      ABI-encoded as uint8, so the selectors match the Safe's `Enum.Operation` exactly.
 */
interface ITransactionGuard is IERC165 {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        SignholdGuard.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 hash, bool success) external;
}

/**
 * @title SignholdGuard
 * @notice Safe (Gnosis Safe) transaction guard that lets a Safe execute a transaction only when
 *         (a) the Signhold service has attested a verdict for that exact Safe transaction hash and
 *         (b) if the verdict is `escalate`, or the transaction touches the Safe's own configuration
 *             or this guard, a registered human approver device has signed it.
 *
 *         Three keys, three holders, and an escalated payment needs all three:
 *           - the Safe owner key(s): held by the agent host, sign the Safe transaction;
 *           - the attestor key (secp256k1): held by the Signhold host, signs an EIP-712 `Attestation`;
 *           - the approver key (secp256k1 or P-256): held by the human's device, signs an EIP-712 `Approval`.
 *
 *         Every path fails closed: no attestation => revert, expired => revert, `escalate` without an
 *         unexpired single-use approval => revert, paused => revert (except approved guard
 *         administration / removal, so a pause can be lifted). `block` verdicts are never
 *         attested by the service, so their absence is what blocks them.
 *
 * @dev Nonce convention: the Safe (1.3.0 … 1.5.0) increments `nonce` BEFORE it calls the guard
 *      (`nonce++` precedes `checkTransaction` in `Safe.execTransaction`), so the hash of the
 *      transaction being checked is computed with `nonce() - 1`, exactly as Safe's own
 *      `DebugTransactionGuard` does.
 *
 *      Reentrancy: `checkTransaction` records the hash it accepted and `checkAfterExecution`
 *      must see the same hash; a nested `execTransaction` on the same Safe while one is in
 *      flight is refused. The only external calls are the two Safe view functions and the
 *      RIP-7212 precompile.
 *
 *      Self-protection (stricter choice, see README): any transaction whose `to` is this guard
 *      or the Safe itself (which is where `setGuard`, `enableModule`, `addOwner`, … live), any
 *      `DelegateCall` (which could write the guard storage slot directly), and any transaction
 *      with a gas refund (`gasPrice != 0`, which moves funds the service never simulated) needs
 *      a human approval regardless of the attested verdict. There is no attestation-only path to
 *      re-key, pause, or remove the guard.
 *
 *      Owner escape hatch: owners can always remove the guard with an approved transaction. If the
 *      Signhold service is unavailable (or its attestor key is lost), exactly one transaction is
 *      accepted without an attestation: `setGuard(address(0))` on the Safe, approved by a registered
 *      device under the sentinel audit id `RECOVERY_AUDIT_ID`. Neither the agent host nor the
 *      Signhold host can take that path alone: it needs the Safe owners' signatures and the device.
 *
 *      UNAUDITED. See README.md.
 */
contract SignholdGuard is ITransactionGuard, EIP712 {
    enum Operation {
        Call,
        DelegateCall
    }

    // ---- Verdicts (as attested; `block` is never attested) ----
    uint8 public constant VERDICT_ALLOW = 1;
    uint8 public constant VERDICT_ESCALATE = 2;

    /// @notice Sentinel audit id under which a device may approve guard removal without an attestation.
    bytes32 public constant RECOVERY_AUDIT_ID = keccak256("signhold.safe-guard.recovery.v1");

    /// @notice How far in the future a device's `approvedAt` may be (device/chain clock skew).
    uint64 public constant MAX_CLOCK_SKEW = 5 minutes;

    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(address safe,bytes32 safeTxHash,uint8 verdict,uint64 expiresAt,bytes32 auditId)");
    bytes32 public constant APPROVAL_TYPEHASH =
        keccak256("Approval(address safe,bytes32 safeTxHash,bytes32 auditId,uint64 approvedAt)");

    // `setGuard(address)` selector on the Safe.
    bytes4 private constant SET_GUARD_SELECTOR = bytes4(keccak256("setGuard(address)"));

    struct Attestation {
        uint8 verdict; // 0 = none
        uint64 expiresAt;
        bytes32 auditId;
    }

    struct Approval {
        bytes32 approverId; // secp256k1: address left-padded; P-256: keccak256(abi.encode(qx, qy))
        bytes32 auditId;
        uint64 approvedAt; // 0 = none
    }

    // ---- Configuration (only the Safe, through an approved transaction, can change it) ----

    /// @notice The one Safe this guard protects. Hooks called by any other address revert, except that another Safe may remove the guard.
    address public immutable safe;
    /// @notice The Signhold service's attestor key (secp256k1 address). Never an approver.
    address public attestor;
    /// @notice Registered human approver devices (secp256k1 addresses).
    mapping(address => bool) public approvers;
    /// @notice Registered P-256 approver devices, keyed by keccak256(abi.encode(qx, qy)).
    mapping(bytes32 => bool) public p256Approvers;
    /// @notice Whether P-256 approvals are accepted (requires the RIP-7212 precompile at 0x100).
    bool public p256Enabled;
    /// @notice Seconds an approval stays valid after its `approvedAt`.
    uint64 public approvalWindow;
    /// @notice Maximum distance of an attestation's `expiresAt` from the time it is submitted.
    uint64 public attestationTtl;
    /// @notice When true no transaction executes except guard administration and guard removal (both device-approved).
    bool public paused;

    // ---- State ----
    mapping(bytes32 => Attestation) public attestations;
    mapping(bytes32 => Approval) public approvals;
    /// @dev Hash accepted by `checkTransaction`, awaiting `checkAfterExecution`. Doubles as a reentrancy lock.
    bytes32 private _executing;

    // ---- Events ----
    event AttestationSubmitted(bytes32 indexed safeTxHash, uint8 verdict, uint64 expiresAt, bytes32 indexed auditId, address submitter);
    event ApprovalSubmitted(bytes32 indexed safeTxHash, bytes32 indexed approverId, bytes32 indexed auditId, uint64 approvedAt, bool p256);
    event TransactionChecked(bytes32 indexed safeTxHash, uint8 verdict, bool approvalConsumed, bytes32 approverId);
    event TransactionExecuted(bytes32 indexed safeTxHash, bool success);
    event AttestorChanged(address indexed previous, address indexed current);
    event ApproverSet(address indexed approver, bool enabled);
    event P256ApproverSet(bytes32 indexed approverId, bytes32 qx, bytes32 qy, bool enabled);
    event P256EnabledSet(bool enabled);
    event ApprovalWindowSet(uint64 seconds_);
    event AttestationTtlSet(uint64 seconds_);
    event PausedSet(bool paused);

    // ---- Errors ----
    error OnlySafe();
    error GuardPaused();
    error ZeroAddress();
    error InvalidVerdict(uint8 verdict);
    error InvalidAuditId();
    error InvalidWindow();
    error AttestationExpiredAtSubmission(uint64 expiresAt);
    error AttestationTooFarInFuture(uint64 expiresAt, uint64 maxExpiresAt);
    error InvalidAttestorSignature();
    error AttestationDowngrade(bytes32 safeTxHash);
    error NotAttested(bytes32 safeTxHash);
    error AttestationExpired(bytes32 safeTxHash, uint64 expiresAt);
    error AuditIdMismatch(bytes32 expected, bytes32 actual);
    error UnregisteredApprover(bytes32 approverId);
    error InvalidApproverSignature();
    error InvalidP256PublicKey();
    error ApprovedAtOutOfWindow(uint64 approvedAt);
    error ApprovalAlreadySubmitted(bytes32 safeTxHash);
    error ApprovalRequired(bytes32 safeTxHash);
    error ApprovalExpired(bytes32 safeTxHash, uint64 approvedAt);
    error ApprovalMismatch(bytes32 safeTxHash);
    error P256Disabled();
    error P256PrecompileUnavailable();
    error KeySeparation(address key);
    error Reentrancy();
    error UnexpectedAfterExecution(bytes32 expected, bytes32 actual);

    modifier onlySafe() {
        if (msg.sender != safe) revert OnlySafe();
        _;
    }

    /**
     * @param safe_ The Safe this guard will protect (the only address allowed to call the check hooks).
     * @param attestor_ Signhold attestor address (secp256k1). Must not be an approver or the Safe.
     * @param approvers_ Initial secp256k1 approver devices.
     * @param p256Qx Initial P-256 approver public key x coordinates (same length as `p256Qy`).
     * @param p256Qy Initial P-256 approver public key y coordinates.
     * @param p256Enabled_ Accept P-256 approvals; the constructor reverts if the RIP-7212 precompile is absent.
     * @param approvalWindow_ Seconds an approval stays valid (the service default is 15 minutes).
     * @param attestationTtl_ Maximum attestation lifetime accepted at submission (e.g. 1 hour).
     */
    constructor(
        address safe_,
        address attestor_,
        address[] memory approvers_,
        bytes32[] memory p256Qx,
        bytes32[] memory p256Qy,
        bool p256Enabled_,
        uint64 approvalWindow_,
        uint64 attestationTtl_
    ) EIP712("SignholdGuard", "1") {
        if (safe_ == address(0) || attestor_ == address(0)) revert ZeroAddress();
        if (attestor_ == safe_) revert KeySeparation(attestor_);
        if (approvalWindow_ == 0 || attestationTtl_ == 0) revert InvalidWindow();
        if (p256Qx.length != p256Qy.length) revert InvalidWindow();
        safe = safe_;
        attestor = attestor_;
        emit AttestorChanged(address(0), attestor_);
        for (uint256 i = 0; i < approvers_.length; i++) {
            _setApprover(approvers_[i], true);
        }
        for (uint256 i = 0; i < p256Qx.length; i++) {
            _setP256Approver(p256Qx[i], p256Qy[i], true);
        }
        if (p256Enabled_) _setP256Enabled(true);
        approvalWindow = approvalWindow_;
        emit ApprovalWindowSet(approvalWindow_);
        attestationTtl = attestationTtl_;
        emit AttestationTtlSet(attestationTtl_);
    }

    // =====================================================================================
    // Submissions (anyone may relay; authority comes from the signatures, never the sender)
    // =====================================================================================

    /**
     * @notice Record the Signhold service's verdict for `safeTxHash`.
     * @dev The signature is an EIP-712 `Attestation` by `attestor` over this guard's domain. A new
     *      attestation for the same hash may only tighten: allow -> escalate is accepted, escalate ->
     *      allow is refused. `expiresAt` must be in the future and within `attestationTtl`.
     */
    function submitAttestation(bytes32 safeTxHash, uint8 verdict, uint64 expiresAt, bytes32 auditId, bytes calldata attestorSig) external {
        if (verdict != VERDICT_ALLOW && verdict != VERDICT_ESCALATE) revert InvalidVerdict(verdict);
        if (auditId == bytes32(0) || auditId == RECOVERY_AUDIT_ID) revert InvalidAuditId();
        if (expiresAt <= block.timestamp) revert AttestationExpiredAtSubmission(expiresAt);
        uint64 maxExpiresAt = uint64(block.timestamp) + attestationTtl;
        if (expiresAt > maxExpiresAt) revert AttestationTooFarInFuture(expiresAt, maxExpiresAt);

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(ATTESTATION_TYPEHASH, safe, safeTxHash, verdict, expiresAt, auditId)));
        (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, attestorSig);
        if (err != ECDSA.RecoverError.NoError || signer == address(0) || signer != attestor) revert InvalidAttestorSignature();

        Attestation storage existing = attestations[safeTxHash];
        if (existing.verdict == VERDICT_ESCALATE && verdict == VERDICT_ALLOW) revert AttestationDowngrade(safeTxHash);

        attestations[safeTxHash] = Attestation({verdict: verdict, expiresAt: expiresAt, auditId: auditId});
        emit AttestationSubmitted(safeTxHash, verdict, expiresAt, auditId, msg.sender);
    }

    /**
     * @notice Record a human approval (secp256k1 device) for `safeTxHash`.
     * @dev EIP-712 `Approval{safe, safeTxHash, auditId, approvedAt}` by a registered approver. `auditId`
     *      must be the id of an unexpired attestation already stored for the hash, or `RECOVERY_AUDIT_ID`
     *      (which only ever satisfies a guard-removal transaction). Single use; an unused, unexpired
     *      approval cannot be replaced.
     */
    function submitApproval(bytes32 safeTxHash, bytes32 auditId, address approver, uint64 approvedAt, bytes calldata sig) external {
        bytes32 approverId = bytes32(uint256(uint160(approver)));
        if (!approvers[approver]) revert UnregisteredApprover(approverId);
        bytes32 digest = _approvalDigest(safeTxHash, auditId, approvedAt);
        (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, sig);
        if (err != ECDSA.RecoverError.NoError || signer == address(0) || signer != approver) revert InvalidApproverSignature();
        _storeApproval(safeTxHash, auditId, approverId, approvedAt, false);
    }

    /**
     * @notice Record a human approval from a P-256 (secp256r1, e.g. passkey / Secure Enclave) device.
     * @dev Verified with the RIP-7212 precompile at 0x100 only; if the precompile is absent the call
     *      reverts with `P256PrecompileUnavailable` (there is no Solidity fallback). `s` must be in the
     *      lower half of the curve order.
     */
    function submitApprovalP256(bytes32 safeTxHash, bytes32 auditId, bytes32 qx, bytes32 qy, uint64 approvedAt, bytes32 r, bytes32 s) external {
        if (!p256Enabled) revert P256Disabled();
        bytes32 approverId = keccak256(abi.encode(qx, qy));
        if (!p256Approvers[approverId]) revert UnregisteredApprover(approverId);
        bytes32 digest = _approvalDigest(safeTxHash, auditId, approvedAt);
        if (!_p256VerifyNative(digest, r, s, qx, qy)) revert InvalidApproverSignature();
        _storeApproval(safeTxHash, auditId, approverId, approvedAt, true);
    }

    // =====================================================================================
    // Safe hooks
    // =====================================================================================

    /// @inheritdoc ITransactionGuard
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory, /* signatures: already verified by the Safe */
        address /* msgSender */
    ) external override {
        if (msg.sender != safe) {
            // A Safe this guard was not deployed for (misconfigured `setGuard`): refuse everything
            // except removing this guard again, so the mistake cannot brick that Safe. Nothing is
            // attested or approved for it; this guard has no relationship with it.
            if (!_isGuardRemoval(msg.sender, to, value, data, operation, gasPrice)) revert OnlySafe();
            return;
        }
        if (_executing != bytes32(0)) revert Reentrancy();

        // The Safe has already incremented its nonce for this transaction (see contract docs).
        bytes32 txHash = ISafeView(safe).getTransactionHash(
            to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, ISafeView(safe).nonce() - 1
        );
        bool guardRemoval = _isGuardRemoval(safe, to, value, data, operation, gasPrice);
        // Anything that can change who controls the Safe or this guard, or move funds the service
        // never simulated, needs a human regardless of the attested verdict.
        bool sensitive = to == address(this) || to == safe || operation == Operation.DelegateCall || gasPrice != 0;
        // Paused: nothing executes except guard administration (unpause, re-key) and guard removal,
        // both of which still need an approved device signature below.
        if (paused && to != address(this) && !guardRemoval) revert GuardPaused();
        _enforce(txHash, guardRemoval, sensitive);
    }

    /// @dev The decision itself, split out of `checkTransaction` to keep the Safe's 11-argument hook within stack limits.
    function _enforce(bytes32 txHash, bool guardRemoval, bool sensitive) private {
        Attestation memory att = attestations[txHash];

        if (att.verdict == 0) {
            // Owner escape hatch: the only unattested transaction ever accepted is removing this guard,
            // and it still needs the human's device.
            if (!guardRemoval) revert NotAttested(txHash);
            bytes32 approverId = _consumeApproval(txHash, RECOVERY_AUDIT_ID, true);
            _executing = txHash;
            emit TransactionChecked(txHash, 0, true, approverId);
            return;
        }
        if (block.timestamp >= att.expiresAt) revert AttestationExpired(txHash, att.expiresAt);

        bool needsApproval = att.verdict == VERDICT_ESCALATE || sensitive;
        bytes32 usedBy = bytes32(0);
        if (needsApproval) usedBy = _consumeApproval(txHash, att.auditId, guardRemoval);
        _executing = txHash;
        emit TransactionChecked(txHash, att.verdict, needsApproval, usedBy);
    }

    /// @inheritdoc ITransactionGuard
    function checkAfterExecution(bytes32 hash, bool success) external override {
        if (msg.sender != safe) return; // foreign Safe removing this guard (see checkTransaction); nothing to clear
        bytes32 expected = _executing;
        if (expected == bytes32(0) || hash != expected) revert UnexpectedAfterExecution(expected, hash);
        _executing = bytes32(0);
        delete attestations[hash];
        delete approvals[hash];
        emit TransactionExecuted(hash, success);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(ITransactionGuard).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    // =====================================================================================
    // Administration: only the Safe, i.e. only through a Safe transaction that itself passes
    // this guard with a human approval (`to == address(this)` always needs one).
    // =====================================================================================

    function setAttestor(address newAttestor) external onlySafe {
        if (newAttestor == address(0)) revert ZeroAddress();
        if (newAttestor == safe || approvers[newAttestor]) revert KeySeparation(newAttestor);
        emit AttestorChanged(attestor, newAttestor);
        attestor = newAttestor;
    }

    function setApprover(address approver, bool enabled) external onlySafe {
        _setApprover(approver, enabled);
    }

    function setP256Approver(bytes32 qx, bytes32 qy, bool enabled) external onlySafe {
        _setP256Approver(qx, qy, enabled);
    }

    function setP256Enabled(bool enabled) external onlySafe {
        _setP256Enabled(enabled);
    }

    function setApprovalWindow(uint64 seconds_) external onlySafe {
        if (seconds_ == 0) revert InvalidWindow();
        approvalWindow = seconds_;
        emit ApprovalWindowSet(seconds_);
    }

    function setAttestationTtl(uint64 seconds_) external onlySafe {
        if (seconds_ == 0) revert InvalidWindow();
        attestationTtl = seconds_;
        emit AttestationTtlSet(seconds_);
    }

    function setPaused(bool paused_) external onlySafe {
        paused = paused_;
        emit PausedSet(paused_);
    }

    // =====================================================================================
    // Views for off-chain parity
    // =====================================================================================

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function hashAttestation(bytes32 safeTxHash, uint8 verdict, uint64 expiresAt, bytes32 auditId) external view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(ATTESTATION_TYPEHASH, safe, safeTxHash, verdict, expiresAt, auditId)));
    }

    function hashApproval(bytes32 safeTxHash, bytes32 auditId, uint64 approvedAt) external view returns (bytes32) {
        return _approvalDigest(safeTxHash, auditId, approvedAt);
    }

    /// @notice Id under which a P-256 public key is registered.
    function p256ApproverId(bytes32 qx, bytes32 qy) external pure returns (bytes32) {
        return keccak256(abi.encode(qx, qy));
    }

    // =====================================================================================
    // Internals
    // =====================================================================================

    function _approvalDigest(bytes32 safeTxHash, bytes32 auditId, uint64 approvedAt) private view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(APPROVAL_TYPEHASH, safe, safeTxHash, auditId, approvedAt)));
    }

    function _storeApproval(bytes32 safeTxHash, bytes32 auditId, bytes32 approverId, uint64 approvedAt, bool p256) private {
        if (auditId == bytes32(0)) revert InvalidAuditId();
        if (auditId != RECOVERY_AUDIT_ID) {
            Attestation storage att = attestations[safeTxHash];
            if (att.verdict == 0) revert NotAttested(safeTxHash);
            if (block.timestamp >= att.expiresAt) revert AttestationExpired(safeTxHash, att.expiresAt);
            if (att.auditId != auditId) revert AuditIdMismatch(att.auditId, auditId);
        }
        if (approvedAt > block.timestamp + MAX_CLOCK_SKEW) revert ApprovedAtOutOfWindow(approvedAt);
        if (approvedAt == 0 || uint256(approvedAt) + approvalWindow <= block.timestamp) revert ApprovedAtOutOfWindow(approvedAt);

        Approval storage existing = approvals[safeTxHash];
        // An unused approval can only be replaced once it has expired.
        if (existing.approvedAt != 0 && uint256(existing.approvedAt) + approvalWindow > block.timestamp) revert ApprovalAlreadySubmitted(safeTxHash);

        approvals[safeTxHash] = Approval({approverId: approverId, auditId: auditId, approvedAt: approvedAt});
        emit ApprovalSubmitted(safeTxHash, approverId, auditId, approvedAt, p256);
    }

    /**
     * @dev Require an unexpired approval bound to `auditId` (or to `RECOVERY_AUDIT_ID` when
     *      `allowRecovery`) and delete it (single use). Effects happen before the Safe executes.
     */
    function _consumeApproval(bytes32 txHash, bytes32 auditId, bool allowRecovery) private returns (bytes32 approverId) {
        Approval memory ap = approvals[txHash];
        if (ap.approvedAt == 0) revert ApprovalRequired(txHash);
        if (ap.auditId != auditId && !(allowRecovery && ap.auditId == RECOVERY_AUDIT_ID)) revert ApprovalMismatch(txHash);
        if (uint256(ap.approvedAt) + approvalWindow <= block.timestamp) revert ApprovalExpired(txHash, ap.approvedAt);
        delete approvals[txHash];
        return ap.approverId;
    }

    /// @dev Exactly `safe_.setGuard(address(0))`: a plain call, no value, no refund.
    function _isGuardRemoval(address safe_, address to, uint256 value, bytes memory data, Operation operation, uint256 gasPrice) private pure returns (bool) {
        if (to != safe_ || value != 0 || operation != Operation.Call || gasPrice != 0 || data.length != 36) return false;
        bytes4 selector;
        address arg;
        assembly ("memory-safe") {
            selector := mload(add(data, 32))
            arg := mload(add(data, 36))
        }
        return selector == SET_GUARD_SELECTOR && arg == address(0);
    }

    function _setApprover(address approver, bool enabled) private {
        if (approver == address(0)) revert ZeroAddress();
        if (enabled && (approver == attestor || approver == safe)) revert KeySeparation(approver);
        approvers[approver] = enabled;
        emit ApproverSet(approver, enabled);
    }

    function _setP256Approver(bytes32 qx, bytes32 qy, bool enabled) private {
        if (enabled && !P256.isValidPublicKey(qx, qy)) revert InvalidP256PublicKey();
        bytes32 id = keccak256(abi.encode(qx, qy));
        p256Approvers[id] = enabled;
        emit P256ApproverSet(id, qx, qy, enabled);
    }

    function _setP256Enabled(bool enabled) private {
        if (enabled) {
            // Probe the precompile with a known-valid vector; refuse to enable P-256 where it is absent
            // (`_p256VerifyNative` reverts P256PrecompileUnavailable in that case).
            bool ok = _p256VerifyNative(
                0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023,
                0x0000000000000000000000000000000000000000000000000000000000000005,
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957,
                0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b
            );
            if (!ok) revert P256PrecompileUnavailable();
        }
        p256Enabled = enabled;
        emit P256EnabledSet(enabled);
    }

    /// @dev Lower half of the P-256 curve order: signatures with `s` above it are refused (malleability).
    uint256 private constant P256_HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
    /// @dev RIP-7212 precompile (P256VERIFY) address.
    address private constant P256_PRECOMPILE = address(0x100);

    /**
     * @dev RIP-7212 precompile only, no Solidity fallback. Returns false for a malformed or invalid
     *      signature; reverts `P256PrecompileUnavailable` when a known-valid probe vector
     *      (Wycheproof ecdsa_secp256r1_sha256_p1363, as used by OpenZeppelin's P256) also fails,
     *      which is how an absent precompile (empty return) is told apart from a bad signature.
     */
    function _p256VerifyNative(bytes32 h, bytes32 r, bytes32 s, bytes32 qx, bytes32 qy) private view returns (bool) {
        if (uint256(r) == 0 || uint256(r) >= P256.N || uint256(s) == 0 || uint256(s) > P256_HALF_N) return false;
        if (!P256.isValidPublicKey(qx, qy)) return false;
        if (_rip7212(h, r, s, qx, qy)) return true;
        if (
            _rip7212(
                0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, // sha256("123400")
                0x0000000000000000000000000000000000000000000000000000000000000005,
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957,
                0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b
            )
        ) return false; // precompile present, signature invalid
        revert P256PrecompileUnavailable();
    }

    /// @dev `staticcall` 0x100 with `hash || r || s || qx || qy` (160 bytes); valid iff it returns 32 bytes equal to 1.
    function _rip7212(bytes32 h, bytes32 r, bytes32 s, bytes32 qx, bytes32 qy) private view returns (bool isValid) {
        bytes memory input = abi.encode(h, r, s, qx, qy);
        (bool ok, bytes memory ret) = P256_PRECOMPILE.staticcall(input);
        return ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }
}
