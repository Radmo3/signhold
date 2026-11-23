// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/**
 * @dev Test double for the RIP-7212 precompile, installed at 0x100 with `hardhat_setCode`.
 *      Same ABI as the real thing: 160-byte input `hash || r || s || qx || qy`, returns 32 bytes
 *      equal to 1 on a valid signature and NO output otherwise. Verification is real
 *      (OpenZeppelin's pure-Solidity P-256), so tampered signatures fail as they would on-chain.
 *      Gas is not representative (the real precompile costs 3450 / 6900 gas).
 */
contract MockP256Precompile {
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 160) return "";
        (bytes32 h, bytes32 r, bytes32 s, bytes32 qx, bytes32 qy) = abi.decode(input, (bytes32, bytes32, bytes32, bytes32, bytes32));
        if (P256.verifySolidity(h, r, s, qx, qy)) return abi.encode(uint256(1));
        return "";
    }
}
