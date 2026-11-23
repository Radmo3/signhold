import { createRequire } from "node:module";
import { defineConfig } from "hardhat/config";
import hardhatViem from "@nomicfoundation/hardhat-viem";
import hardhatNodeTestRunner from "@nomicfoundation/hardhat-node-test-runner";
import hardhatNetworkHelpers from "@nomicfoundation/hardhat-network-helpers";

// The compiler is the pinned `solc` npm package (solc-js, WASM), not a binary
// downloaded at build time: the build is reproducible and works offline / in CI.
const require = createRequire(import.meta.url);
const SOLC_VERSION = "0.8.28";
const solcPath = process.env.SIGNHOLD_SOLC_PATH ?? require.resolve("solc/soljson.js");

export default defineConfig({
  plugins: [hardhatViem, hardhatNodeTestRunner, hardhatNetworkHelpers],
  solidity: {
    version: SOLC_VERSION,
    path: solcPath,
    settings: { optimizer: { enabled: true, runs: 1000 }, evmVersion: "cancun" },
  },
  paths: { tests: { nodejs: "test" }, sources: "contracts" },
  networks: {
    // Default: Osaka (Fusaka) rules, which include EIP-7951's native P256VERIFY precompile at 0x100.
    hardhatMainnet: { type: "edr-simulated", chainType: "l1", hardfork: "osaka" },
    // Pre-Fusaka rules: no precompile at 0x100, used to test the fail-closed P-256 behaviour
    // and to install the mock precompile with hardhat_setCode.
    hardhatCancun: { type: "edr-simulated", chainType: "l1", hardfork: "cancun" },
  },
});
