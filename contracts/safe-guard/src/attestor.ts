/**
 * Server-side attestor: the Signhold service's secp256k1 key that signs EIP-712 `Attestation`s.
 * It is a third key kind, distinct from the Ed25519 audit signing key and never an approver.
 */
import { privateKeyToAccount } from "viem/accounts";
import { isHex, type Address, type Hex } from "viem";
import { attestationTypedData, type AttestationMessage, type GuardDomainInput } from "./typedData.js";

export interface Attestor {
  /** The address the guard must be configured with (`attestor`). */
  readonly address: Address;
  signAttestation(domain: GuardDomainInput, message: AttestationMessage): Promise<Hex>;
}

export interface CreateAttestorOptions {
  /** 32-byte secp256k1 private key, 0x-prefixed hex. Keep it in a secrets manager; never on the agent host. */
  privateKey: Hex | string;
}

/** Parse a 32-byte private key given as hex with or without `0x` (secp256k1 or P-256). */
export function parsePrivateKeyHex(material: string): Hex {
  const trimmed = material.trim();
  const hex = trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed : `0x${trimmed}`;
  if (!isHex(hex) || hex.length !== 66) throw new Error("private key must be 32 bytes of hex");
  return hex as Hex;
}

export const parseSecp256k1PrivateKey = parsePrivateKeyHex;

export function createAttestor(opts: CreateAttestorOptions): Attestor {
  const account = privateKeyToAccount(parseSecp256k1PrivateKey(opts.privateKey));
  return {
    address: account.address,
    signAttestation(domain, message) {
      return account.signTypedData(attestationTypedData(domain, message));
    },
  };
}
