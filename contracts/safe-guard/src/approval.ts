/**
 * Approver-device signing of EIP-712 `Approval`s, for secp256k1 devices (any viem account:
 * a private key, a hardware wallet, a WalletConnect session) and for P-256 devices
 * (passkeys / Secure Enclave class keys; here backed by `@noble/curves` for ops laptops and tests).
 *
 * The private key never leaves the device. These helpers run ON the device.
 */
import { p256 } from "@noble/curves/nist";
import { bytesToHex, hashTypedData, hexToBytes, keccak256, encodeAbiParameters, type Address, type Hex } from "viem";
import { approvalTypedData, type ApprovalMessage, type GuardDomainInput } from "./typedData.js";

/** The subset of a viem `Account` an approver device needs: an address and `signTypedData`. */
export interface TypedDataSigner {
  readonly address: Address;
  signTypedData(typedData: ReturnType<typeof approvalTypedData>): Promise<Hex>;
}

/** secp256k1 approval: a 65-byte `r || s || v` signature the guard verifies with `ECDSA.recover`. */
export async function signApproval(signer: TypedDataSigner, domain: GuardDomainInput, message: ApprovalMessage): Promise<Hex> {
  return signer.signTypedData(approvalTypedData(domain, message));
}

// ---- P-256 (secp256r1) ----

export interface P256PublicKey {
  qx: Hex;
  qy: Hex;
}

export interface P256Signature {
  r: Hex;
  s: Hex;
}

/** The id under which the guard registers a P-256 key: `keccak256(abi.encode(qx, qy))`. */
export function p256ApproverId(key: P256PublicKey): Hex {
  return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [key.qx, key.qy]));
}

export function p256PublicKeyFromPrivate(privateKey: Uint8Array | Hex): P256PublicKey {
  const priv = typeof privateKey === "string" ? hexToBytes(privateKey) : privateKey;
  const pub = p256.getPublicKey(priv, false); // 0x04 || x || y
  return { qx: bytesToHex(pub.slice(1, 33)), qy: bytesToHex(pub.slice(33, 65)) };
}

/** Split an uncompressed SEC1 public key (`0x04 || x || y`) into coordinates. */
export function p256PublicKeyFromUncompressed(pub: Uint8Array | Hex): P256PublicKey {
  const bytes = typeof pub === "string" ? hexToBytes(pub) : pub;
  if (bytes.length !== 65 || bytes[0] !== 0x04) throw new TypeError("expected a 65-byte uncompressed P-256 public key");
  return { qx: bytesToHex(bytes.slice(1, 33)), qy: bytesToHex(bytes.slice(33, 65)) };
}

export function generateP256PrivateKey(): Uint8Array {
  return p256.utils.randomPrivateKey();
}

/**
 * P-256 approval over the raw EIP-712 digest (no extra hashing: RIP-7212 takes the hash as input).
 * `s` is normalised to the lower half of the curve order, which the guard requires.
 */
export function signApprovalP256(privateKey: Uint8Array | Hex, domain: GuardDomainInput, message: ApprovalMessage): P256Signature {
  const priv = typeof privateKey === "string" ? hexToBytes(privateKey) : privateKey;
  const digest = hexToBytes(hashTypedData(approvalTypedData(domain, message)));
  const sig = p256.sign(digest, priv, { prehash: false, lowS: true });
  return { r: `0x${sig.r.toString(16).padStart(64, "0")}`, s: `0x${sig.s.toString(16).padStart(64, "0")}` };
}

/** Local verification of a P-256 approval signature (what the precompile will compute). Never throws. */
export function verifyApprovalP256(key: P256PublicKey, signature: P256Signature, domain: GuardDomainInput, message: ApprovalMessage): boolean {
  try {
    const digest = hexToBytes(hashTypedData(approvalTypedData(domain, message)));
    const pub = new Uint8Array([0x04, ...hexToBytes(key.qx), ...hexToBytes(key.qy)]);
    const compact = new Uint8Array([...hexToBytes(signature.r), ...hexToBytes(signature.s)]); // r || s, 64 bytes
    if (compact.length !== 64) return false;
    return p256.verify(compact, digest, pub, { prehash: false, lowS: true });
  } catch {
    return false;
  }
}
