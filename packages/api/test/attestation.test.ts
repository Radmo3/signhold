/**
 * On-chain enforcement (contracts/safe-guard): `POST /v1/attestations` and secp256k1 /
 * EIP-712 approvers.
 *
 * Properties under test: the service signs an `Attestation` only for a check whose verdict
 * is allow or escalate (never block), only for the exact Safe transaction the check decided
 * on, only for a plain call without gas refund; the attestor key is never an approver; an
 * `eip712` approval by a registered secp256k1 device is accepted off-chain only when bound to
 * the attestation issued for that audit id (one device signature, two verifiers).
 */
import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import {
  approvalTypedData,
  attestationTypedData,
  auditIdToBytes32,
  computeSafeTxHash,
  plainSafeTx,
  recoverAttestationSigner,
  signApproval,
  type SafeTransaction,
} from "@signhold/safe-guard";
import { ApproverRegistry, parseApproverKeysEnv, summarizeApprovals, summarizeAttestations } from "../src/approvals.js";
import { AttestationService, verifyAttestationRequest, parseAttestationRequest } from "../src/attestations.js";
import { InMemoryAuditStore } from "../src/audit.js";
import { createEd25519Signer, keyIdOf, loadEd25519PublicKey, verifyChain } from "../src/integrity.js";
import { createServer } from "../src/server.js";
import type { ServerOptions } from "../src/types.js";
import { FROM, FakeAdapter, FakeEngine, TO, intentId, requestBody, testPolicy } from "./fakes.js";

const AGENT_KEY = "agent-api-key";
const APPROVER_API_KEY = "approver-api-key";
const agentHeaders = { "x-api-key": AGENT_KEY };
const approverHeaders = { "x-api-key": APPROVER_API_KEY };
const GUARD = "0x9999999999999999999999999999999999999999";
const ZERO = "0x0000000000000000000000000000000000000000";

const attestorPk = generatePrivateKey();
const attestorAccount = privateKeyToAccount(attestorPk);
const device = privateKeyToAccount(generatePrivateKey()); // secp256k1 approver device
const stranger = privateKeyToAccount(generatePrivateKey());

async function build(opts: Partial<ServerOptions> & { verdict?: "allow" | "block" | "escalate"; now?: () => number; noAttestor?: boolean } = {}) {
  const { verdict = "escalate", now, noAttestor, ...rest } = opts;
  const signer = createEd25519Signer(generateKeyPairSync("ed25519").privateKey);
  const pk = loadEd25519PublicKey(signer.publicKeyPem);
  const audit = new InMemoryAuditStore({ signer });
  const app = await createServer({
    engine: new FakeEngine(verdict),
    adapters: { evm: new FakeAdapter("evm") },
    policies: new Map([[testPolicy.id, testPolicy]]),
    audit,
    apiKeys: [{ id: "agent", key: AGENT_KEY }, { id: "approver-device", key: APPROVER_API_KEY }],
    auditPublicKeys: new Map([[keyIdOf(pk), pk]]),
    approvers: [{ keyId: "ops-wallet", publicKey: device.address, type: "secp256k1" }],
    approvals: { ttlMs: 60_000, clockSkewMs: 5_000, now },
    attestor: noAttestor ? undefined : { privateKey: attestorPk, now },
    logger: false,
    rateLimit: false,
    env: "test",
    ...rest,
  });
  return { app, audit, auditPublicKeys: new Map([[keyIdOf(pk), pk]]) };
}

async function check(app: FastifyInstance, n = 1) {
  const body = requestBody();
  (body.intent as Record<string, unknown>).id = intentId(n);
  const res = await app.inject({ method: "POST", url: "/v1/check", payload: body, headers: agentHeaders });
  expect(res.statusCode).toBe(200);
  return res.json() as { decision: { verdict: string }; auditId: string; approval?: { challenge: string; expiresAt: string } };
}

/** The Safe transaction matching `requestBody()`'s intent: from = the Safe, to/value/data as audited. */
function safeTxFor(nonce = 7n): SafeTransaction {
  return plainSafeTx({ to: TO, value: 1_000_000_000_000_000_000n, data: "0xdeadbeef", nonce });
}

function attestationBody(auditId: string, over: Record<string, unknown> = {}, txOver: Partial<Record<keyof SafeTransaction, unknown>> = {}) {
  const tx = safeTxFor();
  return {
    auditId,
    safe: FROM,
    guard: GUARD,
    chainId: 1,
    safeTx: { ...Object.fromEntries(Object.entries(tx).map(([k, v]) => [k, typeof v === "bigint" ? v.toString() : v])), ...txOver },
    ...over,
  };
}

async function attest(app: FastifyInstance, body: unknown, headers: Record<string, string> = agentHeaders) {
  const res = await app.inject({ method: "POST", url: "/v1/attestations", payload: body, headers });
  return { res, json: res.json() as Record<string, unknown> };
}

describe("POST /v1/attestations", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("attests an escalate check for the exact Safe transaction with a signature the guard's domain accepts", async () => {
    const built = await build();
    app = built.app;
    const r = await check(app);
    const { res, json } = await attest(app, attestationBody(r.auditId));
    expect(res.statusCode).toBe(200);
    expect(json.verdict).toBe("escalate");
    expect(json.verdictCode).toBe(2);
    expect(json.attestor).toBe(attestorAccount.address);
    expect(json.safeTxHash).toBe(computeSafeTxHash(1, FROM, safeTxFor()));
    expect(json.auditIdBytes32).toBe(auditIdToBytes32(r.auditId));
    expect(Number(json.expiresAtUnix) * 1000).toBeGreaterThan(Date.now());
    // The signature verifies over the guard's EIP-712 domain for the named guard and chain only.
    const message = { safe: FROM, safeTxHash: json.safeTxHash as `0x${string}`, verdict: 2 as const, expiresAt: BigInt(json.expiresAtUnix as string), auditId: json.auditIdBytes32 as `0x${string}` };
    expect(await recoverAttestationSigner({ chainId: 1, guard: GUARD }, message, json.signature as `0x${string}`)).toBe(attestorAccount.address);
    expect(await recoverAttestationSigner({ chainId: 8453, guard: GUARD }, message, json.signature as `0x${string}`)).not.toBe(attestorAccount.address);
    expect(await recoverAttestationSigner({ chainId: 1, guard: TO }, message, json.signature as `0x${string}`)).not.toBe(attestorAccount.address);
    // Audited: an `attestation` record chained after the check, carrying what was signed.
    const rec = (await built.audit.get(json.attestationAuditId as string))!;
    expect(rec.type).toBe("attestation");
    expect(rec.attestation).toMatchObject({ checkAuditId: r.auditId, outcome: "attested", safe: FROM, guard: GUARD, chainId: "1", verdictCode: 2, signature: json.signature });
    const all = await built.audit.range(0, 10);
    expect(verifyChain(all, { publicKeys: built.auditPublicKeys, requireSignatures: true }).ok).toBe(true);
    const prov = summarizeAttestations(all);
    expect(prov).toHaveLength(1);
    expect(prov[0]).toMatchObject({ type: "attestation", checkAuditId: r.auditId, problems: [] });
    expect(summarizeApprovals(all)).toEqual([]); // attestation records are not approval records
  });

  it("attests an allow check with verdict code 1", async () => {
    ({ app } = await build({ verdict: "allow" }));
    const r = await check(app);
    const { res, json } = await attest(app, attestationBody(r.auditId));
    expect(res.statusCode).toBe(200);
    expect(json.verdict).toBe("allow");
    expect(json.verdictCode).toBe(1);
  });

  it("never attests a block decision (403) and records the refusal", async () => {
    const built = await build({ verdict: "block" });
    app = built.app;
    const r = await check(app);
    const { res, json } = await attest(app, attestationBody(r.auditId));
    expect(res.statusCode).toBe(403);
    expect(json.error).toBe("attestation_refused");
    expect(json.signature).toBeUndefined();
    const all = await built.audit.range(0, 10);
    const refused = all.find((x) => x.type === "attestation_refused")!;
    expect(refused.attestation?.refusalReason).toContain("blocked");
    expect(summarizeAttestations(all)[0]).toMatchObject({ type: "attestation_refused", outcome: "refused", problems: [] });
  });

  it("refuses any Safe transaction that is not byte-for-byte the audited intent", async () => {
    const built = await build();
    app = built.app;
    const r = await check(app);
    const cases: Array<[string, Record<string, unknown>, Partial<Record<keyof SafeTransaction, unknown>>]> = [
      ["different to", {}, { to: FROM }],
      ["different value", {}, { value: "1" }],
      ["different data", {}, { data: "0xdeadbeef00" }],
      ["different chain", { chainId: 8453 }, {}],
      ["safe is not intent.from", { safe: TO }, {}],
      ["delegatecall", {}, { operation: 1 }],
      ["gas refund", {}, { gasPrice: "1", refundReceiver: TO }],
      ["gas token", {}, { gasToken: TO }],
      ["hash cross-check mismatch", { safeTxHash: `0x${"ab".repeat(32)}` }, {}],
      ["unknown audit id", { auditId: "22222222-2222-4222-8222-222222222222" }, {}],
    ];
    for (const [name, over, txOver] of cases) {
      const { res, json } = await attest(app, attestationBody(r.auditId, over, txOver));
      expect(res.statusCode, name).toBe(403);
      expect(json.error, name).toBe("attestation_refused");
    }
    // The hash cross-check passes when it matches.
    const ok = await attest(app, attestationBody(r.auditId, { safeTxHash: computeSafeTxHash(1, FROM, safeTxFor()) }));
    expect(ok.res.statusCode).toBe(200);
    // Refusals are audited with reasons; nothing was signed for them.
    const refusals = (await built.audit.range(0, 100)).filter((x) => x.type === "attestation_refused");
    expect(refusals.length).toBe(cases.length - 1); // the unknown audit id has no record to attach to
    expect(refusals.every((x) => x.attestation?.signature === undefined)).toBe(true);
  });

  it("refuses an attestation record or approval record as the audit id, and a guard outside the allowlist", async () => {
    const built = await build({ attestor: { privateKey: attestorPk, guards: [GUARD] } });
    app = built.app;
    const r = await check(app);
    const first = await attest(app, attestationBody(r.auditId));
    expect(first.res.statusCode).toBe(200);
    const again = await attest(app, attestationBody(first.json.attestationAuditId as string));
    expect(again.res.statusCode).toBe(403);
    const otherGuard = await attest(app, attestationBody(r.auditId, { guard: TO }));
    expect(otherGuard.res.statusCode).toBe(403);
  });

  it("malformed bodies are 400 and leave no audit record; the route needs an API key; without an attestor it is 404", async () => {
    const built = await build();
    app = built.app;
    const r = await check(app);
    const before = (await built.audit.range(0, 100)).length;
    for (const bad of [
      {},
      attestationBody(r.auditId, { extra: 1 }),
      attestationBody(r.auditId, {}, { operation: 2 }),
      attestationBody(r.auditId, {}, { value: "-1" }),
      attestationBody(r.auditId, {}, { data: "0xabc" }),
      attestationBody(r.auditId, { safe: "nope" }),
      attestationBody(r.auditId, { chainId: -1 }),
    ]) {
      const { res } = await attest(app, bad);
      expect(res.statusCode).toBe(400);
    }
    expect((await built.audit.range(0, 100)).length).toBe(before);
    expect((await attest(app, attestationBody(r.auditId), {})).res.statusCode).toBe(401);
    await app.close();
    ({ app } = await build({ noAttestor: true }));
    const r2 = await check(app);
    expect((await attest(app, attestationBody(r2.auditId))).res.statusCode).toBe(404);
  });

  it("refuses to start when the attestor key is registered as an approver (key separation)", async () => {
    await expect(build({ approvers: [{ keyId: "attestor-as-approver", publicKey: attestorAccount.address, type: "secp256k1" }] })).rejects.toThrow(/server-held key/);
  });

  it("verifyAttestationRequest and the parser reject what the route rejects (unit)", () => {
    const parsed = parseAttestationRequest(attestationBody("11111111-1111-4111-8111-000000000001"));
    expect(verifyAttestationRequest(parsed, undefined, {})).toContain("unknown_audit");
    const svc = new AttestationService({ privateKey: attestorPk, guards: [GUARD] });
    expect(svc.address).toBe(attestorAccount.address);
    expect(verifyAttestationRequest(parseAttestationRequest(attestationBody("11111111-1111-4111-8111-000000000001", { guard: TO })), undefined, { guards: svc.guards })).toContain("guard_not_allowed");
    expect(() => new AttestationService({ privateKey: attestorPk, guards: ["bad"] })).toThrow();
    expect(() => new AttestationService({ privateKey: "0x12" })).toThrow();
    expect(() => parseAttestationRequest(attestationBody("not-a-uuid"))).toThrow();
  });
});

describe("secp256k1 approvers and eip712 approvals", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  function signedApproval(auditId: string, att: Record<string, unknown>, over: { signer?: typeof device; approvedAt?: Date; domain?: { chainId: number; guard: string }; safeTxHash?: string } = {}) {
    const approvedAt = over.approvedAt ?? new Date(Math.floor(Date.now() / 1000) * 1000);
    const message = { safe: FROM as `0x${string}`, safeTxHash: (over.safeTxHash ?? (att.safeTxHash as string)) as `0x${string}`, auditId: att.auditIdBytes32 as `0x${string}`, approvedAt: BigInt(Math.floor(approvedAt.getTime() / 1000)) };
    const domain = over.domain ?? { chainId: 1, guard: GUARD };
    return { message, domain, approvedAt, sign: async () => signApproval(over.signer ?? device, domain, message) };
  }

  async function approve(body: unknown, headers: Record<string, string> = approverHeaders) {
    const res = await app.inject({ method: "POST", url: "/v1/approvals", payload: body, headers });
    return { res, json: res.json() as Record<string, unknown> };
  }

  it("parses secp256k1 registry entries and keeps Ed25519 entries working", () => {
    const ed = generateKeyPairSync("ed25519");
    const edB64 = (ed.publicKey.export({ type: "spki", format: "der" }) as Buffer).subarray(-32).toString("base64");
    const parsed = parseApproverKeysEnv(`phone:${edB64}, wallet:${device.address}, hw:secp256k1:${stranger.address}, legacy:ed25519:${edB64}`);
    expect(parsed.map((p) => [p.keyId, p.type])).toEqual([["phone", undefined], ["wallet", "secp256k1"], ["hw", "secp256k1"], ["legacy", "ed25519"]]);
    expect(() => parseApproverKeysEnv("wallet:secp256k1:nope")).toThrow();
    expect(() => parseApproverKeysEnv("wallet:secp256k1:")).toThrow();
    const reg = new ApproverRegistry(parsed.filter((p) => p.keyId !== "legacy"));
    expect(reg.size).toBe(3);
    expect(reg.typeOf("wallet")).toBe("secp256k1");
    expect(reg.typeOf("phone")).toBe("ed25519");
    expect(reg.typeOf("nobody")).toBeUndefined();
    expect(reg.addressOf("wallet")).toBe(device.address);
    expect(() => new ApproverRegistry([{ keyId: "a", publicKey: device.address, type: "secp256k1" }, { keyId: "b", publicKey: device.address.toLowerCase(), type: "secp256k1" }])).toThrow(/same key/);
    expect(() => new ApproverRegistry([{ keyId: "a", publicKey: device.address, type: "secp256k1" }], { forbiddenAddresses: [device.address] })).toThrow(/server-held/);
  });

  it("one device signature approves off-chain (eip712) and is bound to the attested Safe transaction", async () => {
    const built = await build();
    app = built.app;
    const r = await check(app);
    expect(r.approval?.challenge).toBeDefined();
    const { json: att } = await attest(app, attestationBody(r.auditId));
    const a = signedApproval(r.auditId, att);
    const body = { auditId: r.auditId, keyId: "ops-wallet", signature: await a.sign(), approvedAt: a.approvedAt.toISOString(), scheme: "eip712" };
    // The agent's key cannot substitute for the device: wrong signer => 403 and the challenge is burned.
    const forged = signedApproval(r.auditId, att, { signer: stranger });
    const f = await approve({ ...body, signature: await forged.sign() }, agentHeaders);
    expect(f.res.statusCode).toBe(403);
    // Fresh check (the previous challenge was burned by the forged attempt).
    const r2 = await check(app, 2);
    const { json: att2 } = await attest(app, attestationBody(r2.auditId));
    const good = signedApproval(r2.auditId, att2);
    const sig = await good.sign();
    const ok = await approve({ auditId: r2.auditId, keyId: "ops-wallet", signature: sig, approvedAt: good.approvedAt.toISOString(), scheme: "eip712" });
    expect(ok.res.statusCode).toBe(200);
    expect(ok.json.verdict).toBe("allow");
    const st = await app.inject({ method: "GET", url: `/v1/approvals/${r2.auditId}`, headers: agentHeaders });
    expect(st.json().status).toBe("approved");
    expect(st.json().approvedBy).toBe("ops-wallet");
    const rec = (await built.audit.range(0, 100)).find((x) => x.type === "approval")!;
    expect(rec.approval?.scheme).toBe("eip712");
    expect(rec.principal?.approverKeyId).toBe("ops-wallet");
    // Replay is refused.
    expect((await approve({ auditId: r2.auditId, keyId: "ops-wallet", signature: sig, approvedAt: good.approvedAt.toISOString(), scheme: "eip712" })).res.statusCode).toBe(403);
  });

  it("an eip712 approval is refused when there is no attestation, when it is for another transaction, guard or chain, or when the scheme does not match the key", async () => {
    ({ app } = await build());
    // No attestation issued for this audit id: nothing to bind to.
    const r = await check(app, 1);
    const noAtt = signedApproval(r.auditId, { safeTxHash: computeSafeTxHash(1, FROM, safeTxFor()), auditIdBytes32: auditIdToBytes32(r.auditId) });
    expect((await approve({ auditId: r.auditId, keyId: "ops-wallet", signature: await noAtt.sign(), approvedAt: noAtt.approvedAt.toISOString(), scheme: "eip712" })).res.statusCode).toBe(403);

    const variants: Array<[string, (att: Record<string, unknown>, auditId: string) => ReturnType<typeof signedApproval>]> = [
      ["other safeTxHash", (att, id) => signedApproval(id, att, { safeTxHash: computeSafeTxHash(1, FROM, safeTxFor(8n)) })],
      ["other guard", (att, id) => signedApproval(id, att, { domain: { chainId: 1, guard: TO } })],
      ["other chain", (att, id) => signedApproval(id, att, { domain: { chainId: 8453, guard: GUARD } })],
      ["fractional approvedAt second", (att, id) => signedApproval(id, att, { approvedAt: new Date(Math.floor(Date.now() / 1000) * 1000 + 500) })],
    ];
    let n = 2;
    for (const [name, make] of variants) {
      const rr = await check(app, n++);
      const { json: att } = await attest(app, attestationBody(rr.auditId));
      const a = make(att, rr.auditId);
      const { res } = await approve({ auditId: rr.auditId, keyId: "ops-wallet", signature: await a.sign(), approvedAt: a.approvedAt.toISOString(), scheme: "eip712" });
      expect(res.statusCode, name).toBe(403);
    }
    // Scheme / key-type mismatch: an eip712 signature under an Ed25519 key id, or an Ed25519 body under a secp256k1 id.
    const rr = await check(app, n++);
    const { json: att } = await attest(app, attestationBody(rr.auditId));
    const a = signedApproval(rr.auditId, att);
    expect((await approve({ auditId: rr.auditId, keyId: "nobody", signature: await a.sign(), approvedAt: a.approvedAt.toISOString(), scheme: "eip712" })).res.statusCode).toBe(403);
    const rr2 = await check(app, n++);
    expect((await approve({ auditId: rr2.auditId, keyId: "ops-wallet", signature: "A".repeat(86) + "==", approvedAt: new Date().toISOString() })).res.statusCode).toBe(403);
    // Malformed eip712 bodies are 400.
    for (const bad of [{ scheme: "eip712", signature: "0x12" }, { scheme: "eip712", signature: "A".repeat(86) + "==" }, { scheme: "rsa", signature: `0x${"ab".repeat(65)}` }]) {
      const { res } = await approve({ auditId: rr2.auditId, keyId: "ops-wallet", approvedAt: new Date().toISOString(), ...bad });
      expect(res.statusCode).toBe(400);
    }
  });

  it("the attestation typed data and approval typed data the API uses match the guard's structs", () => {
    const att = attestationTypedData({ chainId: 1, guard: GUARD }, { safe: FROM, safeTxHash: `0x${"11".repeat(32)}`, verdict: 2, expiresAt: 1n, auditId: `0x${"22".repeat(32)}` });
    expect(att.primaryType).toBe("Attestation");
    expect(att.domain).toEqual({ name: "SignholdGuard", version: "1", chainId: 1n, verifyingContract: GUARD });
    const ap = approvalTypedData({ chainId: 1, guard: GUARD }, { safe: FROM, safeTxHash: `0x${"11".repeat(32)}`, auditId: `0x${"22".repeat(32)}`, approvedAt: 1n });
    expect(ap.types.Approval.map((f) => f.name)).toEqual(["safe", "safeTxHash", "auditId", "approvedAt"]);
  });
});
