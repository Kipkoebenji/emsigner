/**
 * End-to-end check using an in-memory repository (no database needed).
 * Requires the CA from step 3 to exist (init-ca.ts) and:
 *   INTERMEDIATE_CA_PASSPHRASE, KEK_CURRENT, KEK_V1
 *
 * Usage: npx tsx src/modules/signingKeys/verify-signing-keys.ts
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { LocalMasterKeyProvider } from "./masterKey.provider.js";
import { InMemorySigningKeyRepository } from "./signingKey.repository.js";
import { SigningKeyService } from "./signingKey.service.js";
import { LocalSigner } from "./local.signer.js";
import { SignerError } from "./signer.types.js";

async function rejectsWith(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: unknown) => e instanceof SignerError && e.code === code);
}

async function main() {
  const repo = new InMemorySigningKeyRepository();
  const masterKeys = LocalMasterKeyProvider.fromEnv();
  const keys = new SigningKeyService(repo, masterKeys);
  const signer = new LocalSigner(repo, masterKeys);

  // 1. Provision
  const info = await keys.provisionUserKey({
    id: "user-a",
    name: "Member A",
    email: "a@example.com",
  });
  assert.ok(!("privateKeyPem" in info), "info must not expose private key");
  const stored = repo.rows[0];
  assert.ok(
    !stored.encryptedPrivateKey.toString("latin1").includes("PRIVATE KEY"),
    "private key must not be stored in plaintext"
  );
  console.log("ok  provision: key stored encrypted, kek =", stored.kekId);

  // 2. Sign a digest and verify with the certificate's public key
  const data = Buffer.from("document bytes to sign");
  const digest = crypto.createHash("sha256").update(data).digest();
  const signature = await signer.sign(digest, "user-a");
  const chain = await signer.getCertificateChain("user-a");
  const userCert = new crypto.X509Certificate(chain.split(/(?=-----BEGIN CERTIFICATE-----)/)[0]);
  assert.equal(crypto.verify("sha256", data, userCert.publicKey, signature), true);
  assert.equal(
    crypto.verify("sha256", Buffer.from("tampered"), userCert.publicKey, signature),
    false
  );
  console.log("ok  sign: signature verifies against the user's certificate");

  // 3. Bad digest length
  await rejectsWith(signer.sign(Buffer.alloc(10), "user-a"), "BAD_DIGEST");
  console.log("ok  bad digest length rejected");

  // 4. Duplicate provisioning refused
  await assert.rejects(
    keys.provisionUserKey({ id: "user-a", name: "Member A", email: "a@example.com" })
  );
  console.log("ok  second active key refused");

  // 5. Ciphertext copied onto another user's row must not decrypt
  await repo.create({ ...stored, userId: "user-b", revokedAt: null });
  await rejectsWith(signer.sign(digest, "user-b"), "KEY_DECRYPT_FAILED");
  console.log("ok  ciphertext bound to its owner (cross-user copy fails)");

  // 6. Wrong master key must not decrypt
  const wrong = new LocalMasterKeyProvider(
    { [masterKeys.currentKeyId]: crypto.randomBytes(32) },
    masterKeys.currentKeyId
  );
  await rejectsWith(new LocalSigner(repo, wrong).sign(digest, "user-a"), "KEY_DECRYPT_FAILED");
  console.log("ok  wrong master key rejected");

  // 7. Expired certificate
  const expiredRepo = new InMemorySigningKeyRepository();
  await expiredRepo.create({ ...stored, notAfter: new Date(Date.now() - 1000) });
  await rejectsWith(new LocalSigner(expiredRepo, masterKeys).sign(digest, "user-a"), "KEY_EXPIRED");
  console.log("ok  expired certificate rejected");

  // 8. Revocation
  assert.equal(await keys.revokeUserKey("user-a"), true);
  await rejectsWith(signer.sign(digest, "user-a"), "NO_ACTIVE_KEY");
  await rejectsWith(signer.sign(digest, "nobody"), "NO_ACTIVE_KEY");
  console.log("ok  revoked / unknown user cannot sign");

  console.log("\nAll checks passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});