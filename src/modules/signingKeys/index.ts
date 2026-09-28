import type { PrismaClient } from "../../../generated/prisma/client.js";
import { LocalSigner } from "./local.signer.js";
import { LocalMasterKeyProvider } from "./masterKey.provider.js";
import { PrismaSigningKeyRepository } from "./signingKey.repository.js";
import { SigningKeyService } from "./signingKey.service.js";
import type { Signer } from "./signer.types.js";

export * from "./signer.types.js";
export * from "./masterKey.provider.js";
export * from "./signingKey.repository.js";
export { SigningKeyService } from "./signingKey.service.js";
export type { ProvisionUserInput, SigningKeyInfo } from "./signingKey.service.js";
export { LocalSigner } from "./local.signer.js";

/**
 * Default wiring. Build this once at startup and pass `signer` / `keys` around.
 * To move to KMS later: write a KmsSigner implementing `Signer` and a
 * KmsMasterKeyProvider (or skip envelope encryption entirely) and change
 * only this function.
 */
export function createSigningKeys(db: PrismaClient): {
  keys: SigningKeyService;
  signer: Signer;
} {
  const repo = new PrismaSigningKeyRepository(db);
  const masterKeys = LocalMasterKeyProvider.fromEnv();
  return {
    keys: new SigningKeyService(repo, masterKeys),
    signer: new LocalSigner(repo, masterKeys),
  };
}