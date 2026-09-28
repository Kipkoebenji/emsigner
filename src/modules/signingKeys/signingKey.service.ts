import crypto from "node:crypto";
import { issueUserCertificate } from "../certAuthority/ca.service.js";
import { sealPrivateKey } from "./envelope.js";
import type { MasterKeyProvider } from "./masterKey.provider.js";
import type { SigningKeyRepository } from "./signingKey.repository.js";

export interface ProvisionUserInput {
  id: string; // your User.id
  name: string;
  email: string;
}

/** Everything about a key that is safe to return to callers. No private material. */
export interface SigningKeyInfo {
  id: string;
  userId: string;
  algorithm: string;
  certSerial: string;
  certFingerprint: string;
  notBefore: Date;
  notAfter: Date;
}

export class SigningKeyService {
  constructor(
    private readonly repo: SigningKeyRepository,
    private readonly masterKeys: MasterKeyProvider
  ) {}

  /**
   * Call right after a user is created. Issues a certificate (step 3),
   * envelope-encrypts the private key, and stores it. The plaintext private
   * key is never returned or persisted.
   */
  async provisionUserKey(user: ProvisionUserInput): Promise<SigningKeyInfo> {
    if (await this.repo.findActiveByUserId(user.id)) {
      throw new Error("User already has an active signing key; revoke it first");
    }

    const issued = issueUserCertificate({ name: user.name, email: user.email });
    const keyId = crypto.randomUUID();

    const sealed = await sealPrivateKey(
      issued.privateKeyPem,
      { keyId, userId: user.id },
      this.masterKeys
    );

    const record = {
      id: keyId,
      userId: user.id,
      algorithm: "RSA-2048",
      certPem: issued.certPem,
      chainPem: issued.chainPem,
      certSerial: issued.serialNumber,
      certFingerprint: issued.fingerprintSha256,
      notBefore: issued.notBefore,
      notAfter: issued.notAfter,
      encryptedPrivateKey: sealed.encryptedPrivateKey,
      wrappedDek: sealed.wrappedDek,
      kekId: sealed.kekId,
      createdAt: new Date(),
      revokedAt: null,
    };
    await this.repo.create(record);

    return toInfo(record);
  }

  /** Revokes the user's active key. Signing is refused immediately afterwards. */
  async revokeUserKey(userId: string): Promise<boolean> {
    return (await this.repo.revokeActive(userId, new Date())) > 0;
  }

  async getActiveKeyInfo(userId: string): Promise<SigningKeyInfo | null> {
    const rec = await this.repo.findActiveByUserId(userId);
    return rec ? toInfo(rec) : null;
  }
}

function toInfo(r: {
  id: string;
  userId: string;
  algorithm: string;
  certSerial: string;
  certFingerprint: string;
  notBefore: Date;
  notAfter: Date;
}): SigningKeyInfo {
  return {
    id: r.id,
    userId: r.userId,
    algorithm: r.algorithm,
    certSerial: r.certSerial,
    certFingerprint: r.certFingerprint,
    notBefore: r.notBefore,
    notAfter: r.notAfter,
  };
}