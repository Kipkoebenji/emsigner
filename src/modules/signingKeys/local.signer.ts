import crypto from "node:crypto";
import { openPrivateKey } from "./envelope.js";
import type { MasterKeyProvider } from "./masterKey.provider.js";
import type { SigningKeyRecord, SigningKeyRepository } from "./signingKey.repository.js";
import {
  DIGEST_LENGTHS,
  SignerError,
  type DigestAlgorithm,
  type Signer,
} from "./signer.types.js";

// DER-encoded DigestInfo prefixes (RFC 8017 section 9.2), prepended to the raw
// digest before PKCS#1 v1.5 signing.
const DIGEST_INFO_PREFIX: Record<DigestAlgorithm, Buffer> = {
  sha256: Buffer.from("3031300d060960864801650304020105000420", "hex"),
  sha384: Buffer.from("3041300d060960864801650304020205000430", "hex"),
  sha512: Buffer.from("3051300d060960864801650304020305000440", "hex"),
};

export class LocalSigner implements Signer {
  constructor(
    private readonly repo: SigningKeyRepository,
    private readonly masterKeys: MasterKeyProvider
  ) {}

  async sign(
    digest: Buffer,
    userId: string,
    digestAlgorithm: DigestAlgorithm = "sha256"
  ): Promise<Buffer> {
    if (digest.length !== DIGEST_LENGTHS[digestAlgorithm]) {
      throw new SignerError(
        "BAD_DIGEST",
        `Expected a ${DIGEST_LENGTHS[digestAlgorithm]}-byte ${digestAlgorithm} digest, got ${digest.length}`
      );
    }

    const record = await this.loadActiveKey(userId);

    let privateKey: crypto.KeyObject;
    try {
      privateKey = await openPrivateKey(
        record,
        { keyId: record.id, userId: record.userId },
        this.masterKeys
      );
    } catch {
      // Deliberately vague: don't leak whether it was the master key, the
      // binding to the user, or tampering.
      throw new SignerError("KEY_DECRYPT_FAILED", "Could not unlock signing key");
    }

    return crypto.privateEncrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      Buffer.concat([DIGEST_INFO_PREFIX[digestAlgorithm], digest])
    );
  }

  async getCertificateChain(userId: string): Promise<string> {
    return (await this.loadActiveKey(userId)).chainPem;
  }

  private async loadActiveKey(userId: string): Promise<SigningKeyRecord> {
    const record = await this.repo.findActiveByUserId(userId);
    if (!record) {
      throw new SignerError("NO_ACTIVE_KEY", "User has no active signing key");
    }
    if (record.notAfter.getTime() < Date.now()) {
      throw new SignerError("KEY_EXPIRED", "User's signing certificate has expired");
    }
    return record;
  }
}