import crypto from "node:crypto";

/**
 * Wraps / unwraps per-user data keys (DEKs). The master key (KEK) lives
 * OUTSIDE Postgres. A KMS implementation maps directly onto this:
 *   wrap   -> KMS Encrypt   (aad -> EncryptionContext)
 *   unwrap -> KMS Decrypt
 */
export interface MasterKeyProvider {
  /** Id of the key used for NEW wraps. Stored next to each wrapped DEK. */
  readonly currentKeyId: string;
  wrap(dek: Buffer, aad: Buffer): Promise<{ kekId: string; wrapped: Buffer }>;
  unwrap(kekId: string, wrapped: Buffer, aad: Buffer): Promise<Buffer>;
}

const IV_LEN = 12;
const TAG_LEN = 16;

/**
 * Master keys from environment variables:
 *   KEK_CURRENT=v1
 *   KEK_V1=<base64 of 32 random bytes>      (openssl rand -base64 32)
 *   KEK_V2=...                              (add when rotating; keep old ones)
 */
export class LocalMasterKeyProvider implements MasterKeyProvider {
  constructor(
    private readonly keys: Record<string, Buffer>,
    readonly currentKeyId: string
  ) {
    if (!keys[currentKeyId]) {
      throw new Error(`Master key "${currentKeyId}" is not loaded`);
    }
    for (const [id, key] of Object.entries(keys)) {
      if (key.length !== 32) {
        throw new Error(`Master key "${id}" must be exactly 32 bytes`);
      }
    }
  }

  static fromEnv(env: NodeJS.ProcessEnv = process.env): LocalMasterKeyProvider {
    const current = env.KEK_CURRENT?.toLowerCase();
    if (!current) throw new Error("KEK_CURRENT is not set");

    const keys: Record<string, Buffer> = {};
    for (const [name, value] of Object.entries(env)) {
      const m = /^KEK_(?!CURRENT$)(.+)$/.exec(name);
      if (m && value) keys[m[1].toLowerCase()] = Buffer.from(value, "base64");
    }
    return new LocalMasterKeyProvider(keys, current);
  }

  async wrap(dek: Buffer, aad: Buffer) {
    const kek = this.keys[this.currentKeyId];
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv("aes-256-gcm", kek, iv);
    cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(dek), cipher.final()]);
    return {
      kekId: this.currentKeyId,
      wrapped: Buffer.concat([iv, cipher.getAuthTag(), ct]),
    };
  }

  async unwrap(kekId: string, wrapped: Buffer, aad: Buffer) {
    const kek = this.keys[kekId];
    if (!kek) throw new Error(`Master key "${kekId}" is not available`);
    const iv = wrapped.subarray(0, IV_LEN);
    const tag = wrapped.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ct = wrapped.subarray(IV_LEN + TAG_LEN);
    const decipher = crypto.createDecipheriv("aes-256-gcm", kek, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }
}