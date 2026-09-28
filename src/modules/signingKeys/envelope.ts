import crypto from "node:crypto";
import type { MasterKeyProvider } from "./masterKey.provider.js";

/**
 * Envelope encryption:
 *   private key --AES-256-GCM(DEK)--> encryptedPrivateKey
 *   DEK         --master key--------> wrappedDek
 *
 * Both blobs are bound (via GCM additional authenticated data) to the key
 * record id AND the user id, so copying one user's ciphertext onto another
 * user's row makes decryption fail instead of silently signing as them.
 */

const FORMAT_VERSION = 1;
const IV_LEN = 12;
const TAG_LEN = 16;

export interface EnvelopeContext {
  keyId: string;
  userId: string;
}

export interface SealedPrivateKey {
  encryptedPrivateKey: Buffer; // version(1) | iv(12) | tag(16) | ciphertext
  wrappedDek: Buffer;
  kekId: string;
}

const keyAad = (c: EnvelopeContext) =>
  Buffer.from(`signing-key:v${FORMAT_VERSION}:${c.keyId}:${c.userId}`);
const dekAad = (c: EnvelopeContext) =>
  Buffer.from(`signing-dek:v${FORMAT_VERSION}:${c.keyId}:${c.userId}`);

export async function sealPrivateKey(
  privateKeyPem: string,
  ctx: EnvelopeContext,
  masterKeys: MasterKeyProvider
): Promise<SealedPrivateKey> {
  const dek = crypto.randomBytes(32);
  try {
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
    cipher.setAAD(keyAad(ctx));
    const ct = Buffer.concat([cipher.update(privateKeyPem, "utf8"), cipher.final()]);
    const encryptedPrivateKey = Buffer.concat([
      Buffer.from([FORMAT_VERSION]),
      iv,
      cipher.getAuthTag(),
      ct,
    ]);

    const { kekId, wrapped } = await masterKeys.wrap(dek, dekAad(ctx));
    return { encryptedPrivateKey, wrappedDek: wrapped, kekId };
  } finally {
    dek.fill(0);
  }
}

/** Decrypts into a KeyObject. Plaintext buffers are zeroed as soon as possible. */
export async function openPrivateKey(
  sealed: SealedPrivateKey,
  ctx: EnvelopeContext,
  masterKeys: MasterKeyProvider
): Promise<crypto.KeyObject> {
  const dek = await masterKeys.unwrap(sealed.kekId, sealed.wrappedDek, dekAad(ctx));
  try {
    const blob = sealed.encryptedPrivateKey;
    if (blob[0] !== FORMAT_VERSION) {
      throw new Error(`Unsupported key format version ${blob[0]}`);
    }
    const iv = blob.subarray(1, 1 + IV_LEN);
    const tag = blob.subarray(1 + IV_LEN, 1 + IV_LEN + TAG_LEN);
    const ct = blob.subarray(1 + IV_LEN + TAG_LEN);

    const decipher = crypto.createDecipheriv("aes-256-gcm", dek, iv);
    decipher.setAAD(keyAad(ctx));
    decipher.setAuthTag(tag);
    const pem = Buffer.concat([decipher.update(ct), decipher.final()]);
    try {
      return crypto.createPrivateKey({ key: pem, format: "pem" });
    } finally {
      pem.fill(0);
    }
  } finally {
    dek.fill(0);
  }
}