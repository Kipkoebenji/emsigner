/**
 * The ONLY thing the rest of the app (PDF signing engine, controllers) should
 * depend on. Today it is backed by LocalSigner (envelope-encrypted keys in
 * Postgres). Later it can be backed by KMS / an HSM without touching callers.
 */

export type DigestAlgorithm = "sha256" | "sha384" | "sha512";

export const DIGEST_LENGTHS: Record<DigestAlgorithm, number> = {
  sha256: 32,
  sha384: 48,
  sha512: 64,
};

export interface Signer {
  /**
   * Signs a PRE-COMPUTED digest with the user's private key.
   * Returns the raw signature bytes (RSA PKCS#1 v1.5).
   * The private key never leaves the implementation.
   */
  sign(
    digest: Buffer,
    userId: string,
    digestAlgorithm?: DigestAlgorithm
  ): Promise<Buffer>;

  /** PEM chain (user cert + intermediate) to embed in the PKCS#7. */
  getCertificateChain(userId: string): Promise<string>;
}

export type SignerErrorCode =
  | "NO_ACTIVE_KEY"
  | "KEY_EXPIRED"
  | "BAD_DIGEST"
  | "KEY_DECRYPT_FAILED";

export class SignerError extends Error {
  constructor(
    public readonly code: SignerErrorCode,
    message: string
  ) {
    super(message);
    this.name = "SignerError";
  }
}