import crypto from "node:crypto";
import forge from "node-forge";

const { pki } = forge;

export const ORG = process.env.CA_ORG ?? "My Organization";
export const COUNTRY = process.env.CA_COUNTRY ?? "KE";

/** Fast keygen via Node's native crypto, converted to node-forge key objects. */
export function newKeyPair(bits: number) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: bits,
  });
  const privateKeyPem = privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;
  const publicKeyPem = publicKey.export({
    type: "spki",
    format: "pem",
  }) as string;
  return {
    privateKeyPem,
    forgePrivate: pki.privateKeyFromPem(privateKeyPem),
    forgePublic: pki.publicKeyFromPem(publicKeyPem),
  };
}

/** 128-bit encoded serial with 120 random bits. The leading "01" keeps it positive. */
export function randomSerial(): string {
  return "01" + crypto.randomBytes(15).toString("hex");
}

export function subject(
  commonName: string,
  extra: forge.pki.CertificateField[] = [],
) {
  return [
    { name: "commonName", value: commonName },
    { name: "organizationName", value: ORG },
    { name: "countryName", value: COUNTRY },
    ...extra,
  ];
}

export function yearsFromNow(years: number): Date {
  const d = new Date();
  d.setFullYear(d.getFullYear() + years);
  return d;
}

/** Encrypt a PKCS#8 private key PEM with a passphrase (AES-256). */
export function encryptPrivateKeyPem(
  privateKeyPem: string,
  passphrase: string,
): string {
  return crypto
    .createPrivateKey(privateKeyPem)
    .export({
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase,
    }) as string;
}

/** Load a passphrase-protected PKCS#8 PEM into a node-forge private key. */
export function loadEncryptedPrivateKey(
  encryptedPem: string,
  passphrase: string,
) {
  const key = crypto.createPrivateKey({ key: encryptedPem, passphrase });
  return pki.privateKeyFromPem(
    key.export({ type: "pkcs8", format: "pem" }) as string,
  );
}

export function sha256Fingerprint(cert: forge.pki.Certificate): string {
  const der = forge.asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
  return crypto
    .createHash("sha256")
    .update(Buffer.from(der, "binary"))
    .digest("hex");
}
