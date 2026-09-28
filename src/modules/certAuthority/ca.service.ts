import fs from "node:fs";
import path from "node:path";
import forge from "node-forge";
import {
  newKeyPair,
  randomSerial,
  subject,
  yearsFromNow,
  loadEncryptedPrivateKey,
  sha256Fingerprint,
} from "./pki.js";

const { pki } = forge;

export interface UserIdentity {
  name: string;
  email: string;
}

export interface IssuedCertificate {
  certPem: string;
  chainPem: string; // user cert + intermediate (what you embed in the PKCS#7)
  privateKeyPem: string; // PLAIN - encrypt it before storing (step 4), never log it
  serialNumber: string;
  fingerprintSha256: string;
  notBefore: Date;
  notAfter: Date;
}

// Adobe's OID for "PDF signing" extended key usage
const ADOBE_PDF_SIGNING_EKU = "1.2.840.113583.1.1.5";

function loadIntermediate() {
  const dir = process.env.CA_OUT_DIR ?? "./ca-out";
  const pass = process.env.INTERMEDIATE_CA_PASSPHRASE;
  if (!pass) throw new Error("INTERMEDIATE_CA_PASSPHRASE is not set");

  // In production, read these from your secrets manager instead of disk.
  const certPem = fs.readFileSync(
    path.join(dir, "intermediate-ca.crt"),
    "utf8",
  );
  const keyPem = fs.readFileSync(path.join(dir, "intermediate-ca.key"), "utf8");

  return {
    cert: pki.certificateFromPem(certPem),
    certPem,
    key: loadEncryptedPrivateKey(keyPem, pass),
  };
}

export function issueUserCertificate(user: UserIdentity): IssuedCertificate {
  const intermediate = loadIntermediate();
  const keys = newKeyPair(2048);

  const cert = pki.createCertificate();
  cert.publicKey = keys.forgePublic;
  cert.serialNumber = randomSerial();
  cert.validity.notBefore = new Date(Date.now() - 5 * 60 * 1000);
  cert.validity.notAfter = new Date(
    Math.min(
      yearsFromNow(2).getTime(),
      intermediate.cert.validity.notAfter.getTime(),
    ),
  );

  cert.setSubject(
    subject(user.name, [{ name: "emailAddress", value: user.email }]),
  );
  cert.setIssuer(intermediate.cert.subject.attributes);

  cert.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "keyUsage",
      digitalSignature: true,
      nonRepudiation: true, // a.k.a. contentCommitment - required for document signing
      critical: true,
    },
    {
      name: "extKeyUsage",
      emailProtection: true,
      [ADOBE_PDF_SIGNING_EKU]: true,
    },
    { name: "subjectKeyIdentifier" },
    {
      name: "authorityKeyIdentifier",
      keyIdentifier: intermediate.cert
        .generateSubjectKeyIdentifier()
        .getBytes(),
    },
    { name: "subjectAltName", altNames: [{ type: 1, value: user.email }] },
  ]);

  cert.sign(intermediate.key, forge.md.sha256.create());

  const certPem = pki.certificateToPem(cert);
  return {
    certPem,
    chainPem: certPem + intermediate.certPem,
    privateKeyPem: keys.privateKeyPem,
    serialNumber: cert.serialNumber,
    fingerprintSha256: sha256Fingerprint(cert),
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter,
  };
}
