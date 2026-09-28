/**
 * One-time CA bootstrap. Creates:
 *   root-ca.crt / root-ca.key            (10 yrs, signs ONLY the intermediate)
 *   intermediate-ca.crt / .key           (5 yrs, signs user certificates)
 *   ca-chain.pem                         (intermediate + root, for verification)
 *
 * Usage:
 *   ROOT_CA_PASSPHRASE=... INTERMEDIATE_CA_PASSPHRASE=... npx tsx src/modules/certAuthority/init-ca.ts
 */
import fs from "node:fs";
import path from "node:path";
import forge from "node-forge";
import {
  ORG,
  newKeyPair,
  randomSerial,
  subject,
  yearsFromNow,
  encryptPrivateKeyPem,
} from "./pki.js";

const { pki } = forge;

const OUT = process.env.CA_OUT_DIR ?? "./ca-out";
const rootPass = process.env.ROOT_CA_PASSPHRASE;
const intPass = process.env.INTERMEDIATE_CA_PASSPHRASE;

if (!rootPass || !intPass) {
  throw new Error("Set ROOT_CA_PASSPHRASE and INTERMEDIATE_CA_PASSPHRASE");
}
if (fs.existsSync(path.join(OUT, "root-ca.crt"))) {
  throw new Error(`CA already exists in ${OUT} - refusing to overwrite`);
}
fs.mkdirSync(OUT, { recursive: true });

const notBefore = new Date(Date.now() - 5 * 60 * 1000); // small clock-skew allowance

// ---------- Root CA (self-signed) ----------
const rootKeys = newKeyPair(4096);
const rootCert = pki.createCertificate();
rootCert.publicKey = rootKeys.forgePublic;
rootCert.serialNumber = randomSerial();
rootCert.validity.notBefore = notBefore;
rootCert.validity.notAfter = yearsFromNow(10);
const rootSubject = subject(`${ORG} Root CA`);
rootCert.setSubject(rootSubject);
rootCert.setIssuer(rootSubject);
rootCert.setExtensions([
  { name: "basicConstraints", cA: true, pathLenConstraint: 1, critical: true },
  { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
  { name: "subjectKeyIdentifier" },
]);
rootCert.sign(rootKeys.forgePrivate, forge.md.sha256.create());

// ---------- Intermediate CA (signed by root) ----------
const intKeys = newKeyPair(3072);
const intCert = pki.createCertificate();
intCert.publicKey = intKeys.forgePublic;
intCert.serialNumber = randomSerial();
intCert.validity.notBefore = notBefore;
intCert.validity.notAfter = yearsFromNow(5);
intCert.setSubject(subject(`${ORG} Signing CA`));
intCert.setIssuer(rootCert.subject.attributes);
intCert.setExtensions([
  { name: "basicConstraints", cA: true, pathLenConstraint: 0, critical: true },
  { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
  { name: "subjectKeyIdentifier" },
  {
    name: "authorityKeyIdentifier",
    keyIdentifier: rootCert.generateSubjectKeyIdentifier().getBytes(),
  },
]);
intCert.sign(rootKeys.forgePrivate, forge.md.sha256.create());

// ---------- Write files ----------
const rootPem = pki.certificateToPem(rootCert);
const intPem = pki.certificateToPem(intCert);

const write = (name: string, data: string, mode = 0o644) =>
  fs.writeFileSync(path.join(OUT, name), data, { mode });

write("root-ca.crt", rootPem);
write("root-ca.key", encryptPrivateKeyPem(rootKeys.privateKeyPem, rootPass), 0o600);
write("intermediate-ca.crt", intPem);
write("intermediate-ca.key", encryptPrivateKeyPem(intKeys.privateKeyPem, intPass), 0o600);
write("ca-chain.pem", intPem + rootPem);

console.log(`CA created in ${OUT}`);
console.log("Next: move root-ca.key OFFLINE (USB / password manager), and load");
console.log("intermediate-ca.key + its passphrase into your secrets manager.");