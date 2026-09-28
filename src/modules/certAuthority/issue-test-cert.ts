/**
 * Issues a throwaway user cert and verifies it against the root.
 * Usage: INTERMEDIATE_CA_PASSPHRASE=... npx tsx src/modules/certAuthority/issue-test-cert.ts
 */
import fs from "node:fs";
import path from "node:path";
import forge from "node-forge";
import { issueUserCertificate } from "./ca.service.js";

const { pki } = forge;
const dir = process.env.CA_OUT_DIR ?? "./ca-out";
const testDir = path.join(dir, "test");
fs.mkdirSync(testDir, { recursive: true });

const issued = issueUserCertificate({ name: "Test Member", email: "member@example.com" });

fs.writeFileSync(path.join(testDir, "user.crt"), issued.certPem);
fs.writeFileSync(path.join(testDir, "user.key"), issued.privateKeyPem, { mode: 0o600 });
fs.writeFileSync(path.join(testDir, "user-chain.pem"), issued.chainPem);

// Verify: user cert -> intermediate -> trusted root
const rootPem = fs.readFileSync(path.join(dir, "root-ca.crt"), "utf8");
const store = pki.createCaStore([rootPem]);
const chain = issued.chainPem
  .split(/(?=-----BEGIN CERTIFICATE-----)/)
  .filter(Boolean)
  .map((p) => pki.certificateFromPem(p));

try {
  pki.verifyCertificateChain(store, chain);
  console.log("Chain verified OK");
} catch (e) {
  console.error("Chain verification FAILED:", e);
  process.exit(1);
}
console.log("Serial:     ", issued.serialNumber);
console.log("Fingerprint:", issued.fingerprintSha256);
console.log("Valid until:", issued.notAfter.toISOString());