import type { PrismaClient } from "../../../generated/prisma/client.js";

export interface SigningKeyRecord {
  id: string;
  userId: string;
  algorithm: string; // e.g. "RSA-2048"
  certPem: string;
  chainPem: string;
  certSerial: string;
  certFingerprint: string;
  notBefore: Date;
  notAfter: Date;
  encryptedPrivateKey: Buffer;
  wrappedDek: Buffer;
  kekId: string;
  createdAt: Date;
  revokedAt: Date | null;
}

export interface SigningKeyRepository {
  create(record: SigningKeyRecord): Promise<void>;
  /** The user's current non-revoked key, if any. */
  findActiveByUserId(userId: string): Promise<SigningKeyRecord | null>;
  /** Marks all active keys for the user revoked; returns how many. */
  revokeActive(userId: string, when: Date): Promise<number>;
}

/** Postgres via Prisma. Inject your existing PrismaClient. */
export class PrismaSigningKeyRepository implements SigningKeyRepository {
  constructor(private readonly db: PrismaClient) {}

  async create(r: SigningKeyRecord): Promise<void> {
    await this.db.signingKey.create({
      data: {
        id: r.id,
        userId: r.userId,
        algorithm: r.algorithm,
        certPem: r.certPem,
        chainPem: r.chainPem,
        certSerial: r.certSerial,
        certFingerprint: r.certFingerprint,
        notBefore: r.notBefore,
        notAfter: r.notAfter,
        encryptedPrivateKey: r.encryptedPrivateKey,
        wrappedDek: r.wrappedDek,
        kekId: r.kekId,
        createdAt: r.createdAt,
        revokedAt: r.revokedAt,
      },
    });
  }

  async findActiveByUserId(userId: string): Promise<SigningKeyRecord | null> {
    const row = await this.db.signingKey.findFirst({
      where: { userId, revokedAt: null },
      orderBy: { createdAt: "desc" },
    });
    if (!row) return null;
    return {
      ...row,
      // Normalise Bytes columns (Uint8Array in some Prisma versions) to Buffer
      encryptedPrivateKey: Buffer.from(row.encryptedPrivateKey),
      wrappedDek: Buffer.from(row.wrappedDek),
    };
  }

  async revokeActive(userId: string, when: Date): Promise<number> {
    const res = await this.db.signingKey.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: when },
    });
    return res.count;
  }
}

/** For tests and local experiments. */
export class InMemorySigningKeyRepository implements SigningKeyRepository {
  readonly rows: SigningKeyRecord[] = [];

  async create(record: SigningKeyRecord) {
    this.rows.push({ ...record });
  }

  async findActiveByUserId(userId: string) {
    const active = this.rows
      .filter((r) => r.userId === userId && r.revokedAt === null)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    return active[0] ?? null;
  }

  async revokeActive(userId: string, when: Date) {
    let n = 0;
    for (const r of this.rows) {
      if (r.userId === userId && r.revokedAt === null) {
        r.revokedAt = when;
        n++;
      }
    }
    return n;
  }
}