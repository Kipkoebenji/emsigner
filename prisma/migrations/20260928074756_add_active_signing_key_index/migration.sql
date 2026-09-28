/*
  Warnings:

  - You are about to drop the column `certificateUrl` on the `SigningKey` table. All the data in the column will be lost.
  - You are about to drop the column `isActive` on the `SigningKey` table. All the data in the column will be lost.
  - You are about to drop the column `keyId` on the `SigningKey` table. All the data in the column will be lost.
  - You are about to drop the column `publicKey` on the `SigningKey` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[certSerial]` on the table `SigningKey` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `certFingerprint` to the `SigningKey` table without a default value. This is not possible if the table is not empty.
  - Added the required column `certPem` to the `SigningKey` table without a default value. This is not possible if the table is not empty.
  - Added the required column `certSerial` to the `SigningKey` table without a default value. This is not possible if the table is not empty.
  - Added the required column `chainPem` to the `SigningKey` table without a default value. This is not possible if the table is not empty.
  - Added the required column `encryptedPrivateKey` to the `SigningKey` table without a default value. This is not possible if the table is not empty.
  - Added the required column `kekId` to the `SigningKey` table without a default value. This is not possible if the table is not empty.
  - Added the required column `notAfter` to the `SigningKey` table without a default value. This is not possible if the table is not empty.
  - Added the required column `notBefore` to the `SigningKey` table without a default value. This is not possible if the table is not empty.
  - Added the required column `wrappedDek` to the `SigningKey` table without a default value. This is not possible if the table is not empty.

*/
-- DropIndex
DROP INDEX "SigningKey_keyId_key";

-- AlterTable
ALTER TABLE "SigningKey" DROP COLUMN "certificateUrl",
DROP COLUMN "isActive",
DROP COLUMN "keyId",
DROP COLUMN "publicKey",
ADD COLUMN     "certFingerprint" TEXT NOT NULL,
ADD COLUMN     "certPem" TEXT NOT NULL,
ADD COLUMN     "certSerial" TEXT NOT NULL,
ADD COLUMN     "chainPem" TEXT NOT NULL,
ADD COLUMN     "encryptedPrivateKey" BYTEA NOT NULL,
ADD COLUMN     "kekId" TEXT NOT NULL,
ADD COLUMN     "notAfter" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "notBefore" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "wrappedDek" BYTEA NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "SigningKey_certSerial_key" ON "SigningKey"("certSerial");

-- CreateIndex
CREATE INDEX "SigningKey_userId_idx" ON "SigningKey"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "SigningKey_one_active_per_user"
ON "SigningKey"("userId")
WHERE "revokedAt" IS NULL;
