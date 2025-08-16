-- CreateTable
CREATE TABLE "public"."Passkey" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "deviceType" TEXT NOT NULL DEFAULT 'unknown',
    "backedUp" BOOLEAN NOT NULL DEFAULT false,
    "transports" TEXT[],
    "name" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsed" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Passkey_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Passkey_credentialId_key" ON "public"."Passkey"("credentialId");

-- CreateIndex
CREATE INDEX "Passkey_userId_idx" ON "public"."Passkey"("userId");

-- CreateIndex
CREATE INDEX "Passkey_credentialId_idx" ON "public"."Passkey"("credentialId");

-- AddForeignKey
ALTER TABLE "public"."Passkey" ADD CONSTRAINT "Passkey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
