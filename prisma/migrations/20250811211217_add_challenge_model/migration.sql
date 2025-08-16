-- CreateTable
CREATE TABLE "public"."Challenge" (
    "id" TEXT NOT NULL,
    "challenge" TEXT NOT NULL,
    "userId" TEXT,
    "email" TEXT,
    "type" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Challenge_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Challenge_challenge_key" ON "public"."Challenge"("challenge");

-- CreateIndex
CREATE INDEX "Challenge_challenge_idx" ON "public"."Challenge"("challenge");

-- CreateIndex
CREATE INDEX "Challenge_expiresAt_idx" ON "public"."Challenge"("expiresAt");
