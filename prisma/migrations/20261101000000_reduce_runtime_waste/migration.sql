-- Use the expiry predicate's index instead of scanning all refresh tokens.
CREATE INDEX "RefreshToken_expiresAt_idx" ON "public"."RefreshToken"("expiresAt");

-- The corresponding unique indexes already support these same lookups.
-- Keep uniqueness and replay protection while avoiding duplicate index upkeep.
DROP INDEX "public"."Passkey_credentialId_idx";
DROP INDEX "public"."Challenge_challenge_idx";
