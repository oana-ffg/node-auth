-- The corresponding unique indexes already support these same lookups.
-- Keep uniqueness and replay protection while avoiding duplicate index upkeep.
DROP INDEX "public"."Passkey_credentialId_idx";
DROP INDEX "public"."Challenge_challenge_idx";
