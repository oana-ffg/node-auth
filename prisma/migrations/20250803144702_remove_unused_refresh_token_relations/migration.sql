/*
  Warnings:

  - You are about to drop the column `replacedById` on the `RefreshToken` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "public"."RefreshToken" DROP CONSTRAINT "RefreshToken_replacedById_fkey";

-- AlterTable
ALTER TABLE "public"."RefreshToken" DROP COLUMN "replacedById";
