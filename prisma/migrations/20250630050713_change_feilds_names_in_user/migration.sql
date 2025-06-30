/*
  Warnings:

  - You are about to drop the column `agreedTerms` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "agreedTerms",
ADD COLUMN     "agreedToTerms" BOOLEAN NOT NULL DEFAULT true;
