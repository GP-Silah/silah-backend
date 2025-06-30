/*
  Warnings:

  - You are about to drop the column `business_name` on the `User` table. All the data in the column will be lost.
  - Added the required column `businessName` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "business_name",
ADD COLUMN     "businessName" TEXT NOT NULL;
