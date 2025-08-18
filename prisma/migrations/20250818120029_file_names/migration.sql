/*
  Warnings:

  - You are about to drop the column `storeBannerUrl` on the `Supplier` table. All the data in the column will be lost.
  - You are about to drop the column `pfpUrl` on the `User` table. All the data in the column will be lost.

*/
-- CreateEnum
CREATE TYPE "ItemType" AS ENUM ('PRODUCT', 'SERVICE');

-- AlterTable
ALTER TABLE "Supplier" DROP COLUMN "storeBannerUrl",
ADD COLUMN     "storeBannerFileName" TEXT;

-- AlterTable
ALTER TABLE "User" DROP COLUMN "pfpUrl",
ADD COLUMN     "pfpFileName" TEXT;
