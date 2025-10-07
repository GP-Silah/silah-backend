/*
  Warnings:

  - You are about to drop the column `tapTokenId` on the `Card` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "public"."Card_tapTokenId_key";

-- AlterTable
ALTER TABLE "public"."Card" DROP COLUMN "tapTokenId";

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
