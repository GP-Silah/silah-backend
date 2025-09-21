/*
  Warnings:

  - You are about to drop the column `isActive` on the `Supplier` table. All the data in the column will be lost.
  - You are about to drop the column `isSubscribed` on the `Supplier` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "public"."Supplier" DROP COLUMN "isActive",
DROP COLUMN "isSubscribed",
ADD COLUMN     "status" "public"."SupplierStatus" NOT NULL DEFAULT 'ACTIVE';
