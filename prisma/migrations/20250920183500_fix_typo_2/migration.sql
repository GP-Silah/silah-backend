/*
  Warnings:

  - You are about to drop the column `usedFreeTrial` on the `Supplier` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "public"."Supplier" DROP COLUMN "usedFreeTrial",
ADD COLUMN     "usedFreeTrail" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
