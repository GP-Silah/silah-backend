/*
  Warnings:

  - You are about to drop the column `ratingCount` on the `Supplier` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "public"."Supplier" DROP COLUMN "ratingCount",
ADD COLUMN     "ratingsCount" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
