/*
  Warnings:

  - You are about to drop the column `groupPurchaseId` on the `PreInvoice` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[groupPurchaseBuyerId]` on the table `PreInvoice` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[offerId]` on the table `PreInvoice` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "public"."PreInvoice" DROP COLUMN "groupPurchaseId",
ADD COLUMN     "groupPurchaseBuyerId" TEXT,
ADD COLUMN     "offerId" TEXT;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateIndex
CREATE UNIQUE INDEX "PreInvoice_groupPurchaseBuyerId_key" ON "public"."PreInvoice"("groupPurchaseBuyerId");

-- CreateIndex
CREATE UNIQUE INDEX "PreInvoice_offerId_key" ON "public"."PreInvoice"("offerId");

-- AddForeignKey
ALTER TABLE "public"."PreInvoice" ADD CONSTRAINT "PreInvoice_groupPurchaseBuyerId_fkey" FOREIGN KEY ("groupPurchaseBuyerId") REFERENCES "public"."GroupPurchaseBuyer"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."PreInvoice" ADD CONSTRAINT "PreInvoice_offerId_fkey" FOREIGN KEY ("offerId") REFERENCES "public"."Offer"("id") ON DELETE SET NULL ON UPDATE CASCADE;
