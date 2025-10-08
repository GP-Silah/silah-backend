/*
  Warnings:

  - You are about to drop the column `checkoutId` on the `Order` table. All the data in the column will be lost.
  - Added the required column `tapChargeId` to the `Order` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "public"."PreInvoiceStatus" AS ENUM ('PENDING', 'FAILED', 'SUCCESSFUL');

-- CreateEnum
CREATE TYPE "public"."InvoiceStatus" AS ENUM ('PENDING', 'ACCEPTED', 'REJECTED', 'FULLY_PAID', 'PARTIALLY_PAID');

-- CreateEnum
CREATE TYPE "public"."InvoiceTermsOfPayment" AS ENUM ('PARTIAL', 'FULL');

-- AlterTable
ALTER TABLE "public"."Order" DROP COLUMN "checkoutId",
ADD COLUMN     "tapChargeId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateTable
CREATE TABLE "public"."Invoice" (
    "id" TEXT NOT NULL,
    "buyerId" TEXT,
    "supplierId" TEXT,
    "deliveryDate" TIMESTAMP(3) NOT NULL,
    "termsOfPayment" "public"."InvoiceTermsOfPayment" NOT NULL,
    "upfrontAmount" DOUBLE PRECISION,
    "tapChargeIdForUpfront" TEXT,
    "tapChargeId" TEXT,
    "uponDeliveryAmount" DOUBLE PRECISION NOT NULL,
    "amount" DOUBLE PRECISION NOT NULL,
    "notesAndTerms" TEXT,
    "status" "public"."InvoiceStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Invoice_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."InvoiceItem" (
    "id" SERIAL NOT NULL,
    "invoiceId" TEXT NOT NULL,
    "name" VARCHAR(60) NOT NULL,
    "description" VARCHAR(100) NOT NULL,
    "agreedDetails" VARCHAR(100) NOT NULL,
    "quantity" INTEGER NOT NULL,
    "unitPrice" DOUBLE PRECISION NOT NULL,
    "priceBasedQuantity" DOUBLE PRECISION NOT NULL,
    "relatedServiceId" TEXT,
    "relatedProductId" TEXT,

    CONSTRAINT "InvoiceItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."PreInvoice" (
    "id" TEXT NOT NULL,
    "invoiceId" TEXT,
    "groupPurchaseId" TEXT,
    "buyerId" TEXT,
    "supplierId" TEXT,
    "productId" TEXT,
    "amount" DOUBLE PRECISION NOT NULL,
    "status" "public"."PreInvoiceStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PreInvoice_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PreInvoice_invoiceId_key" ON "public"."PreInvoice"("invoiceId");

-- AddForeignKey
ALTER TABLE "public"."Invoice" ADD CONSTRAINT "Invoice_buyerId_fkey" FOREIGN KEY ("buyerId") REFERENCES "public"."Buyer"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Invoice" ADD CONSTRAINT "Invoice_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."InvoiceItem" ADD CONSTRAINT "InvoiceItem_invoiceId_fkey" FOREIGN KEY ("invoiceId") REFERENCES "public"."Invoice"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."InvoiceItem" ADD CONSTRAINT "InvoiceItem_relatedServiceId_fkey" FOREIGN KEY ("relatedServiceId") REFERENCES "public"."Service"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."InvoiceItem" ADD CONSTRAINT "InvoiceItem_relatedProductId_fkey" FOREIGN KEY ("relatedProductId") REFERENCES "public"."Product"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."PreInvoice" ADD CONSTRAINT "PreInvoice_invoiceId_fkey" FOREIGN KEY ("invoiceId") REFERENCES "public"."Invoice"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."PreInvoice" ADD CONSTRAINT "PreInvoice_buyerId_fkey" FOREIGN KEY ("buyerId") REFERENCES "public"."Buyer"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."PreInvoice" ADD CONSTRAINT "PreInvoice_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."PreInvoice" ADD CONSTRAINT "PreInvoice_productId_fkey" FOREIGN KEY ("productId") REFERENCES "public"."Product"("id") ON DELETE SET NULL ON UPDATE CASCADE;
