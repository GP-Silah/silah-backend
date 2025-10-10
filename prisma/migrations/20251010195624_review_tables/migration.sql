-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateTable
CREATE TABLE "public"."Review" (
    "id" TEXT NOT NULL,
    "orderId" TEXT,
    "invoiceId" TEXT,
    "buyerId" TEXT,
    "supplierId" TEXT,
    "supplierRating" INTEGER NOT NULL DEFAULT 5,
    "writtenReviewOfSupplier" VARCHAR(150),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Review_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."ItemReview" (
    "id" SERIAL NOT NULL,
    "reviewId" TEXT NOT NULL,
    "orderItemId" INTEGER,
    "invoiceItemId" INTEGER,
    "buyerId" TEXT,
    "itemRating" INTEGER NOT NULL DEFAULT 5,
    "writtenReviewOfItem" VARCHAR(150),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ItemReview_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Review_orderId_key" ON "public"."Review"("orderId");

-- CreateIndex
CREATE UNIQUE INDEX "Review_invoiceId_key" ON "public"."Review"("invoiceId");

-- CreateIndex
CREATE UNIQUE INDEX "ItemReview_orderItemId_key" ON "public"."ItemReview"("orderItemId");

-- CreateIndex
CREATE UNIQUE INDEX "ItemReview_invoiceItemId_key" ON "public"."ItemReview"("invoiceItemId");

-- AddForeignKey
ALTER TABLE "public"."Review" ADD CONSTRAINT "Review_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "public"."Order"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Review" ADD CONSTRAINT "Review_invoiceId_fkey" FOREIGN KEY ("invoiceId") REFERENCES "public"."Invoice"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Review" ADD CONSTRAINT "Review_buyerId_fkey" FOREIGN KEY ("buyerId") REFERENCES "public"."Buyer"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Review" ADD CONSTRAINT "Review_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ItemReview" ADD CONSTRAINT "ItemReview_reviewId_fkey" FOREIGN KEY ("reviewId") REFERENCES "public"."Review"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ItemReview" ADD CONSTRAINT "ItemReview_orderItemId_fkey" FOREIGN KEY ("orderItemId") REFERENCES "public"."CartItem"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ItemReview" ADD CONSTRAINT "ItemReview_invoiceItemId_fkey" FOREIGN KEY ("invoiceItemId") REFERENCES "public"."InvoiceItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ItemReview" ADD CONSTRAINT "ItemReview_buyerId_fkey" FOREIGN KEY ("buyerId") REFERENCES "public"."Buyer"("id") ON DELETE SET NULL ON UPDATE CASCADE;
