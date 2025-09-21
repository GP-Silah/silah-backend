/*
  Warnings:

  - You are about to drop the `SupplierCategory` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "public"."SupplierCategory" DROP CONSTRAINT "SupplierCategory_categoryId_fkey";

-- DropForeignKey
ALTER TABLE "public"."SupplierCategory" DROP CONSTRAINT "SupplierCategory_supplierId_fkey";

-- DropTable
DROP TABLE "public"."SupplierCategory";

-- CreateTable
CREATE TABLE "public"."SupplierSubscription" (
    "id" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "startDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endDate" TIMESTAMP(3) NOT NULL DEFAULT now() + interval '1 month',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SupplierSubscription_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."SupplierFavoriteCategory" (
    "supplierId" TEXT NOT NULL,
    "categoryId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SupplierFavoriteCategory_pkey" PRIMARY KEY ("supplierId","categoryId")
);

-- AddForeignKey
ALTER TABLE "public"."SupplierSubscription" ADD CONSTRAINT "SupplierSubscription_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."SupplierFavoriteCategory" ADD CONSTRAINT "SupplierFavoriteCategory_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."SupplierFavoriteCategory" ADD CONSTRAINT "SupplierFavoriteCategory_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "public"."Category"("id") ON DELETE CASCADE ON UPDATE CASCADE;
