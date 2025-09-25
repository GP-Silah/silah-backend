-- CreateEnum
CREATE TYPE "public"."GroupPurchaseDeadline" AS ENUM ('THREE_DAYS', 'FIVE_DAYS', 'SEVEN_DAYS');

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateTable
CREATE TABLE "public"."Product" (
    "id" TEXT NOT NULL,
    "supplierId" TEXT,
    "name" VARCHAR(60) NOT NULL,
    "description" VARCHAR(1000) NOT NULL,
    "price" DOUBLE PRECISION NOT NULL,
    "stock" INTEGER NOT NULL DEFAULT 0,
    "categoryId" INTEGER NOT NULL,
    "imagesFilesNames" TEXT[],
    "caseQuantity" INTEGER NOT NULL DEFAULT 1,
    "minOrderQuantity" INTEGER NOT NULL DEFAULT 1,
    "maxOrderQuantity" INTEGER,
    "allowGroupPurchase" BOOLEAN NOT NULL DEFAULT false,
    "minGroupOrderQuantity" INTEGER,
    "groupPurchasePrice" DOUBLE PRECISION,
    "groupPurchaseDuration" "public"."GroupPurchaseDeadline",
    "isPublished" BOOLEAN NOT NULL DEFAULT false,
    "wishlistCount" INTEGER NOT NULL DEFAULT 0,
    "avgRating" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "ratingsCount" INTEGER NOT NULL DEFAULT 0,
    "isDeleted" BOOLEAN NOT NULL DEFAULT false,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Product_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "public"."Product" ADD CONSTRAINT "Product_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Product" ADD CONSTRAINT "Product_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "public"."Category"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
