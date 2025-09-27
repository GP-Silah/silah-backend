-- CreateEnum
CREATE TYPE "public"."ServiceAvailability" AS ENUM ('ALWAYS', 'WEEKDAYS', 'WEEKENDS', 'APPOINTMENT');

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateTable
CREATE TABLE "public"."Service" (
    "id" TEXT NOT NULL,
    "supplierId" TEXT,
    "name" VARCHAR(60) NOT NULL,
    "description" VARCHAR(1000) NOT NULL,
    "price" DOUBLE PRECISION NOT NULL,
    "isPriceNegotiable" BOOLEAN NOT NULL DEFAULT false,
    "categoryId" INTEGER NOT NULL,
    "imagesFilesNames" TEXT[],
    "serviceAvailability" "public"."ServiceAvailability" NOT NULL,
    "isPublished" BOOLEAN NOT NULL DEFAULT false,
    "wishlistCount" INTEGER NOT NULL DEFAULT 0,
    "avgRating" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "ratingsCount" INTEGER NOT NULL DEFAULT 0,
    "isDeleted" BOOLEAN NOT NULL DEFAULT false,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Service_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "public"."Service" ADD CONSTRAINT "Service_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Service" ADD CONSTRAINT "Service_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "public"."Category"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
