-- CreateEnum
CREATE TYPE "public"."GroupPurchaseStatus" AS ENUM ('OPEN', 'CLOSED');

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateTable
CREATE TABLE "public"."GroupPurchase" (
    "id" TEXT NOT NULL,
    "productId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "city" TEXT NOT NULL,
    "minGroupQuantity" INTEGER NOT NULL,
    "actualGroupQuantity" INTEGER NOT NULL,
    "totalPrice" DOUBLE PRECISION NOT NULL,
    "deadline" TIMESTAMP(3) NOT NULL,
    "status" "public"."GroupPurchaseStatus" NOT NULL DEFAULT 'OPEN',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GroupPurchase_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."GroupPurchaseBuyer" (
    "id" TEXT NOT NULL,
    "groupPurchaseId" TEXT NOT NULL,
    "buyerId" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL,
    "priceBasedQuantity" DOUBLE PRECISION NOT NULL,
    "joinedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GroupPurchaseBuyer_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "GroupPurchaseBuyer_groupPurchaseId_buyerId_key" ON "public"."GroupPurchaseBuyer"("groupPurchaseId", "buyerId");

-- AddForeignKey
ALTER TABLE "public"."GroupPurchase" ADD CONSTRAINT "GroupPurchase_productId_fkey" FOREIGN KEY ("productId") REFERENCES "public"."Product"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."GroupPurchase" ADD CONSTRAINT "GroupPurchase_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."GroupPurchaseBuyer" ADD CONSTRAINT "GroupPurchaseBuyer_groupPurchaseId_fkey" FOREIGN KEY ("groupPurchaseId") REFERENCES "public"."GroupPurchase"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."GroupPurchaseBuyer" ADD CONSTRAINT "GroupPurchaseBuyer_buyerId_fkey" FOREIGN KEY ("buyerId") REFERENCES "public"."Buyer"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
