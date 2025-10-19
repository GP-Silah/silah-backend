-- CreateEnum
CREATE TYPE "public"."BidExpectedResponseTime" AS ENUM ('ONE_WEEK', 'TWO_WEEKS', 'FOUR_WEEKS', 'SIX_WEEKS');

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateTable
CREATE TABLE "public"."Bid" (
    "id" TEXT NOT NULL,
    "buyerId" TEXT NOT NULL,
    "bidName" VARCHAR(100) NOT NULL,
    "mainActivity" VARCHAR(500) NOT NULL,
    "submissionDeadline" TIMESTAMP(3) NOT NULL,
    "expectedResponseTime" "public"."BidExpectedResponseTime" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Bid_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."Offer" (
    "id" TEXT NOT NULL,
    "bidId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "proposedAmount" DOUBLE PRECISION NOT NULL,
    "expectedCompletionTime" TIMESTAMP(3) NOT NULL,
    "offerDetails" VARCHAR(500) NOT NULL,
    "executionDetails" VARCHAR(500) NOT NULL,
    "notes" VARCHAR(500),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Offer_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "public"."Bid" ADD CONSTRAINT "Bid_buyerId_fkey" FOREIGN KEY ("buyerId") REFERENCES "public"."Buyer"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Offer" ADD CONSTRAINT "Offer_bidId_fkey" FOREIGN KEY ("bidId") REFERENCES "public"."Bid"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Offer" ADD CONSTRAINT "Offer_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "public"."Supplier"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
