/*
  Warnings:

  - A unique constraint covering the columns `[tapTokenId]` on the table `Card` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `tapTokenId` to the `Card` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "public"."Card" ADD COLUMN     "tapTokenId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateIndex
CREATE UNIQUE INDEX "Card_tapTokenId_key" ON "public"."Card"("tapTokenId");
