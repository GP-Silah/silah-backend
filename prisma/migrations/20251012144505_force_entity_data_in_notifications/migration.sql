/*
  Warnings:

  - Made the column `entityId` on table `Notification` required. This step will fail if there are existing NULL values in that column.
  - Made the column `entityType` on table `Notification` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "public"."Notification" ALTER COLUMN "entityId" SET NOT NULL,
ALTER COLUMN "entityType" SET NOT NULL;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
