/*
  Warnings:

  - You are about to drop the column `lastMessage` on the `Chat` table. All the data in the column will be lost.
  - You are about to drop the column `lastMessageAt` on the `Chat` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "public"."Chat" DROP COLUMN "lastMessage",
DROP COLUMN "lastMessageAt";

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
