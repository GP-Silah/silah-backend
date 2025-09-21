-- AlterTable
ALTER TABLE "public"."Supplier" ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "isSubscribed" BOOLEAN NOT NULL DEFAULT false;
