-- AlterTable
ALTER TABLE "public"."Category" ADD COLUMN     "usedFor" "public"."ItemType";

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
