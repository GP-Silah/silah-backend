-- AlterTable
ALTER TABLE "public"."Card" ALTER COLUMN "expMonth" SET DATA TYPE TEXT,
ALTER COLUMN "expYear" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
