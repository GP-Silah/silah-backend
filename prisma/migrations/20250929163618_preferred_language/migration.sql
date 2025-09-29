-- CreateEnum
CREATE TYPE "public"."Languages" AS ENUM ('ARA', 'ENG');

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "preferredLanguage" "public"."Languages" NOT NULL DEFAULT 'ENG';
