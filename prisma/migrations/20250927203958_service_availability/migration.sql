/*
  Warnings:

  - The values [ALWAYS] on the enum `ServiceAvailability` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "public"."ServiceAvailability_new" AS ENUM ('TWENTY_FOUR_SEVEN', 'EVERYDAY', 'WEEKDAYS', 'WEEKENDS', 'APPOINTMENT');
ALTER TABLE "public"."Service" ALTER COLUMN "serviceAvailability" TYPE "public"."ServiceAvailability_new" USING ("serviceAvailability"::text::"public"."ServiceAvailability_new");
ALTER TYPE "public"."ServiceAvailability" RENAME TO "ServiceAvailability_old";
ALTER TYPE "public"."ServiceAvailability_new" RENAME TO "ServiceAvailability";
DROP TYPE "public"."ServiceAvailability_old";
COMMIT;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
