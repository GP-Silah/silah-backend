/*
  Warnings:

  - The values [ARA,ENG] on the enum `Languages` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "public"."Languages_new" AS ENUM ('AR', 'EN');
ALTER TABLE "public"."User" ALTER COLUMN "preferredLanguage" DROP DEFAULT;
ALTER TABLE "public"."User" ALTER COLUMN "preferredLanguage" TYPE "public"."Languages_new" USING ("preferredLanguage"::text::"public"."Languages_new");
ALTER TYPE "public"."Languages" RENAME TO "Languages_old";
ALTER TYPE "public"."Languages_new" RENAME TO "Languages";
DROP TYPE "public"."Languages_old";
ALTER TABLE "public"."User" ALTER COLUMN "preferredLanguage" SET DEFAULT 'EN';
COMMIT;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- AlterTable
ALTER TABLE "public"."User" ALTER COLUMN "preferredLanguage" SET DEFAULT 'EN';
