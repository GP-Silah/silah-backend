/*
  Warnings:

  - The values [ACCESS_TOKEN] on the enum `TokenType` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "TokenType_new" AS ENUM ('EMAIL_VERIFICATION', 'PASSWORD_RESET', 'TOKEN');
ALTER TABLE "UserToken" ALTER COLUMN "tokenType" TYPE "TokenType_new" USING ("tokenType"::text::"TokenType_new");
ALTER TYPE "TokenType" RENAME TO "TokenType_old";
ALTER TYPE "TokenType_new" RENAME TO "TokenType";
DROP TYPE "TokenType_old";
COMMIT;
