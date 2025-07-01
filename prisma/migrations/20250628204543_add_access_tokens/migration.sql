-- AlterEnum
ALTER TYPE "TokenType" ADD VALUE 'ACCESS_TOKEN';

-- AlterTable
ALTER TABLE "UserToken" ALTER COLUMN "isUsed" DROP NOT NULL;
