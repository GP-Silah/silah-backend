-- AlterTable
ALTER TABLE "public"."Chat" ADD COLUMN     "lastMessage" TEXT,
ALTER COLUMN "lastMessageAt" DROP NOT NULL;

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';
