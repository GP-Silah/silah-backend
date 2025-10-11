-- CreateEnum
CREATE TYPE "public"."NotificationType" AS ENUM ('NEW_MESSAGE', 'NEW_ORDER', 'NEW_REVIEW', 'NEW_INVOICE', 'NEW_OFFER', 'BID_STATUS_CHANGED', 'INVOICE_STATUS_CHANGED', 'ORDER_STATUS_CHANGED', 'GROUP_PURCHASE_STATUS_CHANGED');

-- CreateEnum
CREATE TYPE "public"."NotificationEntityType" AS ENUM ('CHAT', 'ORDER', 'REVIEW', 'INVOICE', 'OFFER', 'BID', 'GROUP_PURCHASE');

-- AlterTable
ALTER TABLE "public"."SupplierSubscription" ALTER COLUMN "endDate" SET DEFAULT now() + interval '1 month';

-- CreateTable
CREATE TABLE "public"."NotificationPreference" (
    "userId" TEXT NOT NULL,
    "allowNotifications" BOOLEAN NOT NULL DEFAULT true,
    "newMessageNotify" BOOLEAN NOT NULL DEFAULT true,
    "newOrderNotify" BOOLEAN NOT NULL DEFAULT true,
    "newReviewNotify" BOOLEAN NOT NULL DEFAULT true,
    "newInvoiceNotify" BOOLEAN NOT NULL DEFAULT true,
    "newOfferNotify" BOOLEAN NOT NULL DEFAULT true,
    "biddingStatusNotify" BOOLEAN NOT NULL DEFAULT true,
    "invoiceStatusNotify" BOOLEAN NOT NULL DEFAULT true,
    "orderStatusNotify" BOOLEAN NOT NULL DEFAULT true,
    "groupPurchaseStatusNotify" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationPreference_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "public"."Notification" (
    "id" TEXT NOT NULL,
    "senderUserId" TEXT NOT NULL,
    "receiverUserId" TEXT NOT NULL,
    "type" "public"."NotificationType" NOT NULL,
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "isRead" BOOLEAN NOT NULL DEFAULT false,
    "readAt" TIMESTAMP(3),
    "entityId" TEXT,
    "entityType" "public"."NotificationEntityType",
    "isDeleted" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "public"."NotificationPreference" ADD CONSTRAINT "NotificationPreference_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Notification" ADD CONSTRAINT "Notification_senderUserId_fkey" FOREIGN KEY ("senderUserId") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."Notification" ADD CONSTRAINT "Notification_receiverUserId_fkey" FOREIGN KEY ("receiverUserId") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
