-- Migration: Add CHECK constraint for pfpFileName/isPfpDefault consistency
ALTER TABLE "User"
ADD CONSTRAINT "user_pfp_consistency"
CHECK (
  ("isPfpDefault" = true AND "pfpFileName" IS NULL)
  OR
  ("isPfpDefault" = false AND "pfpFileName" IS NOT NULL)
);
