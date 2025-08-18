-- Migration: Add CHECK constraint for pfpFileName/isPfpDefault consistency
ALTER TABLE "User"
ADD CONSTRAINT "user_pfp_consistency"
CHECK (
  ("isPfpDefault" IS TRUE AND "pfpFileName" IS NULL)
  OR
  ("isPfpDefault" IS FALSE AND "pfpFileName" IS NOT NULL)
);
