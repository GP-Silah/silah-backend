import * as dotenv from 'dotenv';

// ✅ Load the merged env file which contains DATABASE_URL with :5433
dotenv.config({ path: '.env.merged', override: true });

// ✅ Ensure DATABASE_URL exists, but DO NOT regenerate or override port
if (!process.env.DATABASE_URL) {
  throw new Error('❌ DATABASE_URL is not defined in .env.merged!');
}

console.log(`🧪 Using Test Database URL: ${process.env.DATABASE_URL}`);

