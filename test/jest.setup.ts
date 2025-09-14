import * as dotenv from 'dotenv';

// Load merged env first (should contain correct test DB)
dotenv.config({ path: '.env.merged', override: true });

// Optional: if you need to override anything specific for test
process.env.DB_HOST = process.env.DB_HOST || 'localhost';
process.env.DB_PORT = process.env.DB_PORT || '5432';
process.env.DATABASE_URL =
    process.env.DATABASE_URL ||
    `postgresql://${process.env.POSTGRES_USER}:${process.env.POSTGRES_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.POSTGRES_DB}?schema=public`;
