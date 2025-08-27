import * as dotenv from 'dotenv';

// Load merged env first
dotenv.config({ path: '.env.merged' });

// Override for local test execution
process.env.DB_HOST = 'localhost';
process.env.DB_PORT = '5433';
process.env.DATABASE_URL = `postgresql://${process.env.POSTGRES_USER}:${process.env.POSTGRES_PASSWORD}@localhost:5433/${process.env.POSTGRES_DB}?schema=public`;
