#!/bin/sh
set -e   # exit if any command fails

# Run migrations
npx prisma migrate deploy

# Seed categories
npm run prisma:seed:category

# Start NestJS in dev/watch mode
npm run start:dev
