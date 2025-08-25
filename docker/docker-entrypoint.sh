#!/bin/sh

echo "Starting Silah Backend..."

# Check if we're in Docker (DATABASE_URL should be set by docker-compose)
if [ -n "$DATABASE_URL" ]; then
    echo "Running in Docker environment"
    echo "Database URL: $DATABASE_URL"
else
    echo "Running in local environment, loading .env.merged"
    if [ -f ".env.merged" ]; then
        # safer way to load env variables
        set -a
        . .env.merged
        set +a
        echo "Environment variables loaded from .env.merged"
        echo "Database URL: $DATABASE_URL"
    else
        echo "❌ .env.merged file not found!"
        exit 1
    fi
fi

# Wait for database to be ready
echo "Waiting for database to be ready..."
if [ "$DOCKER_ENV" = "true" ]; then
echo "Checking database connection in Docker..."
  # Always 5432 inside Docker
  until nc -z $DB_CONTAINER_NAME 5432; do
    sleep 1
  done
else
  # Use $DB_HOST and $DB_PORT from .env.merged locally
  echo "Checking database connection locally..."
  until nc -z $DB_HOST $DB_PORT; do
    sleep 1
  done
fi
echo "Database ready!"

# Generate Prisma client (important for Docker)
echo "Generating Prisma client..."
npx prisma generate

# Run migrations (use deploy for production-like environments)
echo "Running database migrations..."
npx prisma migrate deploy
echo "✅ Migrations completed successfully"

# Seed categories
echo "🌱 Starting category seeding..."
if npm run prisma:seed:category; then
    echo "✅ Category seeding completed successfully"
else
    echo "⚠️ Category seeding failed, but continuing..."
fi

# Start the application
echo "🚀 Starting NestJS server..."
if [ "$NODE_ENV" = "production" ]; then
    echo "Starting in production mode..."
    node dist/main.js
else
    echo "Starting in development mode..."
    npm run start:dev
fi