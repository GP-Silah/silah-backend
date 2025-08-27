#!/bin/sh
set -e

echo "Starting Silah Backend..."

# Check if we're in Docker
if [ "$DOCKER_ENV" = "true" ]; then 
  echo "Running in Docker environment"
else
    echo "Running in local environment, loading .env.merged"
    if [ -f ".env.merged" ]; then
        # safer way to load env variables
        set -a
        . .env.merged
        set +a
        echo "Environment variables loaded from .env.merged"
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
    # DEBUGGING SECTION
    echo "=== DEBUGGING DIST FOLDER ==="
    echo "Checking if dist exists:"
    ls -la /app/ | grep dist || echo "No dist folder found"
    
    echo "Checking what's inside dist (if exists):"
    ls -la /app/dist/ 2>/dev/null || echo "Dist folder is empty or doesn't exist"
    
    echo "Checking what processes are using /app/dist:"
    lsof /app/dist 2>/dev/null || echo "No processes using dist folder"
    
    echo "Checking mounted filesystems:"
    mount | grep dist || echo "No dist mounts found"
    
    echo "Trying to create a test file in dist:"
    mkdir -p /app/dist && echo "test" > /app/dist/test.txt && echo "✅ Can write to dist" || echo "❌ Cannot write to dist"
    
    echo "Trying to remove test file:"
    rm -f /app/dist/test.txt && echo "✅ Can delete from dist" || echo "❌ Cannot delete from dist"
    
    echo "=== END DEBUGGING ==="
    npm run start:dev
fi