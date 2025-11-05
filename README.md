# Silah Backend

_Last Updated: November 2025_

This is the backend API server for [Silah](https://github.com/GP-Silah), an AI-augmented full-stack B2B platform that connects suppliers and buyers. Built using [NestJS](https://nestjs.com/), a progressive Node.js framework for building efficient and scalable server-side applications.

> **Silah** (Arabic: صِلَة) _[noun]_ Connection, bond, link; often used to describe the ties between people, family, or communities.

---

## Architecture Overview

This NestJS backend handles:

- **User Management & Authentication** (with Commercial Registration verification)
- **Product & Service Catalog Management**
- **Order Processing & Management**
- **Request for Proposals (RFP) System**
- **Real-time Chat & Notifications**
- **File Upload & Storage** (Cloudflare R2 integration)
- **Payment Processing** (Tap Payments integration)
- **Multi-language Support** (DeepL Translate API)

> **Note:** AI features (semantic search, demand forecasting) are handled by a separate FastAPI backend.

---

## Tech Stack

- **Framework:** NestJS (Node.js)
- **Database:** PostgreSQL with Prisma ORM
- **Authentication:** JWT + Wathq API (Commercial Registration verification)
- **Storage:** Cloudflare R2 (for file/image storage)
- **Payments:** Tap Payments Gateway
- **Translation:** DeepL Translate API
- **Real-time:** WebSockets for chat and notifications
- **Testing:** Jest (Unit, Integration, E2E)
- **DevOps:** Docker & Docker Compose

---

## Prerequisites

Before you start, make sure you have:

- Node.js >= 20
- npm >= 10
- Docker & Docker Compose >= 2 (strongly recommended)
- PostgreSQL >= 16 (if not using Docker)

---

## Required API Keys & Accounts

You'll need accounts and API keys for:

- SendGrid (sending emails)
- Tap Payments (payment processing)
- Cloudflare R2 (file storage)
- Wathq API (Saudi Commercial Registration verification)
- DeepL Translate API (for auto-translation of products and services data)

---

## Getting Started

### Method 1: With Docker (Recommended)

Docker simplifies setup by handling the database and environment automatically.

#### 1. Clone the Repository

```bash
git clone https://github.com/GP-Silah/silah-backend.git
cd silah-backend
```

#### 2. Install Dependencies

```bash
npm install
```

#### 3. Set Up Environment Files

Create your environment configuration files:

```bash
# Copy the example files
cp .env.example .env
cp .env.dev.example .env.dev
cp .env.test.example .env.test
```

**Understanding the Environment Files:**

- `.env` used for shared variables (database credentials, API keys)
- `.env.dev` used for development database connection
- `.env.test` used for test database connection (separate from dev)

**Why seperate database config?** Prisma only accepts one `DATABASE_URL` at a time, but we need different databases for development and testing. Our setup dynamically switches between them.

#### 4. Configure Your Environment Variables

Edit the `.env` files with your actual values.

#### 5. Start the Development Environment

```bash
npm run docker:dev
```

This single command will:

- Start PostgreSQL database on port 5432
- Start NestJS backend on port 3000 with hot reload
- Run database migrations automatically
- Seed the database with categories
- Set up health checks to ensure everything is connected

**Important:** The category seeding step is crucial. It inserts ~50 predefined categories that the application relies on. Skipping this will break category-related features.

**What you'll see (simplified):**

```bash
Creating silah_db ... done
Creating silah_backend ... done
Attaching to silah_db, silah_backend
silah_backend    | Database connected successfully
silah_backend    | Migrations applied
silah_backend    | Categories seeded
silah_backend    | 🚀 Server running on http://localhost:3000
```

#### 6. Verify Everything Works

- **API:** `http://localhost:3000/api`
- **Health Check:** `http://localhost:3000/api/health`
- **API Documentation:** `http://localhost:3000/api/docs`

### Method 2: Without Docker (Manual Setup)

If you prefer to run PostgreSQL locally or have specific requirements.

#### 1-3. Same as Docker method (clone, install, configure)

#### 4. Set Up Local PostgreSQL

Make sure PostgreSQL is running locally and create the database:

```bash
# Connect to PostgreSQL
psql -U postgres

# Create user and databases
CREATE USER silah_user WITH PASSWORD 'your_secure_password';
CREATE DATABASE silah_dev OWNER silah_user;
CREATE DATABASE silah_test OWNER silah_user;
GRANT ALL PRIVILEGES ON DATABASE silah_dev TO silah_user;
GRANT ALL PRIVILEGES ON DATABASE silah_test TO silah_user;
```

#### Enable Fuzzy Search Extension (`pg_trgm`)

To enable typo-tolerant search (e.g., "Candle" → "Candl"), you **must** enable the `pg_trgm` extension in both databases:

````sql
\c silah_dev
CREATE EXTENSION IF NOT EXISTS pg_trgm;

\c silah_test
CREATE EXTENSION IF NOT EXISTS pg_trgm;
```

> Warning: This extension is required for full-text fuzzy search in products, suppliers, and categories. Without it, search queries will fail.

#### 5. Set Up Prisma and Database

```bash
# Generate Prisma client
npx prisma generate

# Run migrations (development)
npm run prisma:dev

# Seed the database with categories (REQUIRED)
npm run prisma:seed:category
````

**Important:** The category seeding step is crucial. It inserts ~50 predefined categories that the application relies on. Skipping this will break category-related features.

#### 6. Start the Server

```bash
npm run start:dev
```

---

## Docker Management

### Available Commands

| Command                  | Description                         | Use Case                          |
| ------------------------ | ----------------------------------- | --------------------------------- |
| `npm run docker:dev`     | Start development environment       | Daily development                 |
| `npm run docker:dev:d`   | Start dev environment in background | When you want to free up terminal |
| `npm run docker:test`    | Start test environment              | Running integration/e2e tests     |
| `npm run docker:down`    | Stop all containers                 | Cleanup when done                 |
| `npm run docker:logs`    | View container logs                 | Debugging issues                  |
| `npm run docker:cleanup` | Remove containers & clean system    | Full reset                        |

### Understanding the Docker Setup

```yml
# Two separate databases for isolation
postgres_dev: # Development DB on port 5432
postgres_test: # Test DB on port 5433 (ephemeral data)

# One application container
app: # NestJS backend on port 3000
```

**Why separate test database?**

- **Isolation:** Tests doon't interfere with development data
- **Clean slate:** Each test run starts fresh
- **Speed:** No need to clean up test data
- **Safety:** Can't accidentally delete dev data during testing

### Docker Environment Switching

Our Docker setup intelligently switches between development and test configurations:

```bash
# Development mode
npm run docker:dev
# → Uses .env.dev, connects to postgres_dev, hot reload enabled

# Test mode
npm run docker:test
# → Uses .env.test, connects to postgres_test, optimized for testing
```

### Troubleshooting Docker

**Port 5432 already in use:**

```bash
# Kill any processes using the port
npm run kill:5432

# Or stop local PostgreSQL service
brew services stop postgresql  # macOS
sudo systemctl stop postgresql  # Linux
```

**Containers won't start:**

```bash
# Full cleanup and restart
npm run docker:cleanup
npm run docker:dev
```

**Database connection issues:**

```bash
# Check container logs
npm run docker:logs

# Check if database is ready
npm run db:wait:dev
```

---

### Monitoring & Logging

#### Application Logs

```bash
# View real-time logs
npm run docker:logs

# View specific service logs
docker logs silah_backend -f
docker logs silah_db -f

# Search logs for specific events (e.g., errors)
docker logs silah_backend 2>&1 | grep "ERROR"
```

#### Database Monitoring

```bash
# Connect to database
docker exec -it silah_db psql -U silah_user -d silah_dev

# View active connections
SELECT * FROM pg_stat_activity;

# Monitor query performance
SELECT * FROM pg_stat_statements ORDER BY mean_time DESC;
```

---

## Testing Strategy

We use a comprehensive 3-tier testing approach:

### 1. Unit Tests (`*.spec.ts`)

Test individual components in isolation with mocked dependencies.

```bash
# Run all unit tests
npm test

# Run in watch mode (for development)
npm run test:watch

# Run with coverage report
npm run test:cov

# Debug tests
npm run test:debug
```

**What unit tests cover:**

- Individual service methods
- Controller endpoints (mocked dependencies)
- Utility functions
- Validation logic

### 2. Integration Tests (`*.int-spec.ts`)

Test multiple components working together with real database connections.

```bash
# Run integration tests (automatically manages test database)
npm run test:int
```

**What integration tests cover:**

- Controller + Service workflows
- Service + Database interactions
- Real database operations

**How integration tests work:**

1. Automatically starts test database container
2. Waits for database to be ready
3. Runs migrations and seeds data
4. Executes tests with real database connections
5. Cleans up after completion

### 3. End-to-End Tests (`*.e2e-spec.ts`)

Test complete user workflows through HTTP requests.

```bash
# Run e2e tests
npm run test:e2e
```

**What E2E tests cover:**

- Complete API workflows
- Authentication & Authorization
- Cross-module interaction
- Real HTTP request/response cycles

### Test Configuration Files

- **Unit Tests:** Uses default Jest configuration in `package.json`
- **Integration Tests:** `test/jest-int.json`
- **E2E Tests:** `test/jest-e2e.json`

### Test Database Management

**Development Database (postgres_dev):**

- Local Port: 5432
- Persistent data (survives container restarts)
- Used for: Manual testing, development

**Test Database (postgres_test):**

- Local Port: 5433
- Ephemeral data (fresh start each time)
- Used for: Integration and E2E tests
- Automatically managed by test scripts

### Running Tests in Different Scenarios

```bash
# Quick feedback loop during development
npm run test:watch

# Before committing changes
npm run test && npm run test:int

# Full test suite (CI/CD pipeline)
npm test && npm run test:int && npm run test:e2e

# Coverage report
npm run test:cov
```

---

## Development Workflow

### Daily Development Commands

```bash
# Start development environment
npm run docker:dev

# Watch code changes
npm run start:dev  # (if not using Docker)

# Run tests as you develop
npm run test:watch

# Check code quality
npm run lint
npm run format

# Database operations
npm run prisma:dev            # Run new migrations
npm run prisma:seed:category  # Reseed categories
```

### Database Operations

```bash
# Development database migrations
npm run prisma:dev

# Test database migrations
npm run prisma:test

# Generate Prisma client (after schema changes)
npx prisma generate

# Reset database (⚠️ destroys all data)
npx prisma migrate reset

# View database in Prisma Studio
npx prisma studio
```

### Code Quality & Standards

```bash
# Lint and auto-fix issues
npm run lint

# Format code consistently
npm run format

# Type checking
npm run build

# Pre-commit checks (recommended)
npm run lint && npm run test && npm run build
```

---

## API Documentation

Once your server is running, comprehensive API documentation is available:

### Swagger UI

**URL:** `http://localhost:3000/api/docs`

**Features:**

- Interactive API explorer
- Request/response schemas
- Try-it-out functionality
- Authentication examples
- Detailed endpoint descriptions

---

## Troubleshooting Guide

### Common Issues & Solutions

#### Port 5432 already in use

```bash
# Solution 1: Kill process using the port
npm run kill:5432

# Solution 2: Stop local PostgreSQL
brew services stop postgresql  # macOS
sudo systemctl stop postgresql  # Linux

# Solution 3: Use different port in .env
DATABASE_URL=postgresql://user:pass@localhost:5433/db
```

#### Database connection refused

```bash
# Check if database container is running
docker ps | grep silah_db

# Restart database
npm run docker:down
npm run docker:dev

# Check database logs
docker logs silah_db
```

#### Prisma client not generated

```bash
# Generate Prisma client
npx prisma generate

# Restart your application
npm run start:dev
```

#### Missing categories in database

```bash
# Reseed categories
npm run prisma:seed:category

# Or reset and reseed entire database (this destroys all data)
npx prisma migrate reset
```

#### Docker containers won't start

```bash
# Full cleanup
npm run docker:cleanup

# Check Docker daemon
docker --version
docker info

# Restart Docker service
sudo systemctl restart docker  # Linux
# Restart Docker Desktop on macOS/Windows
```

#### Tests failing randomly

```bash
# Clear Jest cache
npx jest --clearCache

# Run tests individually
npm test -- --testNamePattern="specific test name"

# Check test database
npm run docker:test
docker logs silah_db_test
```

#### Hot reload not working

```bash
# Check volume mounts in docker-compose.override.yml
# Ensure you're using the override file:
npm run docker:dev  # This includes the override file

# If still not working, restart with clean build:
npm run docker:down
npm run docker:dev
```

## Getting Help

If you're still experiencing issues:

1. Check the logs first: `npm run docker:logs`
2. Verify environment variables are set correctly
3. Ensure all required services are running
4. Check GitHub Issues for known problems
5. Contact the development team

---

## License

This project is licensed under the terms specified in the LICENSE file.

---

> Built with care by Silah's Backend Team, as a requirement of a Graduation Project.
