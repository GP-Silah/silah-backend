# Silah Backend

This is the backend for [Silah](https://github.com/GP-Silah). It is built using [NestJS](https://nestjs.com/), a progressive Node.js framework for building efficient and scalable server-side applications.

---

## Prerequisites

- Node.js >= 20
- npm >= 10
- Docker & Docker Compose (optional, but very recommended)
- PostgreSQL >= 16 (if not using Docker)
- Tap Payments account and API keys
- Cloudflare R2 account and API keys
- Watheq API credentials

---

## Getting Started (Without Docker)

Follow the steps below to set up the project locally.

### 1. Clone the Repository

```bash
git clone https://github.com/GP-Silah/silah-backend.git
cd silah-backend
```

### 2. Install Dependencies

Use `npm` to install all project dependencies:

```bash
npm install
```

### 3. Configure Environment Variables

Copy the provided `.env.example` file to `.env` and fill in the required values:

```bash
cp .env.example .env
```

The `.env.example` file includes all necessary environment variables with explanations for each. Make sure to review and update them according to your local setup.

### 4. Set Up the Database with Prisma

After setting your `.env`, run the following to generate Prisma Client and apply the schema:

```bash
npx prisma generate
npx prisma migrate dev
```

This will generate the Prisma Client and apply any pending migrations to your database.

### 5. Seed the Database (Required)

To populate the database with initial data (specifically, the Categories and Subcategories), run:

```bash
npm run prisma:seed:category
```

> **Why this matters:**
> This step inserts around 50 predefined categories into the database using the `src/prisma/categorySeed.ts` script. Each category has a unique ID, and these IDs are used throughout the app to associate users with their selected categories.
> Skipping this step will cause category-related features to break.

### 6. Start the Server

To run the NestJS server in development mode (with hot reload):

```bash
npm run start:dev
```

---

## Getting Started (With Docker)

You can run the project with Docker in two modes:

### Production-like Mode (default)

This mimics a production enviroment

```bash
docker-compose up -d --build
```

- Start Postgres + NestJS backend
- Runs migrations + Seeds automatically
- Serves compiled code (`dis/main.js`)
- Accessible at: `http://localhost:3000`

Check containers:

```bash
docker ps
```

### Development Mode (with Hot Reload)

For local development with live code updates, use the override file:

```bash
docker-compose -f docker-compose.yml -f docker-compose.override.yml up -d --build
```

- Mounts your local source into the container
- Runs `npm run start:dev` with hot reload
- Also run migrations + Seeds automatically

---

## Database

- Uses PostgreSQL
- Managed with Prisma ORM
- Seeded with categories and subcategories

---

## API Documentation

- Swagger available at `http://localhost:3000/api/docs` (requires starting the server)
- It inculdes all endpoints, request/response schemas, and examples

---

## Running Tests

```bash
npm run test
npm run test:watch   # fpr development
npm run lint         # check code style
```

---

## Troubleshooting

- **DB connection issues:** Check `.env` variables
- **Prisma migration errors:** Run `npx prisma migrate reset` to reset local DB
- **Docker issues:** Ensure ports 3000 and 5432 are free, restart containers

---

> Built with care by Silah's Backend Team, as a requirement of a Graduation Project.
