# Silah Backend

This is the backend for [Silah](https://github.com/GP-Silah). It is built using [NestJS](https://nestjs.com/), a progressive Node.js framework for building efficient and scalable server-side applications.

## Getting Started

Follow the steps below to set up the project locally.

---

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

### 4.Set Up the Database with Prisma

After setting your `.env`, run the following to generate Prisma Client and apply the schema:

```bash
npx prisma generate
npx prisma migrate dev
```

This will generate the Prisma Client and apply any pending migrations to your database.

### 5. Seed the Database (Required)

To populate the database with initial data (specifically, the Categories), run:

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

> Built with care by Silah's Backend Team, as a requirement of a Graduation Project.
