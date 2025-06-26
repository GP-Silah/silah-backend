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

Create a `.env` file in the project root and add your PostgreSQL connection string:

```bash
DATABASE_URL="postgresql://yourusername:yourpassword@localhost:5432/yourdb"
```

Replace `yourusername`, `yourpassword`, and `yourdb` with your actual PostgreSQL credentials.

### 4.Set Up the Database with Prisma

After setting your `.env`, run the following to generate Prisma Client and apply the schema:

```bash
npx prisma generate
npx prisma migrate dev
```

This will generate the Prisma Client and apply any pending migrations to your database.

### 5. Start the Server

To run the NestJS server in development mode (with hot reload):

```bash
npm run start:dev
```

---

> Built with care by Silah's Backend Team, as a requirement of a Graduation Project.
