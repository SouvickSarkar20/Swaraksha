# Swaraksha — Production-Grade Authentication API

A battle-tested authentication API built from scratch with **TypeScript**, **Fastify**, and **PostgreSQL**. This project implements every security feature a real-world auth system needs — JWT tokens, refresh token rotation, MFA (TOTP), role-based access control (RBAC), account lockouts, and rate limiting — all deployed via a fully automated CI/CD pipeline to a cloud server.

> 📖 **Deep Dive:** For a detailed walkthrough of every feature, design decision, and the deployment journey, read the full article on [dev.to →](https://dev.to/souvick_20/i-built-a-production-grade-auth-api-from-scratch-heres-everything-i-learned-3on3)

---

## Features at a Glance

| Feature | What it does |
|---|---|
| **JWT Authentication** | Short-lived access tokens + long-lived refresh tokens with automatic rotation |
| **Refresh Token Rotation** | Every refresh gives you a new token pair — reusing an old token instantly revokes the entire family (theft detection) |
| **Multi-Factor Auth (MFA)** | TOTP-based 2FA compatible with Google Authenticator and Authy |
| **Role-Based Access Control** | Three roles (`user`, `moderator`, `admin`) with granular permissions (`read:users`, `manage:roles`, `ban:users`) |
| **Account Lockout** | 5 failed login attempts → account locked for 15 minutes |
| **Rate Limiting** | Powered by Upstash Redis — login routes get 5 req/15min, API routes get 100 req/min |
| **Input Validation** | Every request body is validated at the framework level using Zod schemas (zero manual parsing) |
| **Swagger Docs** | Auto-generated OpenAPI documentation available at `/docs` |
| **Graceful Shutdown** | Server finishes processing active requests before shutting down during deployments |
| **Error Tracking** | Optional Sentry integration that captures unhandled exceptions in production |
| **Health Monitoring** | `/health` endpoint for uptime monitoring services |

---

## Live API

The API is deployed and running on a DigitalOcean Droplet behind a Caddy reverse proxy.

---

## Tech Stack

- **Runtime:** Node.js 20 + TypeScript
- **Framework:** Fastify v5
- **Database:** PostgreSQL (Neon Serverless)
- **ORM:** Drizzle ORM with version-controlled SQL migrations
- **Cache / Rate Limiting:** Upstash Redis
- **Validation:** Zod + fastify-type-provider-zod
- **Auth:** jsonwebtoken, bcrypt, otpauth (TOTP)
- **Monitoring:** Sentry (optional)
- **Containerization:** Docker (multi-stage build, non-root user)
- **CI/CD:** GitHub Actions → GitHub Container Registry → DigitalOcean
- **Reverse Proxy:** Caddy
- **Testing:** Vitest

---

## API Endpoints

### Auth Routes

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| `POST` | `/signup` | No | Create a new account |
| `POST` | `/login` | No | Login with email & password |
| `POST` | `/login/mfa` | No | Complete login with TOTP code |
| `POST` | `/refresh` | No | Get a new token pair using a refresh token |
| `POST` | `/logout` | No | Invalidate a refresh token |
| `GET` | `/me` | Bearer | Get your profile from the JWT |
| `POST` | `/mfa/setup` | Bearer | Generate a TOTP secret and QR URI |
| `POST` | `/mfa/enable` | Bearer | Verify and activate MFA |
| `POST` | `/mfa/disable` | Bearer | Deactivate MFA (requires password + TOTP code) |

### Admin Routes (RBAC Protected)

| Method | Route | Permission | Description |
|--------|-------|------------|-------------|
| `GET` | `/admin/users` | `read:users` | List all users |
| `PATCH` | `/admin/users/:id/role` | `manage:roles` | Change a user's role |
| `PATCH` | `/admin/users/:id/permissions` | `manage:roles` | Update a user's permissions |
| `POST` | `/admin/users/lock` | `ban:users` | Manually lock a user account |

### Utility

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/health` | Returns `{ status: "ok" }` for uptime monitors |
| `GET` | `/docs` | Interactive Swagger UI |

---

## Getting Started

### Prerequisites

- [Node.js 20+](https://nodejs.org/)
- A [Neon](https://neon.tech/) PostgreSQL database (free tier works)
- An [Upstash](https://upstash.com/) Redis instance (free tier works)

### 1. Clone the repository

```bash
git clone https://github.com/SouvickSarkar20/Swaraksha.git
cd Swaraksha
```

### 2. Install dependencies

```bash
npm install
```

### 3. Set up environment variables

Copy the example file and fill in your credentials:

```bash
cp .env.example .env
```

```env
PORT=3000
NODE_ENV=development
DATABASE_URL=postgresql://user:password@ep-example.region.aws.neon.tech/dbname?sslmode=require
REDIS_URL=https://example.upstash.io
REDIS_TOKEN=your_upstash_rest_token
JWT_SECRET=super_secret_jwt_key_at_least_32_characters_long
SENTRY_DSN=https://your-key@o123456.ingest.sentry.io/123456  # Optional
```

| Variable | Required | Where to get it |
|----------|----------|-----------------|
| `DATABASE_URL` | Yes | [Neon Dashboard](https://console.neon.tech/) → Connection string |
| `REDIS_URL` | Yes | [Upstash Console](https://console.upstash.com/) → REST URL |
| `REDIS_TOKEN` | Yes | [Upstash Console](https://console.upstash.com/) → REST Token |
| `JWT_SECRET` | Yes | Any random string, minimum 32 characters |
| `SENTRY_DSN` | No | [Sentry Dashboard](https://sentry.io/) → Project Settings → DSN |

### 4. Run database migrations

```bash
npm run db:migrate:dev
```

### 5. Start the dev server

```bash
npm run dev
```

Open [http://localhost:3000/docs](http://localhost:3000/docs) to see the Swagger UI.

### 6. Run tests

```bash
npm test
```

---

## Running with Docker

If you prefer to run the API in a container:

### Build the image

```bash
docker build -t swaraksha-api .
```

### Run the container

```bash
docker run -d \
  --name swaraksha-api \
  -p 3000:3000 \
  --env-file .env \
  swaraksha-api
```

The API will be available at [http://localhost:3000/docs](http://localhost:3000/docs).

---

## Project Structure

```
src/
├── config/
│   └── env.ts              # Zod-validated environment variables
├── db/
│   ├── client.ts            # Drizzle + Neon database client
│   ├── schema.ts            # Database table definitions
│   └── migrate.ts           # Production migration runner
├── lib/
│   ├── password.ts          # bcrypt hashing utilities
│   ├── token.ts             # JWT sign/verify helpers
│   └── token.test.ts        # Token unit tests
├── middleware/
│   ├── authenticate.ts      # JWT verification middleware
│   ├── authorize.ts         # RBAC permission checker
│   └── rateLimit.ts         # Upstash Redis rate limiter
├── modules/
│   ├── auth/
│   │   ├── auth.route.ts    # Auth endpoint definitions
│   │   ├── auth.schema.ts   # Zod request validation schemas
│   │   ├── auth.service.ts  # Core auth business logic
│   │   └── auth.service.test.ts
│   └── admin/
│       ├── admin.route.ts   # Admin endpoint definitions
│       ├── admin.schema.ts  # Admin Zod schemas
│       └── admin.service.ts # Admin business logic
├── redis/
│   └── client.ts            # Upstash Redis client
└── server.ts                # Fastify app entry point
```

---

## Deployment

This project uses a fully automated CI/CD pipeline. Every push to `main`:

1. **CI** — Runs TypeScript compilation, unit tests, and a Docker build verification
2. **CD** — Builds the production Docker image, pushes it to GitHub Container Registry, SSHs into the DigitalOcean Droplet, runs database migrations, and swaps the live container with zero downtime

The deployment pipeline is defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## License

This project is built for learning and portfolio purposes.

---

> Built by [Souvick Sarkar](https://github.com/SouvickSarkar20)
