import { z } from "zod";
import dotenv from "dotenv";

// Load .env variables into process.env
dotenv.config();

const envSchema = z.object({
    PORT: z.string().default("3000").transform((val) => parseInt(val, 10)),
    NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
    DATABASE_URL: z.string().url("DATABASE_URL must be a valid PostgreSQL URL"),
    REDIS_URL: z.string().url("REDIS_URL must be a valid Upstash URL"),
    REDIS_TOKEN: z.string().min(1, "REDIS_TOKEN is required"),
    JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters long for security"),
    SENTRY_DSN: z.string().url().optional(),
});

// Parse and validate process.env
const parseEnv = () => {
    const result = envSchema.safeParse(process.env);

    if (!result.success) {
        console.error("❌ Invalid environment variables:");
        console.error(JSON.stringify(result.error.format(), null, 2));
        process.exit(1); // Stop the server immediately!
    }

    return result.data;
};

export const env = parseEnv();
export type Env = z.infer<typeof envSchema>;
