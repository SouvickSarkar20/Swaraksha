import { Redis } from "@upstash/redis";
import { env } from "../config/env.js";

// Initialize Upstash Redis client using our validated environment variables
export const redis = new Redis({
    url: env.REDIS_URL,
    token: env.REDIS_TOKEN,
});
