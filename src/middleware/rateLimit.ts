import { Ratelimit } from "@upstash/ratelimit";
import type { FastifyReply, FastifyRequest } from "fastify";
import { redis } from "../redis/client.js";

// Strict limiter for authentication endpoints (/login, /signup)
export const loginLimiter = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(5, "15 m"),
    prefix: "ratelimit:login",
});

// General limiter for API endpoints (/refresh, /me, /logout)
export const apiLimiter = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(100, "1 m"),
    prefix: "ratelimit:api",
});

/**
 * Factory function creating a Fastify preHandler middleware for rate limiting.
 */
export function rateLimit(limiter: Ratelimit) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        // Fallback to "127.0.0.1" if IP is missing during tests or proxy routing
        const ip = request.ip || "127.0.0.1";

        const { success, limit, remaining, reset } = await limiter.limit(ip);

        // Attach standard HTTP X-RateLimit headers
        reply.header("X-RateLimit-Limit", limit);
        reply.header("X-RateLimit-Remaining", remaining);
        reply.header("X-RateLimit-Reset", reset);

        if (!success) {
            await reply.status(429).send({
                error: "Too Many Requests",
                message: "You have exceeded the allowed rate limit. Please try again later.",
            });
            return;
        }
    };
}
