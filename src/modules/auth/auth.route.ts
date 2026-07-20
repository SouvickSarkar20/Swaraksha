import type { FastifyInstance } from "fastify";
import { authenticate } from "../../middleware/authenticate.js";
import {
    apiLimiter,
    loginLimiter,
    rateLimit,
} from "../../middleware/rateLimit.js";
import {
    AccountLockedError,
    authService,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    TokenTheftDetectedError,
} from "./auth.service.js";
import {
    loginSchema,
    logoutSchema,
    refreshSchema,
    signupSchema,
} from "./auth.schema.js";

export async function authRoutes(fastify: FastifyInstance): Promise<void> {
    // POST /signup (Strict Rate Limit: 5 per 15m)
    fastify.post(
        "/signup",
        { preHandler: [rateLimit(loginLimiter)] },
        async (request, reply) => {
            const parseResult = signupSchema.safeParse(request.body);
            if (!parseResult.success) {
                return reply.status(400).send({
                    error: "Bad Request",
                    message: "Validation failed",
                    details: parseResult.error.format(),
                });
            }

            const { email, password } = parseResult.data;
            const result = await authService.signup(email, password);

            return reply.status(201).send(result);
        }
    );

    // POST /login (Strict Rate Limit: 5 per 15m)
    fastify.post(
        "/login",
        { preHandler: [rateLimit(loginLimiter)] },
        async (request, reply) => {
            const parseResult = loginSchema.safeParse(request.body);
            if (!parseResult.success) {
                return reply.status(400).send({
                    error: "Bad Request",
                    message: "Validation failed",
                    details: parseResult.error.format(),
                });
            }

            const { email, password } = parseResult.data;

            try {
                const tokens = await authService.login(email, password);
                return reply.status(200).send(tokens);
            } catch (err) {
                if (err instanceof AccountLockedError) {
                    return reply.status(429).send({
                        error: "Too Many Requests",
                        message: err.message,
                    });
                }
                if (err instanceof InvalidCredentialsError) {
                    return reply.status(401).send({
                        error: "Unauthorized",
                        message: err.message,
                    });
                }
                throw err;
            }
        }
    );

    // POST /refresh (API Rate Limit: 100 per 1m)
    fastify.post(
        "/refresh",
        { preHandler: [rateLimit(apiLimiter)] },
        async (request, reply) => {
            const parseResult = refreshSchema.safeParse(request.body);
            if (!parseResult.success) {
                return reply.status(400).send({
                    error: "Bad Request",
                    message: "Validation failed",
                    details: parseResult.error.format(),
                });
            }

            try {
                const tokens = await authService.refresh(parseResult.data.refreshToken);
                return reply.status(200).send(tokens);
            } catch (err) {
                if (err instanceof TokenTheftDetectedError) {
                    return reply.status(401).send({
                        error: "Unauthorized",
                        message: err.message,
                    });
                }
                if (err instanceof InvalidRefreshTokenError) {
                    return reply.status(401).send({
                        error: "Unauthorized",
                        message: err.message,
                    });
                }
                throw err;
            }
        }
    );

    // POST /logout (API Rate Limit: 100 per 1m)
    fastify.post(
        "/logout",
        { preHandler: [rateLimit(apiLimiter)] },
        async (request, reply) => {
            const parseResult = logoutSchema.safeParse(request.body);
            if (!parseResult.success) {
                return reply.status(400).send({
                    error: "Bad Request",
                    message: "Validation failed",
                    details: parseResult.error.format(),
                });
            }

            await authService.logout(parseResult.data.refreshToken);
            return reply
                .status(200)
                .send({ success: true, message: "Logged out successfully" });
        }
    );

    // GET /me (Protected route via JWT + API Rate Limit)
    fastify.get(
        "/me",
        { preHandler: [rateLimit(apiLimiter), authenticate] },
        async (request, reply) => {
            return reply.status(200).send({
                user: request.user,
            });
        }
    );
}
