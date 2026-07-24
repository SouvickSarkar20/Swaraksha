import type { FastifyInstance } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
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
    InvalidMfaCodeError,
    InvalidRefreshTokenError,
    TokenTheftDetectedError,
} from "./auth.service.js";

import {
    disableMfaSchema,
    enableMfaSchema,
    loginMfaSchema,
    loginSchema,
    logoutSchema,
    refreshSchema,
    signupSchema,
} from "./auth.schema.js";

export async function authRoutes(fastifyApp: FastifyInstance): Promise<void> {
    // 1. Wrap the fastify instance with the ZodTypeProvider!
    const fastify = fastifyApp.withTypeProvider<ZodTypeProvider>();

    // POST /signup (Strict Rate Limit: 5 per 15m)
    fastify.post(
        "/signup",
        { 
            preHandler: [rateLimit(loginLimiter)],
            schema: { body: signupSchema } // 2. Attach schema here! Swagger reads this instantly.
        },
        async (request, reply) => {
            // 3. request.body is automatically validated and strictly typed! No more .safeParse()!
            const { email, password } = request.body;
            const result = await authService.signup(email, password);
            return reply.status(201).send(result);
        }
    );

    // POST /login (Strict Rate Limit: 5 per 15m)
    fastify.post(
        "/login",
        { 
            preHandler: [rateLimit(loginLimiter)],
            schema: { body: loginSchema }
        },
        async (request, reply) => {
            const { email, password } = request.body;
            try {
                const tokensOrChallenge = await authService.login(email, password);
                return reply.status(200).send(tokensOrChallenge);
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

    fastify.post(
        "/login/mfa",
        { 
            preHandler: [rateLimit(loginLimiter)],
            schema: { body: loginMfaSchema }
        },
        async (request, reply) => {
            const { challengeToken, code } = request.body;
            try {
                const tokens = await authService.verifyMfaLogin(challengeToken, code);
                return reply.status(200).send(tokens);
            } catch (err) {
                if (err instanceof AccountLockedError) {
                    return reply.status(429).send({
                        error: "Too Many Requests",
                        message: err.message,
                    });
                }
                if (err instanceof InvalidCredentialsError || err instanceof InvalidMfaCodeError) {
                    return reply.status(401).send({
                        error: "Unauthorized",
                        message: err.message,
                    });
                }
                throw err;
            }
        }
    );

    fastify.post(
        "/mfa/setup",
        { 
            preHandler: [rateLimit(apiLimiter), authenticate],
            schema: { security: [{ bearerAuth: [] }] }
        },
        async (request, reply) => {
            try {
                const setupData = await authService.setupMfa(request.user!.userId);
                return reply.status(200).send(setupData);
            } catch (err) {
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

    fastify.post(
        "/mfa/enable",
        { 
            preHandler: [rateLimit(apiLimiter), authenticate],
            schema: { 
                body: enableMfaSchema,
                security: [{ bearerAuth: [] }]
            }
        },
        async (request, reply) => {
            try {
                const result = await authService.enableMfa(request.user!.userId, request.body.code);
                return reply.status(200).send(result);
            } catch (err) {
                if (err instanceof InvalidMfaCodeError) {
                    return reply.status(400).send({
                        error: "Bad Request",
                        message: err.message,
                    });
                }
                throw err;
            }
        }
    );

    fastify.post(
        "/mfa/disable",
        { 
            preHandler: [rateLimit(apiLimiter), authenticate],
            schema: { 
                body: disableMfaSchema,
                security: [{ bearerAuth: [] }]
            }
        },
        async (request, reply) => {
            try {
                const result = await authService.disableMfa(
                    request.user!.userId,
                    request.body.password,
                    request.body.code
                );
                return reply.status(200).send(result);
            } catch (err) {
                if (err instanceof InvalidCredentialsError || err instanceof InvalidMfaCodeError) {
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
        { 
            preHandler: [rateLimit(apiLimiter)],
            schema: { body: refreshSchema }
        },
        async (request, reply) => {
            try {
                const tokens = await authService.refresh(request.body.refreshToken);
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
        { 
            preHandler: [rateLimit(apiLimiter)],
            schema: { body: logoutSchema }
        },
        async (request, reply) => {
            await authService.logout(request.body.refreshToken);
            return reply
                .status(200)
                .send({ success: true, message: "Logged out successfully" });
        }
    );

    // GET /me (Protected route via JWT + API Rate Limit)
    fastify.get(
        "/me",
        { 
            preHandler: [rateLimit(apiLimiter), authenticate],
            schema: { security: [{ bearerAuth: [] }] }
        },
        async (request, reply) => {
            return reply.status(200).send({
                user: request.user,
            });
        }
    );
}
