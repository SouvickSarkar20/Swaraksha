import type { FastifyInstance } from "fastify";
import { authenticate } from "../../middleware/authenticate.js";
import {
    authService,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
} from "./auth.service.js";
import {
    loginSchema,
    logoutSchema,
    refreshSchema,
    signupSchema,
} from "./auth.schema.js";

export async function authRoutes(fastify: FastifyInstance): Promise<void> {
    // POST /signup
    fastify.post("/signup", async (request, reply) => {
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
    });

    // POST /login
    fastify.post("/login", async (request, reply) => {
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
            if (err instanceof InvalidCredentialsError) {
                return reply.status(401).send({
                    error: "Unauthorized",
                    message: err.message,
                });
            }
            throw err;
        }
    });

    // POST /refresh
    fastify.post("/refresh", async (request, reply) => {
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
            if (err instanceof InvalidRefreshTokenError) {
                return reply.status(401).send({
                    error: "Unauthorized",
                    message: err.message,
                });
            }
            throw err;
        }
    });

    // POST /logout
    fastify.post("/logout", async (request, reply) => {
        const parseResult = logoutSchema.safeParse(request.body);
        if (!parseResult.success) {
            return reply.status(400).send({
                error: "Bad Request",
                message: "Validation failed",
                details: parseResult.error.format(),
            });
        }

        await authService.logout(parseResult.data.refreshToken);
        return reply.status(200).send({ success: true, message: "Logged out successfully" });
    });

    // GET /me (Protected route!)
    fastify.get(
        "/me",
        { preHandler: [authenticate] },
        async (request, reply) => {
            // `request.user` is guaranteed to exist and be valid because of `authenticate` middleware
            return reply.status(200).send({
                user: request.user,
            });
        }
    );
}
