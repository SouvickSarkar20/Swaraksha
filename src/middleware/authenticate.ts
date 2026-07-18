import type { FastifyReply, FastifyRequest } from "fastify";
import {
    ExpiredTokenError,
    InvalidTokenError,
    verifyAccessToken,
    type AccessTokenPayload,
} from "../lib/token.js";

// Augment FastifyRequest type so `request.user` is fully typed across all routes!
declare module "fastify" {
    interface FastifyRequest {
        user?: AccessTokenPayload;
    }
}

/**
 * Fastify preHandler middleware to guard protected routes (like GET /me).
 * Verifies the short-lived JWT access token from the Authorization header.
 */
export async function authenticate(
    request: FastifyRequest,
    reply: FastifyReply
): Promise<void> {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        await reply.status(401).send({
            error: "Unauthorized",
            message: "Missing or malformed Authorization header. Expected 'Bearer <token>'",
        });
        return;
    }

    const token = authHeader.split(" ")[1];

    try {
        const payload = verifyAccessToken(token);
        request.user = payload;
    } catch (error) {
        if (error instanceof ExpiredTokenError) {
            await reply.status(401).send({
                error: "Unauthorized",
                message: "Access token has expired. Please use /refresh to obtain a new token.",
            });
            return;
        }

        await reply.status(401).send({
            error: "Unauthorized",
            message: "Invalid access token.",
        });
        return;
    }
}
