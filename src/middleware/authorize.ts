import type { FastifyReply, FastifyRequest } from "fastify";

export function authorize(...requiredPermissions: string[]) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        if (!request.user) {
            await reply.status(401).send({
                error: "Unauthorized",
                message: "Authentication required before checking permissions.",
            });
            return;
        }
        const userPermissions = request.user.permissions || [];

        // The user must possess EVERY permission requested in the array
        const hasAllPermissions = requiredPermissions.every((perm) =>
            userPermissions.includes(perm)
        );
        if (!hasAllPermissions) {
            await reply.status(403).send({
                error: "Forbidden",
                message: `Insufficient permissions. Required: [${requiredPermissions.join(", ")}]`,
            });
            return;
        }
    };
}

export function authorizeRole(...allowedRoles: string[]) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
        if (!request.user) {
            await reply.status(401).send({
                error: "Unauthorized",
                message: "Authentication required before checking roles.",
            });
            return;
        }
        if (!allowedRoles.includes(request.user.role)) {
            await reply.status(403).send({
                error: "Forbidden",
                message: `Insufficient role. Required one of: [${allowedRoles.join(", ")}]`,
            });
            return;
        }
    };
}