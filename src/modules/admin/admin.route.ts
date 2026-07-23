import type { FastifyInstance } from "fastify";
import { authenticate } from "../../middleware/authenticate.js";
import { authorize } from "../../middleware/authorize.js";
import { apiLimiter, rateLimit } from "../../middleware/rateLimit.js";
import { adminService } from "./admin.service.js";
import { updatePermissionsSchema, updateRoleSchema } from "./admin.schema.js";

export async function adminRoutes(fastify: FastifyInstance): Promise<void> {
    // All admin routes globally require Rate Limiting + Authentication
    fastify.addHook("preHandler", rateLimit(apiLimiter));
    fastify.addHook("preHandler", authenticate);

    // GET /admin/users - Requires 'read:users' permission
    fastify.get(
        "/users",
        { preHandler: [authorize("read:users")] },
        async (request, reply) => {
            const usersList = await adminService.listUsers();
            return reply.send(usersList);
        }
    );

    // PATCH /admin/users/:id/role - Requires 'manage:roles' permission
    fastify.patch<{ Params: { id: string } }>(
        "/users/:id/role",
        { preHandler: [authorize("manage:roles")] },
        async (request, reply) => {
            const parseResult = updateRoleSchema.safeParse(request.body);
            if (!parseResult.success) {
                return reply.status(400).send({ error: "Bad Request", details: parseResult.error.format() });
            }

            try {
                const result = await adminService.updateUserRole(request.params.id, parseResult.data.role);
                return reply.send(result);
            } catch (err: any) {
                return reply.status(404).send({ error: "Not Found", message: err.message });
            }
        }
    );

    // PATCH /admin/users/:id/permissions - Requires 'manage:roles' permission
    fastify.patch<{ Params: { id: string } }>(
        "/users/:id/permissions",
        { preHandler: [authorize("manage:roles")] },
        async (request, reply) => {
            const parseResult = updatePermissionsSchema.safeParse(request.body);
            if (!parseResult.success) {
                return reply.status(400).send({ error: "Bad Request", details: parseResult.error.format() });
            }

            try {
                const result = await adminService.updateUserPermissions(request.params.id, parseResult.data.permissions);
                return reply.send(result);
            } catch (err: any) {
                return reply.status(404).send({ error: "Not Found", message: err.message });
            }
        }
    );

    // POST /admin/users/lock - Requires 'ban:users' permission
    fastify.post<{ Body: { email: string } }>(
        "/users/lock",
        { preHandler: [authorize("ban:users")] },
        async (request, reply) => {
            if (!request.body || !request.body.email) {
                return reply.status(400).send({ error: "Bad Request", message: "Email is required" });
            }

            const result = await adminService.lockUserAccount(request.body.email);
            return reply.send(result);
        }
    );
}
