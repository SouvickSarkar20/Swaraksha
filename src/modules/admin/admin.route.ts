import type { FastifyInstance } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import { authenticate } from "../../middleware/authenticate.js";
import { authorize } from "../../middleware/authorize.js";
import { apiLimiter, rateLimit } from "../../middleware/rateLimit.js";
import { adminService } from "./admin.service.js";
import { updatePermissionsSchema, updateRoleSchema } from "./admin.schema.js";

export async function adminRoutes(fastifyApp: FastifyInstance): Promise<void> {
    const fastify = fastifyApp.withTypeProvider<ZodTypeProvider>();

    // All admin routes globally require Rate Limiting + Authentication
    fastify.addHook("preHandler", rateLimit(apiLimiter));
    fastify.addHook("preHandler", authenticate);

    // GET /admin/users - Requires 'read:users' permission
    fastify.get(
        "/users",
        { 
            preHandler: [authorize("read:users")],
            schema: { security: [{ bearerAuth: [] }] }
        },
        async (request, reply) => {
            const usersList = await adminService.listUsers();
            return reply.send(usersList);
        }
    );

    // PATCH /admin/users/:id/role - Requires 'manage:roles' permission
    fastify.patch(
        "/users/:id/role",
        { 
            preHandler: [authorize("manage:roles")],
            schema: { 
                params: z.object({ id: z.string() }),
                body: updateRoleSchema,
                security: [{ bearerAuth: [] }]
            }
        },
        async (request, reply) => {
            try {
                const result = await adminService.updateUserRole(request.params.id, request.body.role);
                return reply.send(result);
            } catch (err: any) {
                return reply.status(404).send({ error: "Not Found", message: err.message });
            }
        }
    );

    // PATCH /admin/users/:id/permissions - Requires 'manage:roles' permission
    fastify.patch(
        "/users/:id/permissions",
        { 
            preHandler: [authorize("manage:roles")],
            schema: { 
                params: z.object({ id: z.string() }),
                body: updatePermissionsSchema,
                security: [{ bearerAuth: [] }]
            }
        },
        async (request, reply) => {
            try {
                const result = await adminService.updateUserPermissions(request.params.id, request.body.permissions);
                return reply.send(result);
            } catch (err: any) {
                return reply.status(404).send({ error: "Not Found", message: err.message });
            }
        }
    );

    // POST /admin/users/lock - Requires 'ban:users' permission
    fastify.post(
        "/users/lock",
        { 
            preHandler: [authorize("ban:users")],
            schema: { 
                body: z.object({ email: z.string().email() }),
                security: [{ bearerAuth: [] }]
            }
        },
        async (request, reply) => {
            const result = await adminService.lockUserAccount(request.body.email);
            return reply.send(result);
        }
    );
}
