import { z } from "zod";

export const updateRoleSchema = z.object({
    role: z.enum(["USER", "MODERATOR", "ADMIN"], {
        errorMap: () => ({ message: "Role must be USER, MODERATOR, or ADMIN" }),
    }),
});

export const updatePermissionsSchema = z.object({
    permissions: z.array(z.string()).min(0),
});
