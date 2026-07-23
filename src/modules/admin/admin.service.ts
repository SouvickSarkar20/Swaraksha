import { eq, desc } from "drizzle-orm";
import { db } from "../../db/client.js";
import { users } from "../../db/schema.js";
import { redis } from "../../redis/client.js";

export class AdminService {
    async listUsers() {
        // Select specific fields so we never leak password hashes!
        const allUsers = await db.select({
            id: users.id,
            email: users.email,
            role: users.role,
            permissions: users.permissions,
            isMfaEnabled: users.isMfaEnabled,
            createdAt: users.createdAt,
        })
            .from(users)
            .orderBy(desc(users.createdAt))
            .limit(50);

        return allUsers;
    }

    async updateUserRole(targetUserId: string, newRole: "USER" | "MODERATOR" | "ADMIN") {
        const updated = await db
            .update(users)
            .set({ role: newRole })
            .where(eq(users.id, targetUserId))
            .returning({ id: users.id, role: users.role });

        if (updated.length === 0) {
            throw new Error("User not found");
        }
        return updated[0];
    }

    async updateUserPermissions(targetUserId: string, permissions: string[]) {
        const updated = await db
            .update(users)
            .set({ permissions })
            .where(eq(users.id, targetUserId))
            .returning({ id: users.id, permissions: users.permissions });

        if (updated.length === 0) {
            throw new Error("User not found");
        }
        return updated[0];
    }

    async lockUserAccount(targetEmail: string) {
        const lockoutKey = `failed_logins:${targetEmail.toLowerCase()}`;
        // Artificially set their failed logins to 999 and lock them for 24 hours
        await redis.set(lockoutKey, 999, { ex: 60 * 60 * 24 });
        return { success: true, message: `Account ${targetEmail} administratively locked for 24 hours.` };
    }
}

export const adminService = new AdminService();
