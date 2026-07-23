export type UserRole = "USER" | "MODERATOR" | "ADMIN";

export const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
    USER: ["read:profile", "update:profile"],
    MODERATOR: ["read:profile", "update:profile", "read:users", "ban:users"],
    ADMIN: ["read:profile", "update:profile", "read:users", "ban:users", "delete:users", "manage:roles"],
};

export function computeUserPermissions(role: UserRole, customPermissions: string[] = []): string[] {
    const base = ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS.USER;
    return Array.from(new Set([...base, ...customPermissions]));
}
