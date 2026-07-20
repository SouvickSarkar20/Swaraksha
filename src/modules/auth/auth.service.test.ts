import { beforeEach, describe, expect, it, vi } from "vitest";
import { hashPassword } from "../../lib/password.js";
import { hashRefreshToken } from "../../lib/token.js";
// At the top of src/modules/auth/auth.service.test.ts inside vi.hoisted():
const { mockDb, mockRedis } = vi.hoisted(() => {
    return {
        mockDb: {
            query: {
                users: {
                    findFirst: vi.fn(),
                },
            },
            insert: vi.fn().mockReturnValue({
                values: vi.fn().mockResolvedValue([]),
            }),
        },
        mockRedis: {
            set: vi.fn(),
            get: vi.fn(),
            del: vi.fn(),
            incr: vi.fn(),
            sadd: vi.fn(),
            smembers: vi.fn(),
            expire: vi.fn(),
        },
    };
});

// 2. Now we can safely reference them inside vi.mock!
vi.mock("../../db/client.js", () => ({
    db: mockDb,
}));
vi.mock("../../redis/client.js", () => ({
    redis: mockRedis,
}));

import {
    AuthService,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    AccountLockedError,
    TokenTheftDetectedError,
} from "./auth.service.js";

describe("AuthService Unit Tests", () => {
    let authService: AuthService;

    beforeEach(() => {
        vi.clearAllMocks();
        authService = new AuthService();
    });

    describe("signup()", () => {
        it("should insert a new user and return success message when email is new", async () => {
            mockDb.query.users.findFirst.mockResolvedValue(undefined);

            const result = await authService.signup("new@example.com", "Password123!");

            expect(result.success).toBe(true);
            expect(mockDb.insert).toHaveBeenCalledTimes(1);
        });

        it("should return identical success message WITHOUT inserting when email is already taken (No Enumeration)", async () => {
            mockDb.query.users.findFirst.mockResolvedValue({
                id: "existing-uuid",
                email: "taken@example.com",
                passwordHash: "$2b$10$dummyhash...",
            });

            const result = await authService.signup("taken@example.com", "Password123!");

            expect(result.success).toBe(true);
            // Ensure we didn't try to insert duplicate user into DB!
            expect(mockDb.insert).not.toHaveBeenCalled();
        });
    });

    describe("login()", () => {
        it("should return access and refresh tokens when credentials are valid", async () => {
            const plainPassword = "ValidPassword2026!";
            const hashed = await hashPassword(plainPassword);
            mockRedis.get.mockResolvedValue(null); // Not locked out
            mockDb.query.users.findFirst.mockResolvedValue({
                id: "user-uuid-123",
                email: "user@example.com",
                passwordHash: hashed,
            });
            const tokens = await authService.login("user@example.com", plainPassword);
            expect(tokens.accessToken).toBeDefined();
            expect(tokens.refreshToken).toBeDefined();
            expect(mockRedis.del).toHaveBeenCalledWith("failed_logins:user@example.com");
            expect(mockRedis.set).toHaveBeenCalledTimes(1);
            expect(mockRedis.sadd).toHaveBeenCalledTimes(1);
        });
        it("should throw AccountLockedError immediately when failed_logins count in Redis is >= 5", async () => {
            mockRedis.get.mockResolvedValue(5); // Account is locked out!
            await expect(
                authService.login("user@example.com", "Password123!")
            ).rejects.toThrow(AccountLockedError);
            // Verify DB was not queried to save CPU and prevent timing leaks
            expect(mockDb.query.users.findFirst).not.toHaveBeenCalled();
        });
        it("should increment failed_logins counter in Redis when password is incorrect", async () => {
            const hashed = await hashPassword("RealPassword123!");
            mockRedis.get.mockResolvedValue(null);
            mockDb.query.users.findFirst.mockResolvedValue({
                id: "user-uuid-123",
                email: "user@example.com",
                passwordHash: hashed,
            });
            await expect(
                authService.login("user@example.com", "WrongPassword!")
            ).rejects.toThrow(InvalidCredentialsError);
            expect(mockRedis.incr).toHaveBeenCalledWith("failed_logins:user@example.com");
        });
    });

    describe("refresh()", () => {
        it("should mark old token as rotated and issue new tokens when old token is active", async () => {
            const rawToken = "old-raw-token-123";
            mockRedis.get.mockResolvedValue(
                JSON.stringify({ userId: "user-uuid-123", familyId: "fam-1", isRotated: false })
            );
            mockDb.query.users.findFirst.mockResolvedValue({
                id: "user-uuid-123",
                email: "user@example.com",
            });
            const tokens = await authService.refresh(rawToken);
            expect(tokens.accessToken).toBeDefined();
            expect(tokens.refreshToken).toBeDefined();
            expect(tokens.refreshToken).not.toBe(rawToken);
            // Verify old token was updated with isRotated: true and new token was saved
            expect(mockRedis.set).toHaveBeenCalledTimes(2);
            expect(mockRedis.sadd).toHaveBeenCalledTimes(1);
        });
        it("should throw TokenTheftDetectedError and delete all family keys when an already-rotated token is presented", async () => {
            const rawToken = "stolen-rotated-token";
            mockRedis.get.mockResolvedValue(
                JSON.stringify({ userId: "user-uuid-123", familyId: "fam-1", isRotated: true })
            );
            mockRedis.smembers.mockResolvedValue(["hash-1", "hash-2"]);
            await expect(authService.refresh(rawToken)).rejects.toThrow(TokenTheftDetectedError);
            // Verify that every token in the breached family tree plus the family set was deleted!
            expect(mockRedis.del).toHaveBeenCalledWith("refresh_token:hash-1", "refresh_token:hash-2");
            expect(mockRedis.del).toHaveBeenCalledWith("family_tokens:fam-1");
        });
        it("should throw InvalidRefreshTokenError when token is missing or expired in Redis", async () => {
            mockRedis.get.mockResolvedValue(null);
            await expect(authService.refresh("expired-token")).rejects.toThrow(
                InvalidRefreshTokenError
            );
        });
    });

    describe("logout()", () => {
        it("should delete the entire token family when session data exists", async () => {
            const rawToken = "my-active-refresh-token";
            mockRedis.get.mockResolvedValue(
                JSON.stringify({ userId: "user-uuid-123", familyId: "fam-1", isRotated: false })
            );
            mockRedis.smembers.mockResolvedValue(["hash-abc"]);
            await authService.logout(rawToken);
            expect(mockRedis.del).toHaveBeenCalledWith("refresh_token:hash-abc");
            expect(mockRedis.del).toHaveBeenCalledWith("family_tokens:fam-1");
        });
    });
});
