import { beforeEach, describe, expect, it, vi } from "vitest";
import { hashPassword } from "../../lib/password.js";
import { hashRefreshToken } from "../../lib/token.js";
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

            mockDb.query.users.findFirst.mockResolvedValue({
                id: "user-uuid-123",
                email: "user@example.com",
                passwordHash: hashed,
            });

            const tokens = await authService.login("user@example.com", plainPassword);

            expect(tokens.accessToken).toBeDefined();
            expect(tokens.refreshToken).toBeDefined();
            expect(mockRedis.set).toHaveBeenCalledTimes(1);
        });

        it("should throw InvalidCredentialsError when email is not found", async () => {
            mockDb.query.users.findFirst.mockResolvedValue(undefined);

            await expect(authService.login("ghost@example.com", "Password123!")).rejects.toThrow(
                InvalidCredentialsError
            );
            expect(mockRedis.set).not.toHaveBeenCalled();
        });

        it("should throw InvalidCredentialsError when password is incorrect", async () => {
            const hashed = await hashPassword("RealPassword123!");
            mockDb.query.users.findFirst.mockResolvedValue({
                id: "user-uuid-123",
                email: "user@example.com",
                passwordHash: hashed,
            });

            await expect(authService.login("user@example.com", "WrongPassword!")).rejects.toThrow(
                InvalidCredentialsError
            );
            expect(mockRedis.set).not.toHaveBeenCalled();
        });
    });

    describe("refresh()", () => {
        it("should rotate refresh token and issue new tokens when old token is valid in Redis", async () => {
            const rawToken = "old-raw-token-123";
            mockRedis.get.mockResolvedValue(JSON.stringify({ userId: "user-uuid-123" }));
            mockDb.query.users.findFirst.mockResolvedValue({
                id: "user-uuid-123",
                email: "user@example.com",
            });

            const tokens = await authService.refresh(rawToken);

            expect(tokens.accessToken).toBeDefined();
            expect(tokens.refreshToken).toBeDefined();
            expect(tokens.refreshToken).not.toBe(rawToken);

            // Verify the old token was deleted (rotated out!)
            expect(mockRedis.del).toHaveBeenCalledWith(`refresh_token:${hashRefreshToken(rawToken)}`);
            // Verify a new token was stored
            expect(mockRedis.set).toHaveBeenCalledTimes(1);
        });

        it("should throw InvalidRefreshTokenError when token is missing or expired in Redis", async () => {
            mockRedis.get.mockResolvedValue(null);

            await expect(authService.refresh("expired-token")).rejects.toThrow(
                InvalidRefreshTokenError
            );
            expect(mockRedis.del).not.toHaveBeenCalled();
        });
    });

    describe("logout()", () => {
        it("should delete the hashed refresh token from Upstash Redis", async () => {
            const rawToken = "my-active-refresh-token";
            await authService.logout(rawToken);

            expect(mockRedis.del).toHaveBeenCalledWith(
                `refresh_token:${hashRefreshToken(rawToken)}`
            );
        });
    });
});
