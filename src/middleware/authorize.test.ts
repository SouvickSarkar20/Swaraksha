import type { FastifyReply, FastifyRequest } from "fastify";
import { describe, expect, it, vi } from "vitest";
import { authorize, authorizeRole } from "./authorize.js";

describe("Authorization Middleware", () => {
    // Helper to mock Fastify Request/Reply objects
    const createMockContext = (userPayload?: any) => {
        const request = { user: userPayload } as unknown as FastifyRequest;
        const reply = {
            status: vi.fn().mockReturnThis(),
            send: vi.fn(),
        } as unknown as FastifyReply;
        return { request, reply };
    };

    describe("authorize() permissions guard", () => {
        it("should return 401 if request.user is missing", async () => {
            const { request, reply } = createMockContext(undefined);
            const middleware = authorize("read:users");

            await middleware(request, reply);

            expect(reply.status).toHaveBeenCalledWith(401);
            expect(reply.send).toHaveBeenCalledWith(
                expect.objectContaining({ error: "Unauthorized" })
            );
        });

        it("should return 403 Forbidden if user lacks required permissions", async () => {
            const { request, reply } = createMockContext({
                userId: "123",
                permissions: ["read:profile"], // Missing read:users!
            });
            const middleware = authorize("read:users");

            await middleware(request, reply);

            expect(reply.status).toHaveBeenCalledWith(403);
            expect(reply.send).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: "Forbidden",
                    message: expect.stringContaining("Insufficient permissions"),
                })
            );
        });

        it("should pass silently (void) if user has all required permissions", async () => {
            const { request, reply } = createMockContext({
                userId: "123",
                permissions: ["read:profile", "read:users", "ban:users"],
            });
            const middleware = authorize("read:users", "ban:users");

            await middleware(request, reply);

            // If it passes, status() and send() should NEVER be called
            expect(reply.status).not.toHaveBeenCalled();
            expect(reply.send).not.toHaveBeenCalled();
        });
    });

    describe("authorizeRole() role guard", () => {
        it("should return 403 Forbidden if user role is not in allowed list", async () => {
            const { request, reply } = createMockContext({
                userId: "123",
                role: "USER",
            });
            const middleware = authorizeRole("ADMIN", "MODERATOR");

            await middleware(request, reply);

            expect(reply.status).toHaveBeenCalledWith(403);
        });

        it("should pass silently if user has an allowed role", async () => {
            const { request, reply } = createMockContext({
                userId: "123",
                role: "ADMIN",
            });
            const middleware = authorizeRole("ADMIN", "MODERATOR");

            await middleware(request, reply);

            expect(reply.status).not.toHaveBeenCalled();
        });
    });
});
