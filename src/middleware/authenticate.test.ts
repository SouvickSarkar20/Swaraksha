import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateAccessToken } from "../lib/token.js";
import { authenticate } from "./authenticate.js";

describe("Authenticate Middleware Unit Tests", () => {
    let mockRequest: any;
    let mockReply: any;

    beforeEach(() => {
        mockRequest = {
            headers: {},
        };
        mockReply = {
            status: vi.fn().mockReturnThis(),
            send: vi.fn().mockReturnThis(),
        };
    });

    it("should attach decoded user to request when a valid Bearer token is provided", async () => {
        const validToken = generateAccessToken({
            userId: "uuid-123",
            email: "test@example.com",
        });
        mockRequest.headers.authorization = `Bearer ${validToken}`;

        await authenticate(mockRequest, mockReply);

        expect(mockRequest.user).toBeDefined();
        expect(mockRequest.user.userId).toBe("uuid-123");
        expect(mockReply.status).not.toHaveBeenCalled();
    });

    it("should return 401 when Authorization header is missing", async () => {
        await authenticate(mockRequest, mockReply);

        expect(mockReply.status).toHaveBeenCalledWith(401);
        expect(mockReply.send).toHaveBeenCalledWith(
            expect.objectContaining({
                error: "Unauthorized",
            })
        );
        expect(mockRequest.user).toBeUndefined();
    });

    it("should return 401 when token is invalid or tampered with", async () => {
        mockRequest.headers.authorization = "Bearer invalid.jwt.token";

        await authenticate(mockRequest, mockReply);

        expect(mockReply.status).toHaveBeenCalledWith(401);
        expect(mockReply.send).toHaveBeenCalledWith(
            expect.objectContaining({
                message: "Invalid access token.",
            })
        );
        expect(mockRequest.user).toBeUndefined();
    });
});
