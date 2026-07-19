import { beforeEach, describe, expect, it, vi } from "vitest";
import { rateLimit } from "./rateLimit.js";

describe("Rate Limit Middleware Unit Tests", () => {
    let mockRequest: any;
    let mockReply: any;
    let mockLimiter: any;

    beforeEach(() => {
        mockRequest = {
            ip: "192.168.1.100",
        };
        mockReply = {
            header: vi.fn().mockReturnThis(),
            status: vi.fn().mockReturnThis(),
            send: vi.fn().mockReturnThis(),
        };
        mockLimiter = {
            limit: vi.fn(),
        };
    });

    it("should allow request and attach rate limit headers when under the limit", async () => {
        mockLimiter.limit.mockResolvedValue({
            success: true,
            limit: 5,
            remaining: 4,
            reset: 1700000000,
        });

        const middleware = rateLimit(mockLimiter);
        await middleware(mockRequest, mockReply);

        expect(mockReply.header).toHaveBeenCalledWith("X-RateLimit-Limit", 5);
        expect(mockReply.header).toHaveBeenCalledWith("X-RateLimit-Remaining", 4);
        expect(mockReply.header).toHaveBeenCalledWith("X-RateLimit-Reset", 1700000000);
        expect(mockReply.status).not.toHaveBeenCalled();
    });

    it("should return 429 Too Many Requests when rate limit is exceeded", async () => {
        mockLimiter.limit.mockResolvedValue({
            success: false,
            limit: 5,
            remaining: 0,
            reset: 1700000000,
        });

        const middleware = rateLimit(mockLimiter);
        await middleware(mockRequest, mockReply);

        expect(mockReply.status).toHaveBeenCalledWith(429);
        expect(mockReply.send).toHaveBeenCalledWith(
            expect.objectContaining({
                error: "Too Many Requests",
            })
        );
    });
});
