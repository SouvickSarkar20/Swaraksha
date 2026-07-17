import { describe, expect, it } from "vitest";
import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
import {
    ExpiredTokenError,
    InvalidTokenError,
    generateAccessToken,
    generateRefreshToken,
    hashRefreshToken,
    verifyAccessToken,
} from "./token.js";

describe("Token Generation & Verification Utility", () => {
    describe("Access Tokens (JWT)", () => {
        it("should generate a valid JWT and decode its payload cleanly", () => {
            const payload = { userId: "user-123", email: "test@example.com" };
            const token = generateAccessToken(payload);

            expect(typeof token).toBe("string");

            const decoded = verifyAccessToken(token);
            expect(decoded.userId).toBe(payload.userId);
            expect(decoded.email).toBe(payload.email);
        });

        it("should throw ExpiredTokenError when verifying an expired JWT", () => {
            // Create a token that expired 1 second ago
            const expiredToken = jwt.sign({ userId: "user-123", email: "test@example.com" }, env.JWT_SECRET, {
                expiresIn: "-1s",
            });

            expect(() => verifyAccessToken(expiredToken)).toThrow(ExpiredTokenError);
        });

        it("should throw InvalidTokenError when verifying a tampered/malformed JWT", () => {
            const token = generateAccessToken({ userId: "user-123", email: "test@example.com" });
            const tamperedToken = token + "tampered";

            expect(() => verifyAccessToken(tamperedToken)).toThrow(InvalidTokenError);
            expect(() => verifyAccessToken("not-a-jwt")).toThrow(InvalidTokenError);
        });
    });

    describe("Refresh Tokens (Opaque + Hashed)", () => {
        it("should generate a secure raw token and a distinct SHA-256 hash", () => {
            const { rawToken, hashedToken } = generateRefreshToken();

            expect(rawToken).toBeDefined();
            expect(rawToken.length).toBe(80); // 40 bytes in hex = 80 characters
            expect(hashedToken).toBeDefined();
            expect(hashedToken).not.toBe(rawToken);
            expect(hashedToken.length).toBe(64); // SHA-256 hex is always 64 characters
        });

        it("should consistently produce the same hash for the same raw refresh token", () => {
            const { rawToken, hashedToken } = generateRefreshToken();
            const recomputedHash = hashRefreshToken(rawToken);

            expect(recomputedHash).toBe(hashedToken);
        });
    });
});
