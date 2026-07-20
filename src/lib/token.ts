import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

export interface RefreshTokenData {
    rawToken: string;
    hashedToken: string;
    familyId: string;
}

export interface AccessTokenPayload {
    userId: string;
    email: string;
}

// Custom domain errors for clean error handling across services and middleware
export class TokenVerificationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "TokenVerificationError";
    }
}

export class ExpiredTokenError extends TokenVerificationError {
    constructor(message = "Access token has expired") {
        super(message);
        this.name = "ExpiredTokenError";
    }
}

export class InvalidTokenError extends TokenVerificationError {
    constructor(message = "Invalid access token") {
        super(message);
        this.name = "InvalidTokenError";
    }
}

/**
 * Generates a short-lived (15 min) JWT access token.
 */
export function generateAccessToken(payload: AccessTokenPayload): string {
    return jwt.sign(payload, env.JWT_SECRET, {
        expiresIn: "15m",
    });
}

/**
 * Verifies and decodes a JWT access token.
 * Throws clean domain errors instead of generic/framework errors.
 */
export function verifyAccessToken(token: string): AccessTokenPayload {
    try {
        const decoded = jwt.verify(token, env.JWT_SECRET) as AccessTokenPayload;
        return decoded;
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            throw new ExpiredTokenError();
        }
        throw new InvalidTokenError();
    }
}

/**
 * Generates an opaque, cryptographically secure random refresh token along with its SHA-256 hash.
 * - `rawToken`: Sent to the client (in HTTP-only cookie or response body).
 * - `hashedToken`: Stored as the key in Upstash Redis.
 */
export function generateRefreshToken(existingFamilyId?: string): RefreshTokenData {
    const rawToken = crypto.randomBytes(40).toString("hex");
    const hashedToken = hashRefreshToken(rawToken);
    const familyId = existingFamilyId ?? crypto.randomUUID();
    return { rawToken, hashedToken, familyId };
}

/**
 * Computes the SHA-256 hash of a raw refresh token.
 * Used during `/refresh` or `/logout` to find the session in Upstash Redis.
 */
export function hashRefreshToken(rawToken: string): string {
    return crypto.createHash("sha256").update(rawToken).digest("hex");
}
