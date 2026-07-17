import { eq } from "drizzle-orm";
import { db } from "../../db/client.js";
import { users, type User } from "../../db/schema.js";
import { hashPassword, verifyPassword } from "../../lib/password.js";
import {
    generateAccessToken,
    generateRefreshToken,
    hashRefreshToken,
} from "../../lib/token.js";
import { redis } from "../../redis/client.js";

// Dummy hash used for timing-safe dummy comparisons when a user is not found
const DUMMY_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4h1y/z5/fO";

// 7 days in seconds for Upstash Redis TTL
const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7;

export class InvalidCredentialsError extends Error {
    constructor(message = "Invalid email or password") {
        super(message);
        this.name = "InvalidCredentialsError";
    }
}

export class InvalidRefreshTokenError extends Error {
    constructor(message = "Invalid or expired refresh token") {
        super(message);
        this.name = "InvalidRefreshTokenError";
    }
}

export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
}

export class AuthService {
    /**
     * Timing-safe and non-enumerating signup.
     * Never reveals whether the email already exists or not.
     */
    async signup(email: string, plainPassword: string): Promise<{ success: boolean; message: string }> {
        const existingUser = await db.query.users.findFirst({
            where: eq(users.email, email.toLowerCase()),
        });

        if (existingUser) {
            // Dummy hash to prevent timing attacks revealing the email is taken
            await hashPassword(plainPassword);
            return {
                success: true,
                message: "If the email is valid, your account has been created successfully.",
            };
        }

        const passwordHash = await hashPassword(plainPassword);
        await db.insert(users).values({
            email: email.toLowerCase(),
            passwordHash,
        });

        return {
            success: true,
            message: "If the email is valid, your account has been created successfully.",
        };
    }

    /**
     * Timing-safe login that issues a short-lived access JWT and a long-lived opaque refresh token.
     */
    async login(email: string, plainPassword: string): Promise<AuthTokens> {
        const user = await db.query.users.findFirst({
            where: eq(users.email, email.toLowerCase()),
        });

        if (!user) {
            // Dummy check to prevent timing attacks revealing the email is not registered
            await verifyPassword(plainPassword, DUMMY_HASH);
            throw new InvalidCredentialsError();
        }

        const isPasswordValid = await verifyPassword(plainPassword, user.passwordHash);
        if (!isPasswordValid) {
            throw new InvalidCredentialsError();
        }

        // Generate tokens
        const accessToken = generateAccessToken({ userId: user.id, email: user.email });
        const { rawToken, hashedToken } = generateRefreshToken();

        // Store hashed refresh token in Upstash Redis with a 7-day TTL
        await redis.set(`refresh_token:${hashedToken}`, JSON.stringify({ userId: user.id }), {
            ex: REFRESH_TOKEN_TTL_SECONDS,
        });

        return {
            accessToken,
            refreshToken: rawToken,
        };
    }

    /**
     * Validates a refresh token, rotates it (invalidating the old one), and returns new tokens.
     */
    async refresh(rawRefreshToken: string): Promise<AuthTokens> {
        const hashedToken = hashRefreshToken(rawRefreshToken);
        const redisKey = `refresh_token:${hashedToken}`;

        const sessionData = await redis.get<string | { userId: string }>(redisKey);
        if (!sessionData) {
            throw new InvalidRefreshTokenError();
        }

        // Upstash SDK sometimes returns parsed JSON directly or as string depending on setup
        const parsed = typeof sessionData === "string" ? JSON.parse(sessionData) : sessionData;
        const userId = parsed.userId;

        // Look up user to get fresh email for JWT claims
        const user = await db.query.users.findFirst({
            where: eq(users.id, userId),
        });

        if (!user) {
            await redis.del(redisKey);
            throw new InvalidRefreshTokenError();
        }

        // ROTATION: Delete the old refresh token so it cannot be used again
        await redis.del(redisKey);

        // Issue brand new tokens
        const accessToken = generateAccessToken({ userId: user.id, email: user.email });
        const { rawToken: newRawToken, hashedToken: newHashedToken } = generateRefreshToken();

        await redis.set(`refresh_token:${newHashedToken}`, JSON.stringify({ userId: user.id }), {
            ex: REFRESH_TOKEN_TTL_SECONDS,
        });

        return {
            accessToken,
            refreshToken: newRawToken,
        };
    }

    /**
     * Logs out a user by deleting their current refresh token from Upstash Redis.
     */
    async logout(rawRefreshToken: string): Promise<void> {
        const hashedToken = hashRefreshToken(rawRefreshToken);
        await redis.del(`refresh_token:${hashedToken}`);
    }
}

export const authService = new AuthService();
