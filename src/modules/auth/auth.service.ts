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

const DUMMY_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4h1y/z5/fO";
const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const LOCKOUT_TTL_SECONDS = 60 * 15; // 15 minutes
const MAX_FAILED_ATTEMPTS = 5;

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

export class AccountLockedError extends Error {
    constructor(message = "Account temporarily locked for 15 minutes due to excessive failed attempts.") {
        super(message);
        this.name = "AccountLockedError";
    }
}

export class TokenTheftDetectedError extends Error {
    constructor(message = "Token theft or replay attack detected. All active sessions in this family have been revoked.") {
        super(message);
        this.name = "TokenTheftDetectedError";
    }
}

export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
}

interface StoredRefreshToken {
    userId: string;
    familyId: string;
    isRotated: boolean;
}

export class AuthService {
    async signup(email: string, plainPassword: string): Promise<{ success: boolean; message: string }> {
        const existingUser = await db.query.users.findFirst({
            where: eq(users.email, email.toLowerCase()),
        });

        if (existingUser) {
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

    async login(email: string, plainPassword: string): Promise<AuthTokens> {
        const normalizedEmail = email.toLowerCase();
        const lockoutKey = `failed_logins:${normalizedEmail}`;

        // 1. Check if account is currently locked out
        const failedAttempts = await redis.get<number>(lockoutKey);
        if (failedAttempts && failedAttempts >= MAX_FAILED_ATTEMPTS) {
            throw new AccountLockedError();
        }

        const user = await db.query.users.findFirst({
            where: eq(users.email, normalizedEmail),
        });

        if (!user) {
            await verifyPassword(plainPassword, DUMMY_HASH);
            await this.recordFailedAttempt(lockoutKey);
            throw new InvalidCredentialsError();
        }

        const isPasswordValid = await verifyPassword(plainPassword, user.passwordHash);
        if (!isPasswordValid) {
            await this.recordFailedAttempt(lockoutKey);
            throw new InvalidCredentialsError();
        }

        // 2. Successful login clears failed attempt counter
        await redis.del(lockoutKey);

        // 3. Generate tokens with a fresh familyId
        const accessToken = generateAccessToken({ userId: user.id, email: user.email });
        const { rawToken, hashedToken, familyId } = generateRefreshToken();

        // 4. Store token and register it inside the family set
        const storedData: StoredRefreshToken = { userId: user.id, familyId, isRotated: false };
        await redis.set(`refresh_token:${hashedToken}`, JSON.stringify(storedData), {
            ex: REFRESH_TOKEN_TTL_SECONDS,
        });
        await redis.sadd(`family_tokens:${familyId}`, hashedToken);
        await redis.expire(`family_tokens:${familyId}`, REFRESH_TOKEN_TTL_SECONDS);

        return { accessToken, refreshToken: rawToken };
    }

    private async recordFailedAttempt(lockoutKey: string): Promise<void> {
        const newCount = await redis.incr(lockoutKey);
        if (newCount === 1) {
            await redis.expire(lockoutKey, LOCKOUT_TTL_SECONDS);
        }
    }

    async refresh(rawRefreshToken: string): Promise<AuthTokens> {
        const hashedToken = hashRefreshToken(rawRefreshToken);
        const redisKey = `refresh_token:${hashedToken}`;

        const sessionData = await redis.get<string | StoredRefreshToken>(redisKey);
        if (!sessionData) {
            throw new InvalidRefreshTokenError();
        }

        const session: StoredRefreshToken =
            typeof sessionData === "string" ? JSON.parse(sessionData) : sessionData;

        // THEFT DETECTION: If token was already rotated, revoke the ENTIRE token family!
        if (session.isRotated) {
            await this.revokeTokenFamily(session.familyId);
            throw new TokenTheftDetectedError();
        }

        const user = await db.query.users.findFirst({
            where: eq(users.id, session.userId),
        });

        if (!user) {
            await redis.del(redisKey);
            throw new InvalidRefreshTokenError();
        }

        // ROTATION: Mark old token as rotated instead of deleting it immediately
        session.isRotated = true;
        await redis.set(redisKey, JSON.stringify(session), { ex: REFRESH_TOKEN_TTL_SECONDS });

        // Issue brand new token preserving the same familyId
        const accessToken = generateAccessToken({ userId: user.id, email: user.email });
        const { rawToken: newRawToken, hashedToken: newHashedToken } = generateRefreshToken(session.familyId);

        const newStoredData: StoredRefreshToken = {
            userId: user.id,
            familyId: session.familyId,
            isRotated: false,
        };
        await redis.set(`refresh_token:${newHashedToken}`, JSON.stringify(newStoredData), {
            ex: REFRESH_TOKEN_TTL_SECONDS,
        });
        await redis.sadd(`family_tokens:${session.familyId}`, newHashedToken);
        await redis.expire(`family_tokens:${session.familyId}`, REFRESH_TOKEN_TTL_SECONDS);

        return { accessToken, refreshToken: newRawToken };
    }

    private async revokeTokenFamily(familyId: string): Promise<void> {
        const familyKey = `family_tokens:${familyId}`;
        const allHashes = await redis.smembers(familyKey);

        if (allHashes && allHashes.length > 0) {
            const keysToDelete = allHashes.map((h) => `refresh_token:${h}`);
            await redis.del(...keysToDelete);
        }
        await redis.del(familyKey);
    }

    async logout(rawRefreshToken: string): Promise<void> {
        const hashedToken = hashRefreshToken(rawRefreshToken);
        const sessionData = await redis.get<string | StoredRefreshToken>(`refresh_token:${hashedToken}`);

        if (sessionData) {
            const session: StoredRefreshToken =
                typeof sessionData === "string" ? JSON.parse(sessionData) : sessionData;
            await this.revokeTokenFamily(session.familyId);
        } else {
            await redis.del(`refresh_token:${hashedToken}`);
        }
    }
}

export const authService = new AuthService();
