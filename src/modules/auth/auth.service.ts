import { eq } from "drizzle-orm";
import { db } from "../../db/client.js";
import { computeUserPermissions, type UserRole } from "../../lib/rbac.js";
import { users, type User } from "../../db/schema.js";
import {
    generateBackupCodes,
    generateTotpSecret,
    verifyAndConsumeBackupCode,
    verifyTotpCode,
} from "../../lib/mfa.js";
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
const MFA_CHALLENGE_TTL_SECONDS = 60 * 5; // 5 minutes
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

export class InvalidMfaCodeError extends Error {
    constructor(message = "Invalid 2FA code or emergency backup code") {
        super(message);
        this.name = "InvalidMfaCodeError";
    }
}

export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
}

export type LoginResult =
    | AuthTokens
    | { mfaRequired: true; challengeToken: string };

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

    async login(email: string, plainPassword: string): Promise<LoginResult> {
        const normalizedEmail = email.toLowerCase();
        const lockoutKey = `failed_logins:${normalizedEmail}`;

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

        await redis.del(lockoutKey);

        // MFA STATE MACHINE CHECK
        if (user.isMfaEnabled) {
            const challengeToken = crypto.randomUUID();
            await redis.set(
                `mfa_challenge:${challengeToken}`,
                JSON.stringify({ userId: user.id }),
                { ex: MFA_CHALLENGE_TTL_SECONDS }
            );
            return { mfaRequired: true, challengeToken };
        }

        return this.issueTokensForUser(user);
    }

    async verifyMfaLogin(challengeToken: string, code: string): Promise<AuthTokens> {
        const challengeKey = `mfa_challenge:${challengeToken}`;
        const challengeData = await redis.get<string | { userId: string }>(challengeKey);

        if (!challengeData) {
            throw new InvalidCredentialsError("MFA challenge expired or invalid. Please log in again.");
        }

        const parsed = typeof challengeData === "string" ? JSON.parse(challengeData) : challengeData;
        const user = await db.query.users.findFirst({
            where: eq(users.id, parsed.userId),
        });

        if (!user || !user.totpSecret) {
            await redis.del(challengeKey);
            throw new InvalidCredentialsError();
        }

        // Check TOTP code first
        let isCodeValid = verifyTotpCode(user.totpSecret, code);

        // If not valid TOTP, check backup recovery codes
        if (!isCodeValid && user.backupCodes && user.backupCodes.length > 0) {
            const backupResult = verifyAndConsumeBackupCode(code, user.backupCodes);
            if (backupResult.isValid) {
                isCodeValid = true;
                await db
                    .update(users)
                    .set({ backupCodes: backupResult.remainingCodes })
                    .where(eq(users.id, user.id));
            }
        }

        if (!isCodeValid) {
            await this.recordFailedAttempt(`failed_logins:${user.email}`);
            throw new InvalidMfaCodeError();
        }

        await redis.del(challengeKey);
        return this.issueTokensForUser(user);
    }

    async setupMfa(userId: string): Promise<{ secret: string; otpauthUrl: string; rawBackupCodes: string[] }> {
        const user = await db.query.users.findFirst({
            where: eq(users.id, userId),
        });

        if (!user) {
            throw new InvalidCredentialsError("User not found");
        }

        const { secret, otpauthUrl } = generateTotpSecret(user.email);
        const { rawCodes, hashedCodes } = generateBackupCodes();

        await db
            .update(users)
            .set({
                totpSecret: secret,
                backupCodes: hashedCodes,
                isMfaEnabled: false, // Remains false until verified in enableMfa!
            })
            .where(eq(users.id, userId));

        return { secret, otpauthUrl, rawBackupCodes: rawCodes };
    }

    async enableMfa(userId: string, code: string): Promise<{ success: boolean; message: string }> {
        const user = await db.query.users.findFirst({
            where: eq(users.id, userId),
        });

        if (!user || !user.totpSecret) {
            throw new InvalidMfaCodeError("MFA setup has not been initiated.");
        }

        if (!verifyTotpCode(user.totpSecret, code)) {
            throw new InvalidMfaCodeError("Invalid verification code. Please check your authenticator app.");
        }

        await db
            .update(users)
            .set({ isMfaEnabled: true })
            .where(eq(users.id, userId));

        return { success: true, message: "Multi-factor authentication enabled successfully." };
    }

    async disableMfa(userId: string, plainPassword: string, code: string): Promise<{ success: boolean; message: string }> {
        const user = await db.query.users.findFirst({
            where: eq(users.id, userId),
        });

        if (!user) {
            throw new InvalidCredentialsError("User not found");
        }

        const isPasswordValid = await verifyPassword(plainPassword, user.passwordHash);
        if (!isPasswordValid) {
            throw new InvalidCredentialsError("Incorrect password.");
        }

        if (!user.totpSecret || !verifyTotpCode(user.totpSecret, code)) {
            throw new InvalidMfaCodeError("Invalid 2FA code.");
        }

        await db
            .update(users)
            .set({
                isMfaEnabled: false,
                totpSecret: null,
                backupCodes: null,
            })
            .where(eq(users.id, userId));

        return { success: true, message: "Multi-factor authentication disabled successfully." };
    }

    private async issueTokensForUser(user: User): Promise<AuthTokens> {
        const accessToken = generateAccessToken({
            userId: user.id,
            email: user.email,
            role: user.role, // Embed their primary role
            permissions: computeUserPermissions(user.role as UserRole, user.permissions || []), // Compute their exact granular scopes
        });
        const { rawToken, hashedToken, familyId } = generateRefreshToken();

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

        session.isRotated = true;
        await redis.set(redisKey, JSON.stringify(session), { ex: REFRESH_TOKEN_TTL_SECONDS });

        const accessToken = generateAccessToken({
            userId: user.id,
            email: user.email,
            role: user.role,
            permissions: computeUserPermissions(user.role as UserRole, user.permissions || []),
        });
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
