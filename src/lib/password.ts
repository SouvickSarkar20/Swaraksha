import bcrypt from "bcrypt";
import { env } from "../config/env.js";

const COST_FACTOR = env.NODE_ENV === "test" ? 10 : 12;


export async function hashPassword(plainPassword: string): Promise<string> {
    return bcrypt.hash(plainPassword, COST_FACTOR);
}

/**
 * Verifies if a plain text password matches a stored bcrypt hash.
 * Bcrypt uses timing-safe string comparison internally during verification.
 */
export async function verifyPassword(plainPassword: string, hash: string): Promise<boolean> {
    return bcrypt.compare(plainPassword, hash);
}
