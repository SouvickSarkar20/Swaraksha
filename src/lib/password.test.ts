import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "./password.js";

describe("Password Hashing Utility", () => {
    it("should hash a plain text password into a valid bcrypt hash", async () => {
        const rawPassword = "SuperSecretPassword123!";
        const hash = await hashPassword(rawPassword);

        expect(hash).toBeDefined();
        expect(hash).not.toEqual(rawPassword);
        // Bcrypt hashes start with $2a$, $2b$, or $2y$ followed by the cost factor
        expect(hash).toMatch(/^\$2[aby]\$\d{2}\$.+/);
    });

    it("should return true when verifying the correct password against its hash", async () => {
        const rawPassword = "CorrectPassword2026!";
        const hash = await hashPassword(rawPassword);

        const isMatch = await verifyPassword(rawPassword, hash);
        expect(isMatch).toBe(true);
    });

    it("should return false when verifying an incorrect password against a hash", async () => {
        const rawPassword = "CorrectPassword2026!";
        const hash = await hashPassword(rawPassword);

        const isMatch = await verifyPassword("WrongPassword!", hash);
        expect(isMatch).toBe(false);
    });
});
