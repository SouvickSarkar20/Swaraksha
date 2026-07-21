import * as OTPAuth from "otpauth";
import { describe, expect, it } from "vitest";
import {
    generateBackupCodes,
    generateTotpSecret,
    verifyAndConsumeBackupCode,
    verifyTotpCode,
} from "./mfa.js";

describe("MFA utility Unit Test", () => {

    describe("generateTotpSecret() & verifyTotpCode()", () => {

        it("should generate a valid Base32 secret and otpauth URI", () => {
            const email = "user@example.com";
            const { secret, otpauthUrl } = generateTotpSecret(email);
            expect(typeof secret).toBe("string");
            expect(secret.length).toBeGreaterThan(16);
            expect(otpauthUrl).toContain("otpauth://totp/Swaraksha%20API:user%40example.com");
            expect(otpauthUrl).toContain(`secret=${secret}`);
        });

        it("should return true when a valid 6-digit TOTP code is verified", () => {
            const { secret } = generateTotpSecret("user@example.com");
            // Generate the current valid token using otpauth directly
            const totp = new OTPAuth.TOTP({
                secret: OTPAuth.Secret.fromBase32(secret),
            });
            const validCode = totp.generate();
            expect(verifyTotpCode(secret, validCode)).toBe(true);
        });

        it("should return false when an incorrect or expired 6-digit code is provided", () => {
            const { secret } = generateTotpSecret("user@example.com");
            expect(verifyTotpCode(secret, "000000")).toBe(false);
        });
    });

    describe("generateBackupCodes() & verifyAndConsumeBackupCode()", () => {
        it("should generate 10 raw backup codes and 10 distinct SHA-256 hashes", () => {
            const { rawCodes, hashedCodes } = generateBackupCodes();
            expect(rawCodes).toHaveLength(10);
            expect(hashedCodes).toHaveLength(10);
            expect(rawCodes[0]).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}$/);
            expect(hashedCodes[0]).not.toBe(rawCodes[0]);
        });

        it("should verify a valid backup code and remove its hash from remainingCodes", () => {
            const { rawCodes, hashedCodes } = generateBackupCodes(5);
            const targetCode = rawCodes[2]; // Pick the 3rd code
            const result = verifyAndConsumeBackupCode(targetCode, hashedCodes);
            expect(result.isValid).toBe(true);
            expect(result.remainingCodes).toHaveLength(4);
            // Ensure the consumed code's hash is no longer in remainingCodes!
            expect(result.remainingCodes).not.toContain(hashedCodes[2]);
        });

        it("should return isValid: false when an invalid backup code is submitted", () => {
            const { hashedCodes } = generateBackupCodes(5);
            const result = verifyAndConsumeBackupCode("FFFF-FFFF", hashedCodes);
            expect(result.isValid).toBe(false);
            expect(result.remainingCodes).toHaveLength(5);
        });
    })
})