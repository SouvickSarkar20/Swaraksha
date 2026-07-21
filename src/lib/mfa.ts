import crypto from "node:crypto";
import * as OTPAuth from "otpauth";
export interface TotpSecretData {
    secret: string;
    otpauthUrl: string;
}
export interface BackupCodesData {
    rawCodes: string[];
    hashedCodes: string[];
}
export function generateTotpSecret(email: string, issuer = "Swaraksha API"): TotpSecretData {
    const secret = new OTPAuth.Secret({ size: 20 });
    const totp = new OTPAuth.TOTP({
        issuer,
        label: email,
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        secret,
    });
    return {
        secret: secret.base32,
        otpauthUrl: totp.toString(),
    };
}
export function verifyTotpCode(secretBase32: string, code: string): boolean {
    try {
        const totp = new OTPAuth.TOTP({
            secret: OTPAuth.Secret.fromBase32(secretBase32),
            algorithm: "SHA1",
            digits: 6,
            period: 30,
        });
        const delta = totp.validate({ token: code, window: 1 });
        return delta !== null;
    } catch {
        return false;
    }
}
export function generateBackupCodes(count = 10): BackupCodesData {
    const rawCodes: string[] = [];
    const hashedCodes: string[] = [];
    for (let i = 0; i < count; i++) {
        const part1 = crypto.randomBytes(2).toString("hex").toUpperCase();
        const part2 = crypto.randomBytes(2).toString("hex").toUpperCase();
        const rawCode = `${part1}-${part2}`;
        rawCodes.push(rawCode);
        hashedCodes.push(hashBackupCode(rawCode));
    }
    return { rawCodes, hashedCodes };
}
export function hashBackupCode(code: string): string {
    return crypto.createHash("sha256").update(code.trim().toUpperCase()).digest("hex");
}
export function verifyAndConsumeBackupCode(
    rawCode: string,
    storedHashes: string[]
): { isValid: boolean; remainingCodes: string[] } {
    const inputHash = hashBackupCode(rawCode);
    const index = storedHashes.indexOf(inputHash);
    if (index === -1) {
        return { isValid: false, remainingCodes: storedHashes };
    }
    // Remove consumed hash cleanly without mutating original array
    const remainingCodes = storedHashes.filter((_, i) => i !== index);
    return { isValid: true, remainingCodes };
}