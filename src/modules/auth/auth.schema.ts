import { z } from "zod";

export const signupSchema = z.object({
    email: z.string().email("Invalid email format"),
    password: z
        .string()
        .min(8, "Password must be at least 8 characters long")
        .max(72, "Password cannot exceed 72 characters due to bcrypt limitations"),
});

export const loginSchema = z.object({
    email: z.string().email("Invalid email format"),
    password: z.string().min(1, "Password is required"),
});

export const refreshSchema = z.object({
    refreshToken: z.string().min(1, "Refresh token is required"),
});

export const logoutSchema = z.object({
    refreshToken: z.string().min(1, "Refresh token is required"),
});

export const loginMfaSchema = z.object({
    challengeToken: z.string().min(1, "Challenge token is required"),
    code: z.string().min(1, "Verification code or backup code is required"),
});
export const enableMfaSchema = z.object({
    code: z.string().min(1, "6-digit verification code is required"),
});
export const disableMfaSchema = z.object({
    password: z.string().min(1, "Password is required"),
    code: z.string().min(1, "Verification code is required"),
});
export type SignupInput = z.infer<typeof signupSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;
export type LogoutInput = z.infer<typeof logoutSchema>;
