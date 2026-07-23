import { boolean, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
    id: uuid("id").primaryKey().defaultRandom(),
    email: text("email").notNull().unique(),
    passwordHash: text("password_hash").notNull(),
    isMfaEnabled: boolean("is_mfa_enabled").default(false).notNull(),
    totpSecret: text("totp_secret"),
    backupCodes: text("backup_codes").array(),
    role: text("role").default("USER").notNull(),
    permissions: text("permissions").array().default([]).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// Type inference from schema so we don't duplicate types manually!
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
