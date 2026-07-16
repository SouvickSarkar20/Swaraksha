import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import { env } from "../config/env.js";
import * as schema from "./schema.js";

// Initialize Neon HTTP connection
const sql = neon(env.DATABASE_URL);

// Pass schema so we can use Drizzle's relational query builder (`db.query...`)
export const db = drizzle(sql, { schema });
