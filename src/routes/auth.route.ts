// /src/routes/auth.route.ts
import { ExpressAuth } from "@auth/express";
import PostgresAdapter from "@auth/pg-adapter";
import { pool } from "../db.js";
import GitHub from "@auth/core/providers/github";
import Credentials from "@auth/express/providers/credentials"
import Google from "@auth/express/providers/google"
import bcrypt from "bcrypt";
import { Router } from "express";
import dotenv from "dotenv";
dotenv.config();

const { AUTH_SECRET, GITHUB_ID, GITHUB_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env;

if (!AUTH_SECRET) throw new Error("Missing AUTH_SECRET");
if (!GITHUB_ID || !GITHUB_SECRET) throw new Error("Missing GitHub OAuth credentials");
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) throw new Error("Missing GitHub OAuth credentials");

interface Session {
    user: {
        id: number;
        name?: string;
        email?: string;
        image?: string;
        role: "admin" | "user";
    };
}
const authConfig = {
    trustHost: true,
    secret: AUTH_SECRET!,
    adapter: PostgresAdapter(pool),
    providers: [
        GitHub({ clientId: GITHUB_ID, clientSecret: GITHUB_SECRET }),
        Google({ clientId: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET }),
        Credentials({
            credentials: {
                mode: {
                    type: "text",
                    label: "Mode",
                    placeholder: "login or register",
                },
                email: {
                    type: "email",
                    label: "Email",
                    placeholder: "johndoe@gmail.com",
                },
                password: {
                    type: "password",
                    label: "Password",
                    placeholder: "*****",
                },
                name: {
                    type: "text",
                    label: "Name",
                    placeholder: "John Doe (required for register)",
                    optional: true,
                },
            },
            authorize: async (credentials) => {
                const { mode, email, password, name } = credentials || {};

                if (!email || !password) {
                    throw new Error("Email and password are required.");
                }

                if (mode === "register") {
                    if (!name) {
                        throw new Error("Name is required for registration.");
                    }

                    // Check if user already exists
                    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
                    if (existingUser.rows.length > 0) {
                        throw new Error("User already exists.");
                    }

                    // Hash password
                    const hashedPassword = await hashPassword(password as string);

                    // Insert user
                    const insertResult = await pool.query(
                        `INSERT INTO users (email, name, role, hashed_password) VALUES ($1, $2, $3, $4) RETURNING *`,
                        [email, name, 'user', hashedPassword]
                    );

                    const newUser = insertResult.rows[0];

                    // Return new user object for session
                    return {
                        id: newUser.id,
                        name: newUser.name,
                        email: newUser.email,
                        role: newUser.role,
                    };
                } else if (mode === "login") {
                    // Existing login logic
                    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
                    const user = result.rows[0];
                    if (!user) {
                        throw new Error("Invalid credentials.");
                    }
                    const isValid = await verifyPassword(password as string, user.hashed_password);
                    if (!isValid) {
                        throw new Error("Invalid credentials.");
                    }
                    return {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        role: user.role,
                    };
                } else {
                    throw new Error("Invalid mode.");
                }
            }
        }),

    ],
    callbacks: {
        session: async ({ session, user }) => {
            // ✅ Add id and role to session.user
            session.user.id = user.id;
            session.user.role = user.role;
            return session;
        },
    },
};

// 🧠 2. Export both separately
export const authRoute = ExpressAuth(authConfig);
export const authConfigObject = authConfig;
async function saltAndHashPassword(_: unknown): Promise<string> {
    throw new Error("You shouldn't use this. Use verifyPassword() instead.");
}

async function getUserFromDb(email: string, plainPassword: string) {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];

    if (!user) return null;

    const isValid = await verifyPassword(plainPassword, user.hashed_password);
    if (!isValid) return null;

    return {
        id: user.id,
        name: user.name,
        email: user.email,
        image: user.image,
        role: user.role, // 👈 include this
    };
}


// Hash a plain password before storing it
export const hashPassword = async (plain: string) => {
    const saltRounds = 10;
    return await bcrypt.hash(plain, saltRounds);
};

// Compare a plain password with the stored hash
export const verifyPassword = async (plain: string, hash: string) => {
    return await bcrypt.compare(plain, hash);
};

export const registerRoute = Router();

registerRoute.post("/register", async (req, res) => {
    const { email, name, password, role } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Missing email or password" });
    }

    const hashedPassword = await hashPassword(password);

    try {
        await pool.query(
            `
            INSERT INTO users (email, name, role, hashed_password)
            VALUES ($1, $2, $3, $4)
            `,
            [email, name ?? null, role ?? 'user', hashedPassword]
        );

        res.status(201).json({ success: true });
    } catch (err: any) {
        if (err.code === "23505") {
            return res.status(409).json({ error: "User already exists" });
        }
        res.status(500).json({ error: "Registration failed", details: err.message });
    }
});
