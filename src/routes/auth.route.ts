import { ExpressAuth } from "@auth/express";
import PostgresAdapter from "@auth/pg-adapter";
import { pool } from "../db.js";
import GitHub from "@auth/core/providers/github";
import Credentials from "@auth/express/providers/credentials";
import Google from "@auth/express/providers/google";
import bcrypt from "bcrypt";
import { Router } from "express";
import dotenv from "dotenv";
dotenv.config();

const { AUTH_SECRET, GITHUB_ID, GITHUB_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env;

if (!AUTH_SECRET) throw new Error("Missing AUTH_SECRET");
if (!GITHUB_ID || !GITHUB_SECRET) throw new Error("Missing GitHub OAuth credentials");
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) throw new Error("Missing Google OAuth credentials");

declare module "@auth/express" {
    interface Session {
        user: {
            id: string;
            role: string;
        };
    }
}

const authConfig = {
    trustHost: true,
    secret: AUTH_SECRET!,
    adapter: PostgresAdapter(pool),

    // <<< IMPORTANT: Use DATABASE session strategy to enable session storage and cookie setting for Credentials provider
    session: {
        strategy: "jwt" as const,
        maxAge: 30 * 24 * 60 * 60, // 30 days
    },

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

                    // Check if user exists
                    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
                    if (existingUser.rows.length > 0) {
                        throw new Error("User already exists.");
                    }

                    // Hash password
                    const hashedPassword = await hashPassword(password as string);

                    // Insert user
                    const insertResult = await pool.query(
                        `INSERT INTO users (email, name, role, hashed_password) VALUES ($1, $2, $3, $4) RETURNING *`,
                        [email, name, "user", hashedPassword]
                    );

                    const newUser = insertResult.rows[0];

                    return {
                        id: newUser.id,
                        name: newUser.name,
                        email: newUser.email,
                        image: newUser.image || null,
                        role: newUser.role,
                    };
                } else if (mode === "login") {
                    // Login
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
                        image: user.image || null,
                        role: user.role,
                    };
                } else {
                    throw new Error("Invalid mode.");
                }
            },
        }),
    ],

    callbacks: {
        async jwt({ token, user }: any) {
            // On sign-in, merge user info into the JWT
            if (user) {
                token.id = user.id;
                token.role = user.role;
            }
            return token;
        },
        session: async ({ session, token }: any) => {
            session.user.id = token.id;
            session.user.role = token.role;
            console.log("SESSION CALLBACK:", session); // This should log on every session creation/request
            return session;
        },
    },
};

export const authRoute = ExpressAuth(authConfig);
export const authConfigObject = authConfig;

// Password hash/verify helpers
export const hashPassword = async (plain: string) => {
    const saltRounds = 10;
    return await bcrypt.hash(plain, saltRounds);
};

export const verifyPassword = async (plain: string, hash: string) => {
    return await bcrypt.compare(plain, hash);
};

// Optional: separate Express Router for manual register API
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
            [email, name ?? null, role ?? "user", hashedPassword]
        );

        res.status(201).json({ success: true });
    } catch (err: any) {
        if (err.code === "23505") {
            return res.status(409).json({ error: "User already exists" });
        }
        res.status(500).json({ error: "Registration failed", details: err.message });
    }
});
