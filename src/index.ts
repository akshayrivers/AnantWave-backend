import express from "express";
import dotenv from "dotenv";
import { authRoute } from "./routes/auth.route.js";
import { registerRoute } from "./routes/auth.route.js";
import { authSession } from "./middleware/session.js";
import { requireRole } from "./middleware/requireRole.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON body (for login, register, etc.)
app.use(express.json());

// Required for Auth.js when behind proxy (e.g., Vercel, Railway, etc.)
app.set("trust proxy", true);

// Attach session to res.locals
app.use(authSession);

// ✅ Mount Auth.js at "/auth" (no wildcard!)
app.use("/auth", authRoute);

// Custom routes
app.use("/api", registerRoute);

// Test route
app.get("/", (req, res) => {
    res.send("Hello from Express + Auth.js + PostgreSQL!");
});
app.get("/hmm", requireRole("admin"), (_req: any, res: { send: (arg0: string) => void; }) => {
    res.send("Hello from Express + Auth.js + PostgreSQL!");
});

app.listen(PORT, () => {
    console.log(`🚀 Server is running at http://localhost:${PORT}`);
});
