import { Request, Response, NextFunction } from "express";
import { getSession } from "@auth/express";
import { authConfigObject } from "../routes/auth.route.js"; // this should export your ExpressAuth config


export const requireRole = (role: "admin" | "user") => {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const session = await getSession(req, authConfigObject); // ✅ pass full config

            if (!(session?.user)) {
                return res.status(401).json({ error: "Unauthorized" });
            }

            if ((session.user as any).role !== role) {
                return res.status(403).json({ error: `Forbidden: Requires ${role} role` });
            }


            // You can attach session.user to req if needed globally
            (req as any).user = session.user;

            next();
        } catch (error) {
            console.error("Auth error:", error);
            return res.status(401).json({ error: "Unauthorized" });
        }
    };
};
