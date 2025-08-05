// src/middleware/session.ts
import { getSession } from "@auth/express";
import { authConfigObject } from "../routes/auth.route.js";
import { Request, Response, NextFunction } from "express";

export async function authSession(req: Request, res: Response, next: NextFunction) {
    try {
        const session = await getSession(req, authConfigObject);
        res.locals.session = session;
        next();
    } catch (err) {
        res.locals.session = null;
        next();
    }
}
