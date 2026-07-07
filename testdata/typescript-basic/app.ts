import express from "express";
import { validateToken, authorize } from "./auth";
import { getConfig } from "./config";

const app = express();

app.get("/api/data", async (req, res) => {
  const token = req.headers.authorization;
  const user = validateToken(token);
  if (!user) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }

  if (!authorize(user, getConfig().allowedGroups)) {
    res.status(403).json({ error: "forbidden" });
    return;
  }

  res.json({ data: "secret stuff" });
});

app.get("/admin/dashboard", async (req, res) => {
  const token = req.headers.authorization;
  const user = validateToken(token);
  // No authorization check - anyone with a valid token can access admin
  res.json({ admin: true, user });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

function handler(req: any, res: any) {
  const token = req.headers.authorization;
  const user = validateToken(token);
  if (!authorize(user, [])) {
    throw new Error("forbidden");
  }
  res.json({ ok: true });
}

export default app;
