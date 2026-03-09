import Fastify from "fastify";
import cors from "@fastify/cors";
import multipart from "@fastify/multipart";
import rateLimit from "@fastify/rate-limit";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import bcrypt from "bcryptjs";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { pipeline } from "stream/promises";
import "dotenv/config";
import { initDb, seedTrialUsers } from "./db/index";

import {
  getUserByEmail,
  getUploads,
  createUploadRecord,
  getUploadByHash,
  getUploadMetadata,
  getAnomalyEventsPaginated,
  getRawLogsPaginated,
  getGlobalIntelligence,
  deleteUploadRecord,
} from "./db/queries";
import { analysisQueue } from "./queue/index";
import "./workers/analysisWorker";

const server = Fastify({ logger: true });

// 1. Initialize SQLite
initDb();

// 2. Seed Trial Users (Idempotent: will safely ignore if they already exist)
seedTrialUsers();

const isProd = process.env.NODE_ENV === "production";

// 2. Ensure Uploads Directory Exists
const uploadsDir = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, "uploads")
  : path.resolve(__dirname, "../uploads");

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// 3. Register Plugins
server.register(cors, {
  origin: [
    "http://localhost:5173",
    process.env.FRONTEND_URL || "", // We will set this variable in Railway
  ],
  credentials: true,
});

server.register(jwt, {
  secret: process.env.JWT_SECRET || "super-secure-soc-secret-key-12345",
});

server.register(cookie, {
  secret: process.env.COOKIE_SECRET || "cookie-signature-secret",
});

// Add Rate Limiter (max 10 uploads per minute per IP for testing)
server.register(rateLimit, {
  max: 10,
  timeWindow: "1 minute",
});

server.register(multipart, {
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

// ==========================================
// ROUTES
// ==========================================

const authenticate = async (request: any, reply: any) => {
  try {
    const token = request.cookies.token;
    if (!token)
      return reply.status(401).send({ error: "Authentication required" });

    // Verify token signature
    const payload = server.jwt.verify(token) as {
      userId: string;
      absoluteExp: number;
    };

    // Check ABSOLUTE Max Session Time (e.g. 8 hours)
    if (Date.now() > payload.absoluteExp) {
      reply.clearCookie("token");
      return reply
        .status(401)
        .send({ error: "Maximum session time exceeded. Please log in again." });
    }

    // ROLLING INACTIVITY RESET: User is active, so we push the 10-minute cookie death out by another 10 minutes
    reply.setCookie("token", token, {
      path: "/",
      httpOnly: true, // Prevents XSS attacks
      ssecure: isProd,
      sameSite: isProd ? "none" : "lax",
      maxAge: 10 * 60, // 10 minutes of inactivity allowed
    });

    request.user = payload;
  } catch (err) {
    reply.clearCookie("token");
    return reply.status(401).send({ error: "Session expired or invalid" });
  }
};

server.post("/api/auth/login", async (request, reply) => {
  const { email, password } = request.body as any;
  if (!email || !password)
    return reply.status(400).send({ error: "Email and password required" });

  const user = getUserByEmail(email);
  if (!user) return reply.status(401).send({ error: "Invalid credentials" });

  const isValid = await bcrypt.compare(password, user.password_hash);
  if (!isValid) return reply.status(401).send({ error: "Invalid credentials" });

  // 8 Hours absolute maximum session time from login
  const absoluteExp = Date.now() + 8 * 60 * 60 * 1000;
  const token = server.jwt.sign({
    userId: user.id,
    email: user.email,
    absoluteExp,
  });

  reply.setCookie("token", token, {
    path: "/",
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    maxAge: 10 * 60, // Starts the 10-minute inactivity timer
  });

  return reply.send({
    message: "Login successful",
    user: { id: user.id, email: user.email },
  });
});

server.post("/api/auth/logout", async (request, reply) => {
  reply.clearCookie("token", { path: "/" });
  return reply.send({ message: "Logged out" });
});

server.get(
  "/api/auth/me",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    return reply.send({ user: request.user });
  },
);

// Fetch logs (supports optional ?active=true query parameter)
server.get(
  "/api/logs",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    try {
      const { active } = request.query as { active?: string };
      // Pass userId
      const logs = getUploads(request.user.userId, active === "true");
      return reply.send(logs);
    } catch (err) {
      return reply.status(500).send({ error: "Failed to fetch logs" });
    }
  },
);

server.get(
  "/api/logs/check/:hash",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    const { hash } = request.params as { hash: string };
    // Pass userId
    const existing = getUploadByHash(request.user.userId, hash);
    if (existing)
      return reply.send({
        exists: true,
        uploadId: existing.id,
        status: existing.status,
      });
    return reply.send({ exists: false });
  },
);

// Upload Route
server.post(
  "/api/logs/upload",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    const data = await request.file();
    if (!data) return reply.status(400).send({ error: "No file uploaded" });

    const allowedExtensions = [".txt", ".csv", ".log"];
    const ext = path.extname(data.filename).toLowerCase();
    if (!allowedExtensions.includes(ext))
      return reply.status(415).send({ error: `Unsupported file type: ${ext}` });

    const fileHash = (data.fields.hash as any)?.value;
    if (!fileHash)
      return reply.status(400).send({ error: "File hash is required" });

    // Pass userId
    const existing = getUploadByHash(request.user.userId, fileHash);
    if (existing) {
      await data.toBuffer();
      return reply.send({
        uploadId: existing.id,
        status: existing.status,
        duplicate: true,
      });
    }

    const uploadId = crypto.randomUUID();
    const filePath = path.join(uploadsDir, `${uploadId}-${data.filename}`);

    try {
      await pipeline(data.file, fs.createWriteStream(filePath));

      // 2. Capture the file size from the disk
      const stats = fs.statSync(filePath);
      const fileSize = stats.size;

      // Pass userId during creation!
      createUploadRecord(
        request.user.userId,
        uploadId,
        data.filename,
        fileSize,
        fileHash,
        filePath,
      );

      await analysisQueue.add("process-log", { uploadId, filePath });
      return reply.send({ uploadId, status: "pending", duplicate: false });
    } catch (err: any) {
      console.error("UPLOAD ERROR:", err.message);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

      return reply
        .status(500)
        .send({ error: "Internal server error during upload" });
    }
  },
);

// Status & Results Polling Route
server.get(
  "/api/logs/:id",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    const { id } = request.params as { id: string };
    // Pass userId
    const results = getUploadMetadata(request.user.userId, id);
    if (!results)
      return reply.status(404).send({ error: "Log upload not found" });
    return reply.send(results);
  },
);

// Paginated Events Route with fully mapped frontend filters
server.get(
  "/api/logs/:id/events",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    const { id } = request.params as { id: string };
    const {
      page = "1",
      limit = "20",
      sortBy = "severity",
      category,
      clientIp,
      severity,
    } = request.query as any;

    try {
      // Pass userId
      const events = getAnomalyEventsPaginated(
        request.user.userId,
        id,
        parseInt(page, 10),
        parseInt(limit, 10),
        sortBy,
        category,
        clientIp,
        severity,
      );
      return reply.send({
        data: events,
        nextCursor:
          events.length === parseInt(limit, 10) ? parseInt(page, 10) + 1 : null,
      });
    } catch (error) {
      return reply
        .status(403)
        .send({ error: "Unauthorized or failed to fetch paginated events" });
    }
  },
);

server.get(
  "/api/logs/:id/raw",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    const { id } = request.params as { id: string };
    const { page = "1", limit = "20", search } = request.query as any;

    try {
      // Pass userId
      const result = getRawLogsPaginated(
        request.user.userId,
        id,
        parseInt(page, 10),
        parseInt(limit, 10),
        search,
      );
      return reply.send({
        data: result.events,
        totalRecords: result.totalRecords,
        totalPages: result.totalPages,
      });
    } catch (error) {
      return reply
        .status(403)
        .send({ error: "Unauthorized or failed to fetch raw logs" });
    }
  },
);

// ==========================================
// GLOBAL INTELLIGENCE DASHBOARD
// ==========================================
server.get(
  "/api/intelligence",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    const { timeRange = "24h" } = request.query as { timeRange?: string };
    try {
      // Pass userId
      const data = getGlobalIntelligence(request.user.userId, timeRange);
      return reply.send(data);
    } catch (error) {
      return reply
        .status(500)
        .send({ error: "Failed to fetch global intelligence" });
    }
  },
);

// Delete Log File Route
server.delete(
  "/api/logs/:id",
  { preHandler: [authenticate] },
  async (request: any, reply) => {
    const { id } = request.params as { id: string };

    try {
      const filePath = deleteUploadRecord(request.user.userId, id);

      if (!filePath) {
        return reply
          .status(404)
          .send({ error: "Log upload not found or unauthorized" });
      }

      // Delete the physical file from the Railway Volume / local disk
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }

      return reply.send({
        message: "File, raw logs, and anomalies deleted successfully",
      });
    } catch (error: any) {
      // Catch the active processing error and return a 409 Conflict
      if (error.message === "PROCESSING_ACTIVE") {
        return reply.status(409).send({
          error:
            "Cannot delete this log file because it is currently being analyzed by the AI. Please wait for it to finish.",
        });
      }

      server.log.error(error);
      return reply.status(500).send({ error: "Failed to delete log data" });
    }
  },
);

// ==========================================
// START SERVER
// ==========================================
const start = async () => {
  try {
    const port = parseInt(process.env.PORT || "3000", 10);
    await server.listen({ port, host: "0.0.0.0" });
    console.log(`🚀 SOC Analyzer API running at http://localhost:${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

start();
