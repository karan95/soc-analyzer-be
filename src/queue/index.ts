import { Queue } from "bullmq";
import Redis from "ioredis";

// Use the exact same connection logic here!
const connection = process.env.REDIS_URL
  ? (new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: null,
      tls: process.env.REDIS_URL.startsWith("rediss://")
        ? { rejectUnauthorized: false }
        : undefined,
    }) as any)
  : {
      host: process.env.REDIS_HOST || "127.0.0.1",
      port: parseInt(process.env.REDIS_PORT || "6379", 10),
      keepAlive: 10000,
    };

export const analysisQueue = new Queue("log-analysis", { connection });
