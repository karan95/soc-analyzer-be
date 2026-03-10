import { Queue } from "bullmq";
import Redis from "ioredis";

const redisOptions: any = {
  maxRetriesPerRequest: null,
  enableOfflineQueue: false,
  keepAlive: 10000,
  pingInterval: 10000,
  family: 0,
  retryStrategy(times: number) {
    // Exponential backoff reconnect: 50ms, 100ms, 150ms... up to 2 seconds
    return Math.min(times * 50, 2000);
  },
  reconnectOnError(err: Error) {
    // Automatically reconnect on network errors like ETIMEDOUT
    return true;
  },
};

// initialize the connection using the shared options
const connection = process.env.REDIS_URL
  ? new Redis(process.env.REDIS_URL, {
      ...redisOptions,
      tls: process.env.REDIS_URL.startsWith("rediss://")
        ? { rejectUnauthorized: false }
        : undefined,
    })
  : new Redis({
      host: process.env.REDIS_HOST || "127.0.0.1",
      port: parseInt(process.env.REDIS_PORT || "6379", 10),
      ...redisOptions,
    });

export const analysisQueue = new Queue("soc-logs-queue", {
  connection: connection as any,
});

analysisQueue.on("error", (err) => {
  // We swallow the error cleanly. The ioredis retryStrategy will auto-reconnect.
  console.warn(
    "[BullMQ Queue] Background connection drop caught & auto-healing:",
    err.message,
  );
});
