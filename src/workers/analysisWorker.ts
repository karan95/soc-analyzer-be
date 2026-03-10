import "dotenv/config";
import { Worker } from "bullmq";
import { GoogleGenerativeAI } from "@google/generative-ai";
import OpenAI from "openai";
import Redis from "ioredis";
import path from "path";
import { parseZScalerLogs } from "../utils/parser";
import {
  updateUploadStatus,
  saveTimelineEvent,
  updateAnomalyForensics,
  saveRawLogsBatch,
} from "../db/queries";

const uploadsDir = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, "uploads")
  : path.resolve(__dirname, "../../uploads");

// Initialize AI Clients
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "");
const deepseek = new OpenAI({
  baseURL: "https://api.deepseek.com",
  apiKey: process.env.DEEPSEEK_API_KEY || "",
});

const geminiPrompt = `
You are a Senior SOC Analyst. Analyze the following parsed ZScaler Proxy Logs.
Provide a JSON response with two keys:
1. "summary": A 2-3 sentence executive summary of the log file's events.
2. "timeline": An array of ONLY the suspicious, dangerous, or highly unusual events representing the security threats in the network. Do NOT include normal, benign traffic.

CRITICAL: For the "category" field, you MUST classify the event using ONLY one of the following exact strings. Do not invent new categories:
- "Normal Traffic"
- "Data Exfiltration"
- "Malware Callback (C2)"
- "Malicious Download"
- "Phishing & Credential Theft"
- "Evasion & Anonymizer"
- "Reconnaissance & Probing"
- "Shadow IT"
- "Policy Violation"

For each timeline event, include:
- timestamp: string
- category: string (MUST be from the exact list above)
- description: string
- isAnomaly: boolean
- rawLine: string (ONLY if isAnomaly is true)
- action: string (ONLY if isAnomaly is true)
- url: string (ONLY if isAnomaly is true)
- clientIp: string (ONLY if isAnomaly is true)

Focus heavily on finding potential data exfiltration, malware callbacks, evasion tactics, and unusual blocked traffic.
Return ONLY valid JSON.
`;

export const logWorker = new Worker(
  "log-analysis",
  async (job) => {
    const { uploadId, filename } = job.data;
    const filePath = path.join(uploadsDir, `${uploadId}-${filename}`);

    console.log(
      `[Worker] Started processing upload: ${uploadId} at (${filePath})`,
    );

    try {
      updateUploadStatus(uploadId, "processing");

      // 1. Parse, chunk, and validate the logs
      const { chunks, corruptedCount, totalCount } =
        await parseZScalerLogs(filePath);
      console.log(
        `[Worker] Parsed ${totalCount} lines. Found ${corruptedCount} corrupted lines.`,
      );
      for (const chunk of chunks) {
        const parsedLogs = JSON.parse(chunk);
        saveRawLogsBatch(uploadId, parsedLogs);
      }
      console.log(`[Worker] Saved ${totalCount} logs to raw data lake.`);

      // 2. Stage 1: Gemini
      const model = genAI.getGenerativeModel({
        model: "gemini-2.5-flash",
      });
      console.log("Gemini Key exists:", !!process.env.GEMINI_API_KEY);
      let allAnomalies: any[] = [];
      let finalSummary = "";

      // Loop through each chunk sequentially so we don't hit Gemini rate limits
      for (let i = 0; i < chunks.length; i++) {
        console.log(
          `[Worker] Sending chunk ${i + 1}/${chunks.length} to Gemini...`,
        );

        const triageResult = await model.generateContent({
          contents: [
            {
              role: "user",
              parts: [{ text: geminiPrompt + "\n\nLogs:\n" + chunks[i] }],
            },
          ],
          generationConfig: { responseMimeType: "application/json" },
        });

        const rawText = triageResult.response.text();
        const cleanText = rawText
          .replace(/```json/g, "")
          .replace(/```/g, "")
          .trim();
        const triageData = JSON.parse(cleanText);

        // Aggregate summaries and save timeline events
        finalSummary += triageData.summary + " ";

        // ONLY save actual anomalies to the timeline_events table
        for (const event of triageData.timeline || []) {
          if (event.isAnomaly) {
            const insertedId = saveTimelineEvent(uploadId, event);

            if (event.rawLine) {
              allAnomalies.push({ dbId: insertedId, rawLine: event.rawLine });
            }
          }
        }
      }

      // 3. Stage 2: DeepSeek-R1 (Concurrent Forensic Deep Dive)
      console.log(
        `[Worker] Gemini found ${allAnomalies.length} anomalies. Triggering DeepSeek-R1...`,
      );

      // BATCHING LOGIC: Chunk anomalies into arrays of 10 to preserve reasoning quality & prevent output truncation
      const DEEPSEEK_BATCH_SIZE = 10;
      const anomalyBatches = [];
      for (let i = 0; i < allAnomalies.length; i += DEEPSEEK_BATCH_SIZE) {
        anomalyBatches.push(allAnomalies.slice(i, i + DEEPSEEK_BATCH_SIZE));
      }

      // Use Promise.all to analyze all anomalies at the exact same time, Process all batches concurrently
      const deepSeekPromises = anomalyBatches.map(async (batch, batchIndex) => {
        try {
          console.log(
            `[Worker] DeepSeek analyzing batch ${batchIndex + 1}/${anomalyBatches.length}...`,
          );

          // Inject an ID so the LLM can easily map the result back to us
          const payload = batch.map((anomaly, index) => ({
            id: Number(anomaly.dbId),
            log: anomaly.rawLine,
          }));

          const forensicResponse = await deepseek.chat.completions.create({
            model: "deepseek-reasoner", // Uses R1
            messages: [
              {
                role: "system",
                content: `You are an elite cybersecurity forensics AI. Analyze the provided JSON array of ZScaler proxy logs.
                Return a JSON object with a single key "results" containing an array of your analyses. 
                
                CRITICAL INSTRUCTIONS:
                - "id": The exact integer ID provided in the input.
                - "reasoning": Provide a MAX 2-SENTENCE forensic summary. Be extremely concise.
                - "confidenceScore": A float between 0.0 and 1.0.
                - "severity": "Low", "Medium", "High", or "Critical".`,
              },
              { role: "user", content: JSON.stringify(payload) },
            ],
            response_format: { type: "json_object" },
          });

          // DeepSeek-R1 separates its <think> blocks from the final content when using the API
          const responseText =
            forensicResponse.choices[0].message.content || '{"results": []}';

          // Safety catch: Sometimes reasoning models append markdown blocks to JSON
          const cleanJson = responseText
            .replace(/```json/g, "")
            .replace(/```/g, "")
            .trim();
          const forensicResult = JSON.parse(cleanJson);

          // Map the results back to the original anomaly using the injected ID and save
          for (const item of forensicResult.results || []) {
            updateAnomalyForensics(item.id, {
              id: item.id,
              reasoning: item.reasoning,
              confidenceScore: item.confidenceScore,
              severity: item.severity,
            });
          }
        } catch (err) {
          console.error(
            `[Worker] DeepSeek failed on batch ${batchIndex + 1}:`,
            err,
          );
          // Fallback: If a batch fails, save the anomalies with default values so they aren't lost
          for (const anomaly of batch) {
            updateAnomalyForensics(anomaly.dbId, {
              id: anomaly.dbId,
              reasoning: "DeepSeek API failed to analyze this anomaly.",
              confidenceScore: 0.0,
              severity: "Medium",
            });
          }
        }
      });

      await Promise.all(deepSeekPromises);

      // 4. Complete Job with Metadata
      const completionMessage = `${finalSummary.trim()} (Processed ${totalCount} logs. Skipped ${corruptedCount} corrupted lines).`;
      updateUploadStatus(uploadId, "completed", completionMessage);

      console.log(`[Worker] Successfully finished processing ${uploadId}`);
    } catch (error) {
      console.error(`[Worker] Failed processing ${uploadId}:`, error);
      updateUploadStatus(uploadId, "failed");
    }
  },
  {
    connection: process.env.REDIS_URL
      ? (new Redis(process.env.REDIS_URL, {
          maxRetriesPerRequest: null,
          tls: process.env.REDIS_URL.startsWith("rediss://")
            ? { rejectUnauthorized: false }
            : undefined,
        }) as any)
      : {
          host: process.env.REDIS_HOST || "127.0.0.1",
          port: parseInt(process.env.REDIS_PORT || "6379", 10),
        },
    concurrency: 2, // Dropped to 2 so multiple concurrent jobs don't instantly exceed OpenAI rate limits
  },
);
