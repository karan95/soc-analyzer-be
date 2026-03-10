import fs from "fs";
import { parse } from "csv-parse";
import { ZScalerLogEntry } from "../schema/index";

export const parseZScalerLogs = (
  filePath: string,
): Promise<{
  chunks: string[];
  corruptedCount: number;
  totalCount: number;
}> => {
  return new Promise((resolve, reject) => {
    let currentChunk: ZScalerLogEntry[] = [];
    const chunks: string[] = [];
    let corruptedCount = 0;
    let totalCount = 0;

    // Chunk size limits how many logs go to Gemini per prompt.
    // 100 is a safe balance between context window limits and API rate limits.
    const CHUNK_SIZE = 100;

    fs.createReadStream(filePath)
      .pipe(
        parse({
          delimiter: ",",
          quote: '"',
          skip_empty_lines: true,
          relax_quotes: true, // Helps prevent crashes on malformed internal quotes
          relax_column_count: true,
          columns: false,
        }),
      )
      .on("data", (row: string[]) => {
        totalCount++;

        // Zscaler logs should have roughly 34 columns.
        // If it has fewer than 10, the line is heavily corrupted or truncated.
        if (row.length < 10) {
          corruptedCount++;
          return; // Skip this line
        }

        const entry: ZScalerLogEntry = {
          timestamp: row[0] || "",
          user: row[1] || "Unknown",
          protocol: row[2] || "HTTP",
          url: row[3] || "",
          action: row[4] as any,
          app: row[5] || "",
          category: row[6] || "",
          sentBytes: parseInt(row[7]) || 0,
          receivedBytes: parseInt(row[8]) || 0,
          clientIp: row[21] || "",
          serverIp: row[22] || "",
          requestMethod: row[23] || "",
          responseCode: row[24] || "",
          userAgent: row[25] || "",
          threatName: row[31] || "None",
          ruleLabel: row[32] || "None",
          rawLine: row.map((col) => `"${col}"`).join(","),
        };

        currentChunk.push(entry);

        // Once we hit 100 lines, stringify it and prep a new chunk
        if (currentChunk.length >= CHUNK_SIZE) {
          chunks.push(JSON.stringify(currentChunk));
          currentChunk = [];
        }
      })
      .on("end", () => {
        // Push any remaining lines as the final chunk
        if (currentChunk.length > 0) {
          chunks.push(JSON.stringify(currentChunk));
        }
        resolve({ chunks, corruptedCount, totalCount });
      })
      .on("error", (error: Error) => reject(error));
  });
};
