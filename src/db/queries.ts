import db from "./index";

// --- EXISTING UPLOAD FUNCTIONS ---

export const getUserByEmail = (email: string) => {
  const stmt = db.prepare("SELECT * FROM users WHERE email = ?");
  return stmt.get(email) as
    | { id: string; email: string; password_hash: string }
    | undefined;
};

export const getUploadByHash = (userId: string, hash: string) => {
  const stmt = db.prepare(
    "SELECT id, status FROM log_uploads WHERE user_id = ? AND file_hash = ?",
  );
  return stmt.get(userId, hash) as { id: string; status: string } | undefined;
};

export const createUploadRecord = (
  userId: string,
  id: string,
  filename: string,
  fileSize: number,
  hash: string,
  filePath: string,
) => {
  const stmt = db.prepare(
    "INSERT INTO log_uploads (id, user_id, filename, file_size, file_hash, file_path) VALUES (?, ?, ?, ?, ?, ?)",
  );
  stmt.run(id, userId, filename, fileSize, hash, filePath);
};

export const getUploads = (userId: string, activeOnly: boolean = false) => {
  let sql =
    "SELECT id, filename, status, file_size, created_at FROM log_uploads WHERE user_id = ?";
  if (activeOnly) sql += " AND status IN ('pending', 'processing')";
  sql += " ORDER BY created_at DESC";
  return db.prepare(sql).all(userId);
};

export const updateUploadStatus = (
  id: string,
  status: string,
  summary?: string,
) => {
  const stmt = db.prepare(
    "UPDATE log_uploads SET status = ?, summary = ? WHERE id = ?",
  );
  stmt.run(status, summary || null, id);
};

// --- NEW: HIGH-SPEED BULK INSERTER FOR RAW LOGS ---
export const saveRawLogsBatch = (uploadId: string, logs: any[]) => {
  const stmt = db.prepare(`
    INSERT INTO raw_logs (
      upload_id, timestamp, parsed_timestamp, user, action, url, app, category, 
      client_ip, server_ip, request_method, response_code, user_agent, 
      sent_bytes, received_bytes, threat_name, raw_line
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Using SQLite transactions makes inserting thousands of rows almost instant
  const insertMany = db.transaction((logsArray) => {
    for (const log of logsArray) {
      let parsedDate = null;
      if (log.timestamp) {
        const d = new Date(log.timestamp);
        if (!isNaN(d.getTime())) parsedDate = d.toISOString();
      }
      stmt.run(
        uploadId,
        log.timestamp,
        parsedDate,
        log.user,
        log.action,
        log.url,
        log.app,
        log.category,
        log.clientIp,
        log.serverIp,
        log.requestMethod,
        log.responseCode,
        log.userAgent,
        log.sentBytes,
        log.receivedBytes,
        log.threatName,
        log.rawLine,
      );
    }
  });

  insertMany(logs);
};

// --- EXISTING AI EVENT FUNCTIONS ---
export const saveTimelineEvent = (
  uploadId: string,
  event: any,
): number | bigint => {
  let parsedDate = null;
  if (event.timestamp) {
    const d = new Date(event.timestamp);
    if (!isNaN(d.getTime())) parsedDate = d.toISOString();
  }

  const stmt = db.prepare(`
    INSERT INTO timeline_events (
      upload_id, timestamp, parsed_timestamp, category, description, is_anomaly, action, url, client_ip, raw_line
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    uploadId,
    event.timestamp || "",
    parsedDate,
    event.category || event.title || "Event",
    event.description || "",
    event.isAnomaly ? 1 : 0,
    event.action || null,
    event.url || null,
    event.clientIp || null,
    event.rawLine || null,
  );
  return result.lastInsertRowid;
};

export const updateAnomalyForensics = (
  eventId: number | bigint,
  forensicData: any,
) => {
  const stmt = db.prepare(
    `UPDATE timeline_events SET reasoning = ?, confidence = ?, severity = ? WHERE id = ?`,
  );
  stmt.run(
    forensicData.reasoning || "Analysis complete.",
    forensicData.confidenceScore || 0.0,
    forensicData.severity || "Medium",
    eventId,
  );
};

export const getUploadMetadata = (userId: string, uploadId: string) => {
  const upload = db
    .prepare("SELECT * FROM log_uploads WHERE id = ? AND user_id = ?")
    .get(uploadId, userId) as any;
  if (!upload) return null;

  const stats = db
    .prepare(
      `
    SELECT COUNT(*) as totalAnomalies,
      MAX(CASE WHEN LOWER(severity) = 'critical' THEN 4 WHEN LOWER(severity) = 'high' THEN 3 WHEN LOWER(severity) = 'medium' THEN 2 WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) as maxSeverityLevel
    FROM timeline_events WHERE upload_id = ? AND is_anomaly = 1
  `,
    )
    .get(uploadId) as any;

  let highestSeverity = "Pending";
  if (stats.maxSeverityLevel === 4) highestSeverity = "Critical";
  else if (stats.maxSeverityLevel === 3) highestSeverity = "High";
  else if (stats.maxSeverityLevel === 2) highestSeverity = "Medium";
  else if (stats.maxSeverityLevel === 1) highestSeverity = "Low";

  return {
    jobId: upload.id,
    status: upload.status,
    filename: upload.filename,
    timestamp: upload.created_at,
    analysis: { summary: upload.summary },
    stats: { totalAnomalies: stats.totalAnomalies || 0, highestSeverity },
  };
};

// ========================================================
// ENDPOINT 1: AI ANOMALIES (Queries 'timeline_events')
// ========================================================
export const getAnomalyEventsPaginated = (
  userId: string,
  id: string,
  page: number,
  limit: number,
  sortBy: string = "severity",
  category?: string,
  clientIp?: string,
  severity?: string,
) => {
  // Security Check: Does this user own this upload?
  const upload = db
    .prepare("SELECT id FROM log_uploads WHERE id = ? AND user_id = ?")
    .get(id, userId);
  if (!upload) throw new Error("Unauthorized");

  const offset = (page - 1) * limit;
  const params: any[] = [id];

  let query =
    "SELECT * FROM timeline_events WHERE upload_id = ? AND is_anomaly = 1";
  if (category) {
    query += " AND category = ?";
    params.push(category);
  }
  if (clientIp) {
    query += " AND client_ip LIKE ?";
    params.push(`%${clientIp}%`);
  }
  if (severity && severity !== "all") {
    query += " AND LOWER(severity) = ?";
    params.push(severity.toLowerCase());
  }

  if (sortBy === "severity")
    query += ` ORDER BY CASE WHEN LOWER(severity) = 'critical' THEN 1 WHEN LOWER(severity) = 'high' THEN 2 WHEN LOWER(severity) = 'medium' THEN 3 WHEN LOWER(severity) = 'low' THEN 4 ELSE 5 END ASC, parsed_timestamp DESC`;
  else query += " ORDER BY parsed_timestamp DESC";

  query += " LIMIT ? OFFSET ?";
  params.push(limit, offset);
  const events = db.prepare(query).all(...params) as any[];

  return events.map((e) => ({
    id: `evt_${e.id}`,
    timestamp: e.timestamp,
    category: e.category,
    description: e.description,
    isAnomaly: true,
    action: e.action,
    url: e.url,
    clientIp: e.client_ip,
    reasoning: e.reasoning,
    confidenceScore: e.confidence ? Math.round(e.confidence * 100) : null,
    severity: e.severity ? e.severity.toLowerCase() : "pending",
  }));
};

// ========================================================
// ENDPOINT 2: RAW LOGS (Queries the massive 'raw_logs' lake)
// ========================================================
export const getRawLogsPaginated = (
  userId: string,
  id: string,
  page: number,
  limit: number,
  searchQuery?: string,
) => {
  // Security Check: Does this user own this upload?
  const upload = db
    .prepare("SELECT id FROM log_uploads WHERE id = ? AND user_id = ?")
    .get(id, userId);
  if (!upload) throw new Error("Unauthorized");

  const offset = (page - 1) * limit;
  const params: any[] = [id];
  const countParams: any[] = [id];

  let whereClause = " WHERE upload_id = ?";
  if (searchQuery) {
    whereClause +=
      " AND (url LIKE ? OR client_ip LIKE ? OR user LIKE ? OR threat_name LIKE ?)";
    const pattern = `%${searchQuery}%`;
    params.push(pattern, pattern, pattern, pattern);
    countParams.push(pattern, pattern, pattern, pattern);
  }

  const countRes = db
    .prepare(`SELECT COUNT(*) as count FROM raw_logs ${whereClause}`)
    .get(...countParams) as any;
  const totalRecords = countRes.count;

  const query = `SELECT * FROM raw_logs ${whereClause} ORDER BY parsed_timestamp DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);
  const events = db.prepare(query).all(...params) as any[];

  return {
    events: events.map((e) => ({
      id: `raw_${e.id}`,
      timestamp: e.timestamp,
      user: e.user,
      url: e.url,
      app: e.app,
      category: e.category,
      clientIp: e.client_ip,
      serverIp: e.server_ip,
      requestMethod: e.request_method,
      responseCode: e.response_code,
      userAgent: e.user_agent,
      sentBytes: e.sent_bytes,
      receivedBytes: e.received_bytes,
      action: e.action,
      threatName: e.threat_name,
    })),
    totalRecords,
    totalPages: Math.ceil(totalRecords / limit),
  };
};

// ========================================================
// ENDPOINT 3: GLOBAL THREAT INTELLIGENCE (Dashboard)
// ========================================================
export const getGlobalIntelligence = (userId: string, timeRange: string) => {
  const now = new Date();
  let startDate = new Date(now);

  if (timeRange === "1h") startDate.setHours(now.getHours() - 1);
  else if (timeRange === "24h") startDate.setHours(now.getHours() - 24);
  else if (timeRange === "7d") startDate.setDate(now.getDate() - 7);
  else if (timeRange === "30d") startDate.setDate(now.getDate() - 30);
  else startDate.setFullYear(now.getFullYear() - 10);

  const startDateStr = startDate.toISOString();

  // FIX: Join with log_uploads to enforce user ownership
  const stats = db
    .prepare(
      `
    SELECT 
      COUNT(*) as totalAnomalies,
      SUM(CASE WHEN LOWER(t.severity) = 'critical' THEN 1 ELSE 0 END) as criticalCount,
      SUM(CASE WHEN LOWER(t.severity) = 'high' THEN 1 ELSE 0 END) as highCount,
      SUM(CASE WHEN LOWER(t.severity) = 'medium' THEN 1 ELSE 0 END) as mediumCount
    FROM timeline_events t
    JOIN log_uploads u ON t.upload_id = u.id
    WHERE t.is_anomaly = 1 AND t.parsed_timestamp >= ? AND u.user_id = ?
  `,
    )
    .get(startDateStr, userId) as any;

  const events = db
    .prepare(
      `
    SELECT t.raw_line, t.category, t.severity, t.upload_id 
    FROM timeline_events t
    JOIN log_uploads u ON t.upload_id = u.id
    WHERE t.is_anomaly = 1 AND t.parsed_timestamp >= ? AND u.user_id = ?
  `,
    )
    .all(startDateStr, userId) as any[];

  // (The rest of the JS aggregation logic remains exactly the same...)
  const userCounts: Record<string, { count: number; uploadId: string }> = {};
  const ipCounts: Record<
    string,
    { count: number; type: string; severity: string; uploadId: string }
  > = {};

  events.forEach((e: any) => {
    if (e.raw_line) {
      const cols = e.raw_line
        .split('","')
        .map((c: string) => c.replace(/^"|"$/g, ""));
      const user = cols[1] || "Unknown";
      if (user !== "Unknown" && user !== "") {
        if (!userCounts[user])
          userCounts[user] = { count: 0, uploadId: e.upload_id };
        userCounts[user].count += 1;
      }
      const serverIp = cols[22] || "Unknown";
      if (serverIp !== "Unknown" && serverIp !== "") {
        if (!ipCounts[serverIp]) {
          ipCounts[serverIp] = {
            count: 0,
            type: e.category,
            severity: e.severity || "medium",
            uploadId: e.upload_id,
          };
        }
        ipCounts[serverIp].count += 1;
      }
    }
  });

  const topUsers = Object.entries(userCounts)
    .map(([user, data]) => ({
      user,
      department: "Enterprise",
      incidents: data.count,
      uploadId: data.uploadId,
    }))
    .sort((a, b) => b.incidents - a.incidents)
    .slice(0, 5);
  const topIps = Object.entries(ipCounts)
    .map(([ip, data]) => ({
      ip,
      occurrences: data.count,
      type: data.type || "Unknown Threat",
      severity: data.severity.toLowerCase(),
      uploadId: data.uploadId,
    }))
    .sort((a, b) => b.occurrences - a.occurrences)
    .slice(0, 5);

  return {
    globalStats: {
      totalAnomalies: stats.totalAnomalies || 0,
      criticalCount: stats.criticalCount || 0,
      highCount: stats.highCount || 0,
      mediumCount: stats.mediumCount || 0,
    },
    topMaliciousIPs: topIps,
    topTargetedUsers: topUsers,
  };
};
