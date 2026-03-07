import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import bcrypt from "bcryptjs";

const dbPath = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, "database.sqlite")
  : path.resolve(__dirname, "../../database.sqlite");

const db = new Database(dbPath, { verbose: console.log });

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

export const initDb = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS log_uploads (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      file_size INTEGER DEFAULT 0,
      file_hash TEXT UNIQUE NOT NULL,
      file_path TEXT NOT NULL,
      status TEXT CHECK(status IN ('pending', 'processing', 'completed', 'failed')) DEFAULT 'pending',
      summary TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // NEW: THE DATA LAKE (Stores 100% of the raw ingested logs)
  db.exec(`
    CREATE TABLE IF NOT EXISTS raw_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      upload_id TEXT NOT NULL,
      timestamp TEXT,
      parsed_timestamp DATETIME,
      user TEXT,
      action TEXT,
      url TEXT,
      app TEXT,
      category TEXT,
      client_ip TEXT,
      server_ip TEXT,
      request_method TEXT,
      response_code TEXT,
      user_agent TEXT,
      sent_bytes INTEGER,
      received_bytes INTEGER,
      threat_name TEXT,
      raw_line TEXT,
      FOREIGN KEY (upload_id) REFERENCES log_uploads(id) ON DELETE CASCADE
    )
  `);

  // RELATIONAL ALERTS TABLE: Holds ONLY the Gemini/DeepSeek anomalies
  db.exec(`
    CREATE TABLE IF NOT EXISTS timeline_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      upload_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      parsed_timestamp DATETIME,
      category TEXT NOT NULL, 
      description TEXT,
      is_anomaly INTEGER NOT NULL CHECK (is_anomaly IN (0, 1)),
      
      action TEXT,
      url TEXT,
      client_ip TEXT,
      raw_line TEXT,
      
      reasoning TEXT,
      confidence REAL,
      severity TEXT CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
      
      FOREIGN KEY (upload_id) REFERENCES log_uploads(id) ON DELETE CASCADE
    )
  `);
};

// NEW: Auto-seeder for trial accounts
export const seedTrialUsers = () => {
  const trialUsers = [
    { email: "admin@soc.local", password: "SecurePassword123!" },
    { email: "analyst1@soc.local", password: "Password123!" },
    { email: "analyst2@soc.local", password: "Password123!" },
    { email: "viewer@soc.local", password: "Password123!" },
    { email: "trial@soc.local", password: "Password123!" },
  ];

  const checkStmt = db.prepare(
    "SELECT count(*) as count FROM users WHERE email = ?",
  );
  const insertStmt = db.prepare(
    "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
  );

  const seed = db.transaction((users) => {
    for (const user of users) {
      const res = checkStmt.get(user.email) as { count: number };

      // Only insert if the user does NOT already exist
      if (res.count === 0) {
        const hash = bcrypt.hashSync(user.password, 10); // Hash synchronously for startup script
        insertStmt.run(crypto.randomUUID(), user.email, hash);
        console.log(
          `✅ Trial user created: ${user.email} (Password: ${user.password})`,
        );
      }
    }
  });

  seed(trialUsers);
};

export default db;
