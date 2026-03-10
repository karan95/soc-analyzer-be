# SentinelGrid - SOC Analyzer (Backend)

This is the backend service for the **SentinelGrid SOC Analyzer** web application. The system is designed to ingest, parse, and analyze **ZScaler Web Proxy Logs** to detect suspicious network behavior and potential security threats.

The backend provides:

* RESTful API powered by **Fastify**
* **SQLite** as a lightweight local data lake
* **BullMQ + Redis** for background processing of large log files
* A **two-stage AI analysis pipeline** for anomaly detection and forensic explanation

This architecture allows log ingestion and AI analysis to run **asynchronously**, ensuring the main API remains responsive.

---

# AI Approach to Anomaly Detection

To balance **speed, cost efficiency, and analytical depth**, SentinelGrid uses a **two-stage AI pipeline** inside the background worker.

The system first filters large volumes of logs to identify suspicious behavior, then performs deeper reasoning on those anomalies.

---

## Stage 1: Triage (Google Gemini 2.5 Flash)

Proxy logs can contain **millions of entries**, most of which are benign.

The worker performs the following steps:

1. Parses uploaded CSV logs
2. Splits them into manageable batches
3. Sends each batch to **Gemini 2.5 Flash**

Gemini acts like a **SOC Tier-1 analyst**, performing rapid triage.

It:

* Summarizes network activity
* Filters out normal traffic
* Extracts only suspicious events

Examples of events Gemini identifies:

* Possible **data exfiltration**
* **Shadow IT** applications
* **Policy violations**
* **Malware callbacks**
* Suspicious domain activity
* Abnormal traffic patterns

The output is a **structured JSON list of anomalies**, dramatically reducing the data volume requiring deeper analysis.

---

## Stage 2: Forensic Deep Dive (DeepSeek-R1)

After Gemini isolates suspicious events, they are sent to **DeepSeek-R1 (deepseek-reasoner)**.

DeepSeek performs deep reasoning over raw log lines.

For each anomaly it generates:

* A concise forensic explanation
* A confidence score (0.0 – 1.0)
* A severity classification

Severity Levels:

* Low
* Medium
* High
* Critical

The worker processes anomaly batches using **Promise.all concurrency**, allowing multiple reasoning requests to run simultaneously.

---

# System Architecture

```
Frontend (React / Vite)
        │
        ▼
Fastify REST API
        │
        ▼
File Upload Endpoint
        │
        ▼
BullMQ Job Queue (Redis)
        │
        ▼
Background Worker
        │
 ┌───────────────┬────────────────┐
 ▼               ▼                ▼
Gemini AI     DeepSeek AI     SQLite
(Triage)      (Reasoning)     Data Lake
```

---

# Local Setup Instructions

## Prerequisites

Install the following:

* Node.js v18+
* Redis running on port **6379**

You can also use a cloud Redis provider like **Upstash or Railway**.

---

# Install Dependencies

Clone the repository and run:

```npm install```

---

# Environment Variables

Create a `.env` file in the project root.

```
PORT=3000
FRONTEND_URL=[http://localhost:5173](http://localhost:5173)

JWT_SECRET=your_super_secret_jwt_key
COOKIE_SECRET=your_super_secret_cookie_key
```

# Redis connection

```REDIS_URL=redis://127.0.0.1:6379```

# AI provider keys

```
GEMINI_API_KEY=your_google_ai_key
DEEPSEEK_API_KEY=your_deepseek_api_key
```

---

# Start the Server

Run the development server:

```npm start```

The project uses **ts-node-dev**, so the server automatically restarts when files change.

---

# Test Credentials

On first startup the backend automatically:

* Creates the SQLite database (`database.sqlite`)
* Initializes required tables
* Seeds trial users

Use these credentials to log in:

Email:
[trial@soc.local](mailto:trial@soc.local)

Password:
Password123!

---

## API Endpoints

The backend exposes the following REST endpoints. All endpoints (except login) require a valid HTTP-only JWT cookie. Sessions are valid for up to **8 hours** with a **10-minute** rolling inactivity expiration.

---

### Authentication

* **`POST /api/auth/login`**
    * Authenticates a user and sets an HTTP-only JWT cookie.
    * **Body:** 
    ```json
        { 
          "email": "trial@soc.local", 
          "password": "Password123!" 
        }
* **`POST /api/auth/logout`**
    * Clears the authentication cookie.
* **`GET /api/auth/me`**
    * Returns the currently authenticated user payload.

---

### Log Management & Uploads

* **`GET /api/logs`**
    * Retrieves all log uploads for the authenticated user.
    * **Query Params:** `?active=true` (optional, filters for logs currently being processed).
* **`GET /api/logs/check/:hash`**
    * Checks if a file hash has already been uploaded by the user to prevent duplicate processing.
* **`POST /api/logs/upload`**
    * Accepts a `.txt`, `.csv`, or `.log` file via `multipart/form-data`. 
    * *Note: Requires a `hash` field in the form data.* * Saves to disk and enqueues the BullMQ analysis job.
* **`GET /api/logs/:id`**
    * Status and Summary of log file
* **`DELETE /api/logs/:id`**
    * Deletes a log upload, its associated raw logs, anomalies, and the physical file. 
    * **Note:** Returns `409 Conflict` if the file is currently being analyzed.

---

### Data & Threat Analysis

* **`GET /api/logs/:id/events`**
    * Retrieves a paginated list of AI-identified anomaly events for a specific log upload.
    * **Query Params:** * `page` (default: 1)
        * `limit` (default: 20)
        * `sortBy` (default: severity)
        * `category`, `clientIp`, `severity` (optional filters)
* **`GET /api/logs/:id/raw`**
    * Retrieves paginated raw log entries for a specific log upload.
    * **Query Params:** * `page` (default: 1)
        * `limit` (default: 20)
        * `search` (optional keyword search)
* **`GET /api/intelligence`**
    * Fetches global intelligence dashboard data across all logs.
    * **Query Params:** `timeRange` (default: "24h").

# Technology Stack

Backend:

* Fastify
* TypeScript

Queue Processing:

* BullMQ
* Redis

Database:

* SQLite

AI Providers:

* Google Gemini
* DeepSeek Reasoner

Utilities:

* JWT authentication
* Multipart file uploads
* ts-node-dev

---

# Security Features

* HTTP-only JWT authentication
* Cookie-based session security
* Environment variable isolation
* Background worker isolation
* Controlled file uploads

---

# Peformance
- Log uploads endpoint is strictly limited to 10 requests per user. Additionally, the background worker is configured with concurrency: 2, meaning even if you upload 10 files, the server will only actively process 2 files at the exact same time to prevent exhausting AI API limits. The maximum allowed file size is 10 MB.

---

# Future Improvements

Architecture improvements to handle millions of events:

* Use ClickHouse or Elasticsearch to handle high speed queries
* File ingestion through AWS S3
* Streaming architecture through Apache Kafka
* Funnel approch and use lightweight ML models to filter out 99.9% of the noise, process 0.1% suspicious alerts through DeepSeek, move to slef-hosted models


Feature enhancements include:

* Real-time SOC dashboards
* Threat intelligence enrichment
* Multi-tenant workspace support
* SOC alert notifications
* Streaming log ingestion
* Automated SOC playbooks
* SIEM integrations
