# 🔐 SUKUMA LANGO
### Integrated Digital Access Control & Visitor Forensic Logging System
**KCA University · Department of Information Security & Forensics**
**Candidate: Andy Abuga Ombasa | Reg No: 24/06668**

---

## System Overview

Sukuma Lango replaces paper-based Occurrence Books (OBs) with a forensic-ready, closed-loop digital access control system. It operates entirely on a local LAN server — no cloud, no external dependencies, full data sovereignty.

```
┌─────────────────────────────────────────────────────────┐
│                   SUKUMA LANGO STACK                    │
│                                                         │
│  [Guard Mobile UI]  [Admin Dashboard]                   │
│        ↓                   ↓                            │
│     HTML5 / CSS / Vanilla JS (Frontend)                 │
│              ↓                                          │
│     Node.js + Express (REST API — Port 3000)            │
│              ↓                                          │
│     MySQL 8.0+ InnoDB (ACID Compliant Database)         │
│                                                         │
│  Security: JWT · RBAC · bcrypt · AES-256               │
│  Deployment: Closed LAN · No cloud · Air-gapped         │
└─────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start (Full Setup)

### Prerequisites
- **Node.js** ≥ 18.0.0
- **MySQL** 8.0+
- **npm** ≥ 9.0
- A machine on your LAN (Windows/Linux/macOS)

---

### STEP 1 — Clone / Create Project Structure

```bash
# Create and enter project folder
mkdir sukuma-lango && cd sukuma-lango

# Copy all provided source files into this structure:
# sukuma-lango/
# ├── backend/
# ├── frontend/
# └── database/
```

---

### STEP 2 — Set Up MySQL Database

Log into MySQL as root and run the schema:

```bash
# Linux/macOS
mysql -u root -p < database/schema.sql

# Windows (MySQL Command Line Client)
mysql -u root -p
source C:/path/to/database/schema.sql;
```

Create a dedicated application user (recommended):

```sql
CREATE USER 'sukuma_app'@'localhost' IDENTIFIED BY 'YourStrongPassword123!';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON sukuma_lango.* TO 'sukuma_app'@'localhost';
FLUSH PRIVILEGES;
```

---

### STEP 3 — Configure Environment

```bash
cd backend
cp .env.example .env
```

Now edit `.env` and fill in all values:

```bash
# Generate JWT secret (run this in Node REPL):
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate AES key:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate refresh secret and QR secret similarly
```

**Minimum required .env changes:**
```dotenv
DB_PASSWORD=YourStrongPassword123!
JWT_SECRET=<64-char hex from above>
JWT_REFRESH_SECRET=<different 64-char hex>
AES_ENCRYPTION_KEY=<32-char hex from above>
QR_PASS_SECRET=<any long random string>
```

---

### STEP 4 — Install Dependencies & Seed Database

```bash
# Install Node.js packages
cd backend
npm install

# Seed the default superadmin user
node src/utils/seeder.js
```

Expected output:
```
✅  Default superadmin created successfully!
   Username : superadmin
   Password : Admin@SukumaLango2024
   ⚠️   CHANGE THE PASSWORD IMMEDIATELY after first login!
```

---

### STEP 5 — Start the Server

```bash
# Development mode (auto-restart on changes)
npm run dev

# Production mode
npm start
```

Expected output:
```
✅ Sukuma Lango API running on http://0.0.0.0:3000
   Admin Dashboard: http://0.0.0.0:3000/admin-dashboard/
   Guard Mobile UI: http://0.0.0.0:3000/guard-mobile/
```

---

### STEP 6 — Access the System

| Interface | URL | Users |
|-----------|-----|-------|
| Guard Mobile UI | `http://<SERVER-IP>:3000/guard-mobile/` | Guards |
| Admin Dashboard | `http://<SERVER-IP>:3000/admin-dashboard/` | Admins |
| API Health Check | `http://<SERVER-IP>:3000/api/v1/health` | System |

**Default Credentials:**
- Username: `superadmin`
- Password: `Admin@SukumaLango2024`
- ⚠️ **Change this immediately via the Users management panel.**

---

## 📁 Project Structure

```
sukuma-lango/
├── database/
│   └── schema.sql                  ← Full MySQL schema (5 tables + views + procedures)
│
├── backend/
│   ├── .env.example                ← Environment template (copy to .env)
│   ├── package.json
│   └── src/
│       ├── server.js               ← Express app entry point
│       ├── config/
│       │   └── database.js         ← MySQL connection pool
│       ├── controllers/
│       │   ├── authController.js   ← Login, logout, JWT issuance
│       │   ├── visitorController.js← Register, exit, active list
│       │   └── auditController.js  ← Forensic trail, anomalies, export
│       ├── middleware/
│       │   └── authMiddleware.js   ← JWT verify + RBAC authorize
│       ├── routes/
│       │   ├── authRoutes.js
│       │   ├── visitorRoutes.js
│       │   └── auditRoutes.js
│       └── utils/
│           ├── logger.js           ← Winston rotating file logger
│           ├── crypto.js           ← AES-256 encrypt/decrypt + SHA-256
│           ├── auditLogger.js      ← tblForensicAudits writer
│           └── seeder.js           ← Default admin user seeder
│
└── frontend/
    ├── guard-mobile/
    │   └── index.html              ← Mobile-first Guard Station UI
    └── admin-dashboard/
        └── index.html              ← Admin Forensic Dashboard
```

---

## 🗄️ Database Schema

| Table | Purpose |
|-------|---------|
| `tblRoles` | RBAC role definitions with JSON permission arrays |
| `tblUsers` | Guards & Admins — UUID PKs, bcrypt passwords, lockout |
| `tblVisitors` | Visitor PII registry — all sensitive fields AES-256 encrypted |
| `tblVisitLogs` | Core visit transactions — immutable with SHA-256 integrity hash |
| `tblForensicAudits` | Append-only legal audit ledger — never updated or deleted |

---

## 🔐 Security Architecture

### Authentication
- **bcrypt** (cost=12) for password hashing
- **JWT** access tokens (8h expiry) + refresh tokens (24h)
- Account lockout after 5 consecutive failed attempts (30 min lockout)
- Constant-time login response to prevent username enumeration

### RBAC Permissions

| Permission | SUPER_ADMIN | ADMIN | GUARD |
|------------|:-----------:|:-----:|:-----:|
| register_visitor | ✅ | ✅ | ✅ |
| log_exit | ✅ | ✅ | ✅ |
| view_occupancy | ✅ | ✅ | ✅ |
| view_all_logs | ✅ | ✅ | ❌ |
| view_audit_trail | ✅ | ✅ | ❌ |
| export_logs | ✅ | ✅ | ❌ |
| manage_users | ✅ | ❌ | ❌ |
| blacklist_visitor | ✅ | ✅ | ❌ |

### Data Protection
- **AES-256-CBC** encryption for all PII at rest: visitor name, phone, email, host name, visit purpose
- Fresh IV generated per encryption (randomised — no IV reuse)
- PII stored as `<hex_iv>:<base64_ciphertext>` in database
- SHA-256 integrity hash on every visit log record
- All audit detail fields encrypted before storage

### Forensic Integrity
- `tblForensicAudits` is append-only — no UPDATE or DELETE ever issued against it
- Every login attempt (success and failure) logged
- Every data export logged with the exporting user's identity
- All RBAC denials logged with the attempted permission
- SHA-256 record hash for each visit log enables tamper detection

---

## 📡 API Reference

### Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/auth/login` | None | Login → JWT |
| POST | `/api/v1/auth/logout` | Bearer | Logout |
| POST | `/api/v1/auth/refresh` | None | Refresh token |
| GET | `/api/v1/auth/me` | Bearer | Current user |

### Visitors
| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| POST | `/api/v1/visitors/register` | register_visitor | Check-in visitor |
| PATCH | `/api/v1/visitors/:logId/exit` | log_exit | Record exit |
| GET | `/api/v1/visitors/active` | view_occupancy | Live visitor list |
| GET | `/api/v1/visitors/logs` | view_all_logs | Paginated log query |
| GET | `/api/v1/visitors/:id` | view_own_logs | Visitor by ID |

### Audit & Forensics
| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/v1/audit/logs` | view_audit_trail | Forensic audit trail |
| GET | `/api/v1/audit/anomalies` | view_audit_trail | Anomaly detection |
| GET | `/api/v1/audit/occupancy` | view_occupancy | Real-time count |
| POST | `/api/v1/audit/export` | export_logs | Evidence package |

---

## 🌐 LAN Deployment (Production)

To make the server accessible to all devices on your LAN:

```bash
# Find your server's LAN IP
ip addr show     # Linux
ipconfig         # Windows

# Set HOST in .env to your LAN IP
HOST=192.168.1.100
PORT=3000

# Guards access from phones:
# http://192.168.1.100:3000/guard-mobile/

# Admins access from laptops:
# http://192.168.1.100:3000/admin-dashboard/
```

For persistent background running (Linux):
```bash
# Install PM2 process manager
npm install -g pm2

# Start with PM2
pm2 start src/server.js --name sukuma-lango
pm2 save
pm2 startup
```

---

## 📜 Legal Compliance

- **Kenya Data Protection Act (2019)** — PII encrypted at rest, access-controlled
- **ODPC Guidelines** — Audit trail provides accountability log
- **Chain of Custody** — SHA-256 integrity hashes on all visit records
- **Evidence Admissibility** — Immutable timestamps, append-only audit ledger

---

*Sukuma Lango v1.0 — Built for the KCA University Final Year Project*
*"Transforming passive paper logging into active forensic intelligence."*
