/**
 * sukuma-lango/backend/src/server.js
 * Main Express application — mounts all middleware, routes, and starts the server.
 * Closed-loop LAN deployment: no external calls, no cloud dependencies.
 */

'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const morgan     = require('morgan');
const rateLimit  = require('express-rate-limit');
const path       = require('path');
const fs         = require('fs');

const { testConnection }  = require('./config/database');
const { writeAudit, ACTIONS } = require('./utils/auditLogger');
const logger              = require('./utils/logger');

// Routes
const authRoutes    = require('./routes/authRoutes');
const visitorRoutes = require('./routes/visitorRoutes');
const auditRoutes   = require('./routes/auditRoutes');

// ---------------------------------------------------------------------------
// Ensure log directory exists
// ---------------------------------------------------------------------------
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '../logs');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// App instance
// ---------------------------------------------------------------------------
const app  = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// ---------------------------------------------------------------------------
// Security headers (Helmet)
// Tailored for a closed LAN — no CDN, no external resources.
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],   // Needed for inline JS in local UI
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],             // data: for QR code display
      connectSrc: ["'self'"],
      fontSrc:    ["'self'"],
      objectSrc:  ["'none'"],
      frameSrc:   ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,   // Relax for local LAN clients
}));

// ---------------------------------------------------------------------------
// CORS — restricted to LAN origins only
// ---------------------------------------------------------------------------
const ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  // Add your LAN IP here, e.g.: 'http://192.168.1.100:3000'
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., mobile apps on same LAN, curl)
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked: ${origin}`));
    }
  },
  methods:            ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
  allowedHeaders:     ['Content-Type', 'Authorization'],
  exposedHeaders:     ['X-Request-Id'],
  credentials:        true,
}));

// ---------------------------------------------------------------------------
// Body parsing
// ---------------------------------------------------------------------------
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// ---------------------------------------------------------------------------
// HTTP request logging (Morgan → Winston)
// ---------------------------------------------------------------------------
app.use(morgan('combined', {
  stream: { write: (msg) => logger.http(msg.trim()) },
  skip: (req) => req.url === '/api/v1/health',   // Skip health check noise
}));

// ---------------------------------------------------------------------------
// Global API rate limiter (safety net — per-route limiters also applied)
// ---------------------------------------------------------------------------
app.use('/api/', rateLimit({
  windowMs:        60 * 1000,    // 1 minute
  max:             300,          // 300 requests/min per IP across all API routes
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many requests.' } },
}));

// ---------------------------------------------------------------------------
// Static file serving — serve the frontend from /frontend
// ---------------------------------------------------------------------------
const FRONTEND_DIR = path.join(__dirname, '../../frontend');
app.use(express.static(FRONTEND_DIR));

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------
app.use('/api/v1/auth',     authRoutes);
app.use('/api/v1/visitors', visitorRoutes);
app.use('/api/v1/audit',    auditRoutes);

// ---------------------------------------------------------------------------
// Health check (unauthenticated — for LAN monitoring only)
// ---------------------------------------------------------------------------
app.get('/api/v1/health', async (req, res) => {
  const { pool } = require('./config/database');
  let dbOk = false;
  try {
    await pool.execute('SELECT 1');
    dbOk = true;
  } catch (_) { /* ignore */ }

  res.status(dbOk ? 200 : 503).json({
    status:    dbOk ? 'ok' : 'degraded',
    service:   'Sukuma Lango API',
    version:   '1.0.0',
    timestamp: new Date().toISOString(),
    database:  dbOk ? 'connected' : 'error',
    uptime:    Math.floor(process.uptime()),
  });
});

// ---------------------------------------------------------------------------
// SPA fallback — serve admin dashboard for unknown routes
// ---------------------------------------------------------------------------
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Endpoint not found.' } });
  }
  res.sendFile(path.join(FRONTEND_DIR, 'admin-dashboard', 'index.html'));
});

// ---------------------------------------------------------------------------
// Global error handler
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    message: err.message,
    stack:   err.stack,
    path:    req.originalUrl,
    method:  req.method,
  });

  if (err.message?.startsWith('CORS blocked')) {
    return res.status(403).json({ success: false, error: { code: 'CORS_BLOCKED', message: err.message } });
  }

  res.status(500).json({
    success: false,
    error:   { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred.' },
  });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
async function startServer() {
  logger.info('Starting Sukuma Lango server…');

  // Validate critical env variables
  const required = ['DB_PASSWORD', 'JWT_SECRET', 'JWT_REFRESH_SECRET', 'AES_ENCRYPTION_KEY', 'QR_PASS_SECRET'];
  const missing  = required.filter(k => !process.env[k] || process.env[k].startsWith('CHANGE_ME'));
  if (missing.length) {
    logger.error('STARTUP ABORTED — Missing or default environment variables', { missing });
    process.exit(1);
  }

  // Test DB connection
  const dbConnected = await testConnection();
  if (!dbConnected) {
    logger.error('STARTUP ABORTED — Cannot connect to database.');
    process.exit(1);
  }

  const server = app.listen(PORT, HOST, () => {
    logger.info(`✅ Sukuma Lango API running on http://${HOST}:${PORT}`);
    logger.info(`   Admin Dashboard: http://${HOST}:${PORT}/admin-dashboard/`);
    logger.info(`   Guard Mobile UI: http://${HOST}:${PORT}/guard-mobile/`);
    logger.info(`   Environment:     ${process.env.NODE_ENV}`);

    writeAudit({
      action:     ACTIONS.SYSTEM_STARTUP,
      ipAddress:  '127.0.0.1',
      status:     'SUCCESS',
      detail:     { port: PORT, node: process.version },
    }).catch(() => {});
  });

  // Graceful shutdown
  const shutdown = (signal) => {
    logger.info(`${signal} received — shutting down gracefully…`);
    server.close(() => {
      logger.info('HTTP server closed.');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException',  (err) => logger.error('Uncaught exception',  { error: err.message, stack: err.stack }));
  process.on('unhandledRejection', (err) => logger.error('Unhandled rejection', { error: err?.message }));
}

startServer();

module.exports = app;  // For testing
