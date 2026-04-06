/**
 * sukuma-lango/backend/src/controllers/visitorController.js
 *
 * Handles:
 *   POST /api/v1/visitors/register  — new visitor check-in (creates visit log)
 *   PATCH /api/v1/visitors/:logId/exit — log visitor exit
 *   GET  /api/v1/visitors/active    — list all visitors currently on premises
 *   GET  /api/v1/visitors/:id       — get visitor record by National ID
 *   GET  /api/v1/visitors/logs      — paginated visit log (admin)
 *
 * PII (name, phone, email, host_name, purpose) is AES-256 encrypted before
 * being written to the database and decrypted on read.
 */

'use strict';

const { v4: uuidv4 }         = require('uuid');
const QRCode                 = require('qrcode');
const jwt                    = require('jsonwebtoken');
const { body, param, query: qv, validationResult } = require('express-validator');
const { query, getConnection } = require('../config/database');
const { encrypt, decrypt, sha256 } = require('../utils/crypto');
const { writeAudit, extractRequestContext, ACTIONS } = require('../utils/auditLogger');
const logger                 = require('../utils/logger');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function success(res, statusCode, data) {
  return res.status(statusCode).json({ success: true, data });
}
function fail(res, statusCode, code, message) {
  return res.status(statusCode).json({ success: false, error: { code, message } });
}

/**
 * Decrypt a visitor row from the database for client response.
 * Only call this for authorised requests.
 */
function decryptVisitor(row) {
  return {
    visitorId:   row.visitor_id,
    visitorName: decrypt(row.visitor_name_enc),
    phoneNum:    decrypt(row.phone_num_enc),
    email:       row.email_enc ? decrypt(row.email_enc) : null,
    idType:      row.id_type,
    isBlacklisted: !!row.is_blacklisted,
    firstSeen:   row.first_seen,
    lastSeen:    row.last_seen,
  };
}

/**
 * Decrypt a visit log row for client response.
 */
function decryptLog(row) {
  return {
    logId:        row.log_id,
    visitorId:    row.visitor_id,
    guardUsername: row.guard_username,
    hostName:     decrypt(row.host_name_enc),
    hostDept:     row.host_dept,
    purpose:      row.purpose_enc ? decrypt(row.purpose_enc) : null,
    vehiclePlate: row.vehicle_plate,
    gateEntry:    row.gate_entry,
    gateExit:     row.gate_exit,
    entryTime:    row.entry_time,
    exitTime:     row.exit_time,
    recordHash:   row.record_hash,
  };
}

// ---------------------------------------------------------------------------
// INPUT VALIDATION RULES
// ---------------------------------------------------------------------------
const registerValidation = [
  body('visitorId').trim().notEmpty().withMessage('National ID is required.').isLength({ max: 20 }),
  body('visitorName').trim().notEmpty().withMessage('Visitor name is required.').isLength({ max: 200 }),
  body('phoneNum').trim().notEmpty().withMessage('Phone number is required.').isLength({ max: 20 }),
  body('email').optional({ nullable: true }).trim().isEmail().withMessage('Invalid email address.'),
  body('hostName').trim().notEmpty().withMessage('Host name is required.').isLength({ max: 200 }),
  body('hostDept').optional({ nullable: true }).trim().isLength({ max: 200 }),
  body('purpose').optional({ nullable: true }).trim().isLength({ max: 500 }),
  body('vehiclePlate').optional({ nullable: true }).trim().isLength({ max: 20 }),
  body('gateEntry').optional().trim().isLength({ max: 50 }),
  body('idType').optional().isIn(['national_id', 'passport', 'alien_card']),
];

const exitValidation = [
  param('logId').isUUID(4).withMessage('Invalid log ID.'),
];

// ---------------------------------------------------------------------------
// CONTROLLER: Register Visitor (Check-In)
// POST /api/v1/visitors/register
// ---------------------------------------------------------------------------
async function registerVisitor(req, res) {
  const ctx = extractRequestContext(req);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return fail(res, 422, 'VALIDATION_ERROR', errors.array().map(e => e.msg).join(' '));
  }

  const {
    visitorId, visitorName, phoneNum, email,
    hostName, hostDept, purpose,
    vehiclePlate, gateEntry = 'Main Gate',
    idType = 'national_id',
  } = req.body;

  const conn = await getConnection();
  try {
    await conn.beginTransaction();

    // ── 1. Check for blacklisted visitor ──────────────────────────────────
    const [bRows] = await conn.execute(
      'SELECT is_blacklisted, blacklist_reason FROM tblVisitors WHERE visitor_id = ?',
      [visitorId]
    );

    if (bRows.length && bRows[0].is_blacklisted) {
      await conn.rollback();
      await writeAudit({
        userId:      req.user.userId,
        ...ctx,
        action:      ACTIONS.VISITOR_REGISTERED,
        status:      'FAILURE',
        targetTable: 'tblVisitors',
        targetId:    visitorId,
        detail:      `Blacklisted visitor ${visitorId} attempted entry`,
      });
      return fail(res, 403, 'VISITOR_BLACKLISTED',
        'This visitor is blacklisted. Entry denied. Please contact security management.');
    }

    // ── 2. Upsert visitor record ───────────────────────────────────────────
    // If the visitor exists, update their contact details (they may have changed).
    // If new, insert them.
    await conn.execute(
      `INSERT INTO tblVisitors
         (visitor_id, visitor_name_enc, phone_num_enc, email_enc, id_type)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         visitor_name_enc = VALUES(visitor_name_enc),
         phone_num_enc    = VALUES(phone_num_enc),
         email_enc        = VALUES(email_enc),
         last_seen        = CURRENT_TIMESTAMP`,
      [
        visitorId,
        encrypt(visitorName.trim()),
        encrypt(phoneNum.trim()),
        email ? encrypt(email.trim()) : null,
        idType,
      ]
    );

    // ── 3. Check if visitor already has an active (unclosed) visit ─────────
    const [activeRows] = await conn.execute(
      `SELECT log_id, entry_time FROM tblVisitLogs
       WHERE visitor_id = ? AND exit_time IS NULL
       LIMIT 1`,
      [visitorId]
    );

    if (activeRows.length) {
      await conn.rollback();
      return fail(res, 409, 'ALREADY_INSIDE',
        `This visitor is already logged as inside (Log ID: ${activeRows[0].log_id}). Log their exit first.`);
    }

    // ── 4. Create the visit log ────────────────────────────────────────────
    const logId    = uuidv4();
    const entryTime = new Date();
    const entryTimeStr = entryTime.toISOString().slice(0, 19).replace('T', ' ');

    // Integrity hash for tamper-evidence
    const recordHash = sha256(logId, visitorId, entryTimeStr, req.user.userId);

    // Generate a local pass JWT (QR payload)
    const passPayload = {
      logId, visitorId,
      entryTime: entryTimeStr,
      gate: gateEntry,
      issuedBy: req.user.username,
    };
    const passToken = jwt.sign(passPayload, process.env.QR_PASS_SECRET, {
      expiresIn: `${process.env.QR_PASS_EXPIRES_HOURS || 12}h`,
      issuer:    'sukuma-lango',
    });

    await conn.execute(
      `INSERT INTO tblVisitLogs
         (log_id, visitor_id, user_id, host_name_enc, host_dept,
          purpose_enc, vehicle_plate, local_pass_token,
          entry_time, gate_entry, record_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        logId,
        visitorId,
        req.user.userId,
        encrypt(hostName.trim()),
        hostDept  ? hostDept.trim()  : null,
        purpose   ? encrypt(purpose.trim()) : null,
        vehiclePlate ? vehiclePlate.toUpperCase().trim() : null,
        passToken,
        entryTimeStr,
        gateEntry,
        recordHash,
      ]
    );

    await conn.commit();

    // ── 5. Generate QR code (data URL) ────────────────────────────────────
    let qrCodeDataUrl = null;
    try {
      qrCodeDataUrl = await QRCode.toDataURL(passToken, {
        errorCorrectionLevel: 'H',
        width: 300,
        margin: 2,
      });
    } catch (qrErr) {
      logger.warn('QR code generation failed', { error: qrErr.message });
    }

    // ── 6. Audit the successful registration ──────────────────────────────
    await writeAudit({
      userId:      req.user.userId,
      ...ctx,
      action:      ACTIONS.VISITOR_REGISTERED,
      status:      'SUCCESS',
      targetTable: 'tblVisitLogs',
      targetId:    logId,
      detail:      { visitorId, gate: gateEntry, guard: req.user.username },
    });

    logger.info('Visitor registered', {
      logId, visitorId, gate: gateEntry, guard: req.user.username,
    });

    return success(res, 201, {
      logId,
      visitorId,
      entryTime: entryTimeStr,
      gateEntry,
      recordHash,
      qrCodeDataUrl,   // Display on guard's screen for the physical pass
      passToken,       // Raw token (also encoded in QR)
    });

  } catch (err) {
    await conn.rollback();
    logger.error('registerVisitor error', { error: err.message });
    await writeAudit({
      userId:     req.user.userId,
      ...ctx,
      action:     ACTIONS.VISITOR_REGISTERED,
      status:     'FAILURE',
      detail:     err.message,
    });
    return fail(res, 500, 'SERVER_ERROR', 'Failed to register visitor.');
  } finally {
    conn.release();
  }
}

// ---------------------------------------------------------------------------
// CONTROLLER: Log Exit
// PATCH /api/v1/visitors/:logId/exit
// ---------------------------------------------------------------------------
async function logExit(req, res) {
  const ctx = extractRequestContext(req);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return fail(res, 422, 'VALIDATION_ERROR', errors.array().map(e => e.msg).join(' '));
  }

  const { logId } = req.params;
  const { gateExit = 'Main Gate' } = req.body;

  try {
    // Verify the log exists and is still open
    const [rows] = await query(
      `SELECT log_id, visitor_id, exit_time
       FROM tblVisitLogs WHERE log_id = ?`,
      [logId]
    );

    if (!rows.length) {
      return fail(res, 404, 'LOG_NOT_FOUND', 'Visit log record not found.');
    }

    if (rows[0].exit_time) {
      return fail(res, 409, 'ALREADY_EXITED', 'Exit has already been recorded for this visit.');
    }

    const exitTime = new Date().toISOString().slice(0, 19).replace('T', ' ');

    await query(
      `UPDATE tblVisitLogs
         SET exit_time    = ?,
             exit_user_id = ?,
             gate_exit    = ?
       WHERE log_id = ? AND exit_time IS NULL`,
      [exitTime, req.user.userId, gateExit, logId]
    );

    await writeAudit({
      userId:      req.user.userId,
      ...ctx,
      action:      ACTIONS.VISITOR_EXIT_LOGGED,
      status:      'SUCCESS',
      targetTable: 'tblVisitLogs',
      targetId:    logId,
      detail:      { visitorId: rows[0].visitor_id, gateExit, guard: req.user.username },
    });

    logger.info('Visitor exit logged', { logId, visitorId: rows[0].visitor_id });

    return success(res, 200, { logId, exitTime, gateExit, message: 'Exit recorded successfully.' });

  } catch (err) {
    logger.error('logExit error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Failed to log exit.');
  }
}

// ---------------------------------------------------------------------------
// CONTROLLER: Get active visitors (currently on premises)
// GET /api/v1/visitors/active
// ---------------------------------------------------------------------------
async function getActiveVisitors(req, res) {
  try {
    const [rows] = await query(
      `SELECT
         vl.log_id, vl.visitor_id, vl.entry_time,
         vl.gate_entry, vl.host_dept, vl.vehicle_plate,
         vl.host_name_enc, vl.purpose_enc,
         u.username AS guard_username
       FROM tblVisitLogs vl
       JOIN tblUsers u ON vl.user_id = u.user_id
       WHERE vl.exit_time IS NULL
       ORDER BY vl.entry_time DESC`
    );

    const visitors = rows.map(row => ({
      logId:        row.log_id,
      visitorId:    row.visitor_id,
      entryTime:    row.entry_time,
      gateEntry:    row.gate_entry,
      hostDept:     row.host_dept,
      hostName:     decrypt(row.host_name_enc),
      purpose:      row.purpose_enc ? decrypt(row.purpose_enc) : null,
      vehiclePlate: row.vehicle_plate,
      guardUsername: row.guard_username,
    }));

    return success(res, 200, {
      count: visitors.length,
      visitors,
    });
  } catch (err) {
    logger.error('getActiveVisitors error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Failed to retrieve active visitors.');
  }
}

// ---------------------------------------------------------------------------
// CONTROLLER: Get visit logs (paginated, admin)
// GET /api/v1/visitors/logs?page=1&limit=50&from=YYYY-MM-DD&to=YYYY-MM-DD
// ---------------------------------------------------------------------------
async function getVisitLogs(req, res) {
  const ctx = extractRequestContext(req);

  const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
  const limit = Math.min(100, parseInt(req.query.limit, 10) || 50);
  const offset = (page - 1) * limit;

  const from  = req.query.from  || null;
  const to    = req.query.to    || null;

  let whereClauses = [];
  let params = [];

  if (from) { whereClauses.push('vl.entry_time >= ?'); params.push(from + ' 00:00:00'); }
  if (to)   { whereClauses.push('vl.entry_time <= ?'); params.push(to   + ' 23:59:59'); }

  const where = whereClauses.length ? 'WHERE ' + whereClauses.join(' AND ') : '';

  try {
    const [countRows] = await query(
      `SELECT COUNT(*) AS total FROM tblVisitLogs vl ${where}`, params
    );
    const total = countRows[0].total;

    const [rows] = await query(
      `SELECT
         vl.log_id, vl.visitor_id, vl.entry_time, vl.exit_time,
         vl.gate_entry, vl.gate_exit, vl.host_dept, vl.vehicle_plate,
         vl.host_name_enc, vl.purpose_enc, vl.record_hash,
         u.username AS guard_username
       FROM tblVisitLogs vl
       JOIN tblUsers u ON vl.user_id = u.user_id
       ${where}
       ORDER BY vl.entry_time DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    const logs = rows.map(decryptLog);

    await writeAudit({
      userId:  req.user.userId,
      ...ctx,
      action:  ACTIONS.LOG_VIEWED,
      status:  'SUCCESS',
      detail:  { page, limit, from, to, returned: logs.length },
    });

    return success(res, 200, { total, page, limit, logs });

  } catch (err) {
    logger.error('getVisitLogs error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Failed to retrieve visit logs.');
  }
}

// ---------------------------------------------------------------------------
// CONTROLLER: Get visitor record by National ID
// GET /api/v1/visitors/:id
// ---------------------------------------------------------------------------
async function getVisitorById(req, res) {
  const { id } = req.params;
  try {
    const [rows] = await query(
      `SELECT * FROM tblVisitors WHERE visitor_id = ?`, [id]
    );
    if (!rows.length) {
      return fail(res, 404, 'NOT_FOUND', 'Visitor not found.');
    }
    return success(res, 200, decryptVisitor(rows[0]));
  } catch (err) {
    logger.error('getVisitorById error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Failed to retrieve visitor.');
  }
}

module.exports = {
  registerVisitor,
  logExit,
  getActiveVisitors,
  getVisitLogs,
  getVisitorById,
  registerValidation,
  exitValidation,
};
