/**
 * sukuma-lango/backend/src/utils/auditLogger.js
 * Writes append-only records to tblForensicAudits.
 * This is the chain-of-custody engine — EVERY significant action
 * (login, logout, visitor register, data export, etc.) must call this.
 *
 * Rule: Never update or delete rows in tblForensicAudits.
 */

'use strict';

const { query } = require('../config/database');
const { encrypt } = require('./crypto');
const logger      = require('./logger');

// ---------------------------------------------------------------------------
// Action type constants (import these instead of raw strings)
// ---------------------------------------------------------------------------
const ACTIONS = Object.freeze({
  // Auth
  LOGIN_SUCCESS:        'LOGIN_SUCCESS',
  LOGIN_FAILURE:        'LOGIN_FAILURE',
  LOGOUT:               'LOGOUT',
  TOKEN_REFRESH:        'TOKEN_REFRESH',
  ACCOUNT_LOCKED:       'ACCOUNT_LOCKED',
  PASSWORD_RESET:       'PASSWORD_RESET',
  // Visitor
  VISITOR_REGISTERED:   'VISITOR_REGISTERED',
  VISITOR_EXIT_LOGGED:  'VISITOR_EXIT_LOGGED',
  VISITOR_UPDATED:      'VISITOR_UPDATED',
  VISITOR_BLACKLISTED:  'VISITOR_BLACKLISTED',
  // Admin
  LOG_EXPORTED:         'LOG_EXPORTED',
  LOG_VIEWED:           'LOG_VIEWED',
  USER_CREATED:         'USER_CREATED',
  USER_UPDATED:         'USER_UPDATED',
  USER_DELETED:         'USER_DELETED',
  ROLE_CHANGED:         'ROLE_CHANGED',
  // System
  SYSTEM_STARTUP:       'SYSTEM_STARTUP',
  DB_ERROR:             'DB_ERROR',
  UNAUTHORIZED_ACCESS:  'UNAUTHORIZED_ACCESS',
  FORBIDDEN_ACCESS:     'FORBIDDEN_ACCESS',
});

// ---------------------------------------------------------------------------
// Core audit write function
// ---------------------------------------------------------------------------
/**
 * @param {object} opts
 * @param {string|null}  opts.userId       - UUID of the acting user (null for anon/system)
 * @param {string}       opts.action       - One of ACTIONS constants
 * @param {string|null}  opts.targetTable  - DB table affected
 * @param {string|null}  opts.targetId     - PK of affected record
 * @param {string}       opts.ipAddress    - Client IP
 * @param {string|null}  opts.userAgent    - Browser/client user agent
 * @param {string|null}  opts.requestPath  - Request endpoint
 * @param {'SUCCESS'|'FAILURE'|'WARNING'} opts.status
 * @param {object|string|null} opts.detail - Extra context (will be encrypted)
 */
async function writeAudit({
  userId      = null,
  action,
  targetTable = null,
  targetId    = null,
  ipAddress   = '0.0.0.0',
  userAgent   = null,
  requestPath = null,
  status      = 'SUCCESS',
  detail      = null,
}) {
  try {
    // Encrypt the detail payload to protect any PII it might contain
    const detailStr = detail
      ? (typeof detail === 'object' ? JSON.stringify(detail) : String(detail))
      : null;
    const detailEnc = detailStr ? encrypt(detailStr) : null;

    const sql = `
      INSERT INTO tblForensicAudits
        (user_id, action_taken, target_table, target_id,
         ip_address, user_agent, request_path, status, detail_enc)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await query(sql, [
      userId,
      action,
      targetTable,
      targetId,
      ipAddress.substring(0, 45),           // IPv6 max = 45 chars
      userAgent  ? userAgent.substring(0, 500)   : null,
      requestPath ? requestPath.substring(0, 255) : null,
      status,
      detailEnc,
    ]);
  } catch (err) {
    // Never let audit failure crash the main flow — log to file only
    logger.error('CRITICAL: Failed to write audit record', {
      action,
      userId,
      error: err.message,
    });
  }
}

// ---------------------------------------------------------------------------
// Convenience helper: extract request context from Express req object
// ---------------------------------------------------------------------------
function extractRequestContext(req) {
  return {
    ipAddress:   req.ip || req.connection?.remoteAddress || '0.0.0.0',
    userAgent:   req.get('User-Agent') || null,
    requestPath: req.originalUrl || req.path || null,
  };
}

module.exports = { writeAudit, extractRequestContext, ACTIONS };
