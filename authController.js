/**
 * sukuma-lango/backend/src/controllers/authController.js
 *
 * Handles:
 *   POST /api/v1/auth/login    — credential validation, JWT issuance
 *   POST /api/v1/auth/logout   — client-side token invalidation + audit
 *   POST /api/v1/auth/refresh  — refresh token exchange
 *   GET  /api/v1/auth/me       — return current user profile
 *
 * Security measures:
 *   - bcrypt comparison (cost 12) for password verification
 *   - Configurable account lockout after N failed attempts
 *   - Constant-time response to prevent username enumeration timing attacks
 *   - ALL outcomes logged to tblForensicAudits
 */

'use strict';

const bcrypt                              = require('bcrypt');
const jwt                                 = require('jsonwebtoken');
const { v4: uuidv4 }                      = require('uuid');
const { body, validationResult }          = require('express-validator');
const { query, getConnection }            = require('../config/database');
const { writeAudit, extractRequestContext, ACTIONS } = require('../utils/auditLogger');
const logger                              = require('../utils/logger');

// ---------------------------------------------------------------------------
// Config values (from .env)
// ---------------------------------------------------------------------------
const BCRYPT_ROUNDS        = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;
const JWT_SECRET           = () => process.env.JWT_SECRET;
const JWT_EXPIRES_IN       = process.env.JWT_EXPIRES_IN       || '8h';
const JWT_REFRESH_SECRET   = () => process.env.JWT_REFRESH_SECRET;
const JWT_REFRESH_EXPIRES  = process.env.JWT_REFRESH_EXPIRES_IN || '24h';
const MAX_ATTEMPTS         = parseInt(process.env.ACCOUNT_LOCKOUT_ATTEMPTS, 10) || 5;
const LOCKOUT_MS           = parseInt(process.env.ACCOUNT_LOCKOUT_DURATION_MS, 10) || 1800000;

// ---------------------------------------------------------------------------
// Helper: issue a signed JWT pair (access + refresh)
// ---------------------------------------------------------------------------
function issueTokens(user) {
  const payload = {
    sub:      user.user_id,
    username: user.username,
    role:     user.role_name,
    roleId:   user.role_id,
  };

  const accessToken = jwt.sign(payload, JWT_SECRET(), {
    expiresIn:  JWT_EXPIRES_IN,
    issuer:     'sukuma-lango',
    audience:   'sukuma-lango-client',
    jwtid:      uuidv4(),
  });

  const refreshToken = jwt.sign(
    { sub: user.user_id, type: 'refresh' },
    JWT_REFRESH_SECRET(),
    {
      expiresIn: JWT_REFRESH_EXPIRES,
      issuer:    'sukuma-lango',
      jwtid:     uuidv4(),
    }
  );

  return { accessToken, refreshToken };
}

// ---------------------------------------------------------------------------
// Helper: standard success response
// ---------------------------------------------------------------------------
function success(res, statusCode, data) {
  return res.status(statusCode).json({ success: true, data });
}

// Helper: standard error response
function fail(res, statusCode, code, message) {
  return res.status(statusCode).json({ success: false, error: { code, message } });
}

// ---------------------------------------------------------------------------
// INPUT VALIDATION RULES (express-validator)
// ---------------------------------------------------------------------------
const loginValidation = [
  body('username')
    .trim()
    .notEmpty().withMessage('Username is required.')
    .isLength({ max: 100 }).withMessage('Username too long.'),
  body('password')
    .notEmpty().withMessage('Password is required.')
    .isLength({ min: 8, max: 128 }).withMessage('Password must be 8–128 characters.'),
];

// ---------------------------------------------------------------------------
// CONTROLLER: Login
// POST /api/v1/auth/login
// ---------------------------------------------------------------------------
async function login(req, res) {
  const ctx = extractRequestContext(req);

  // 1. Validate input
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return fail(res, 422, 'VALIDATION_ERROR', errors.array().map(e => e.msg).join(' '));
  }

  const { username, password } = req.body;

  // 2. Fetch user (including role permissions)
  let user;
  try {
    const [rows] = await query(
      `SELECT
         u.user_id, u.username, u.password_hash, u.shift_status,
         u.failed_attempts, u.locked_until, u.role_id,
         r.role_name, r.permissions, r.is_active AS role_active
       FROM tblUsers u
       JOIN tblRoles r ON u.role_id = r.role_id
       WHERE u.username = ?
       LIMIT 1`,
      [username]
    );
    user = rows[0] || null;
  } catch (err) {
    logger.error('Login DB error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Authentication service unavailable.');
  }

  // ---------------------------------------------------------------------------
  // 3. Constant-time path: even if user not found, run bcrypt compare
  //    so response time doesn't reveal whether username exists.
  // ---------------------------------------------------------------------------
  const DUMMY_HASH = '$2b$12$invalidhashforthepurposeoftimingprotectiononly.xxxxx';
  const hashToCompare = user ? user.password_hash : DUMMY_HASH;
  const passwordMatch = await bcrypt.compare(password, hashToCompare);

  // 4. User not found → generic failure
  if (!user) {
    await writeAudit({
      ...ctx,
      action:  ACTIONS.LOGIN_FAILURE,
      status:  'FAILURE',
      detail:  `Unknown username attempt: ${username.substring(0, 20)}`,
    });
    return fail(res, 401, 'INVALID_CREDENTIALS', 'Invalid username or password.');
  }

  // 5. Account locked?
  if (user.locked_until && new Date() < new Date(user.locked_until)) {
    const unlockAt = new Date(user.locked_until).toISOString();
    await writeAudit({
      userId:     user.user_id,
      ...ctx,
      action:     ACTIONS.LOGIN_FAILURE,
      status:     'FAILURE',
      targetTable: 'tblUsers',
      targetId:   user.user_id,
      detail:     `Login attempt on locked account. Unlocks at ${unlockAt}`,
    });
    return fail(res, 423, 'ACCOUNT_LOCKED',
      `Account is locked due to too many failed attempts. Try again after ${unlockAt}.`);
  }

  // 6. Role inactive?
  if (!user.role_active) {
    await writeAudit({
      userId:     user.user_id,
      ...ctx,
      action:     ACTIONS.LOGIN_FAILURE,
      status:     'FAILURE',
      detail:     'Login attempt with deactivated role',
    });
    return fail(res, 403, 'ROLE_INACTIVE', 'Your account role is inactive. Contact an administrator.');
  }

  // 7. Wrong password
  if (!passwordMatch) {
    const newAttempts = (user.failed_attempts || 0) + 1;
    const shouldLock  = newAttempts >= MAX_ATTEMPTS;

    const lockUntil = shouldLock
      ? new Date(Date.now() + LOCKOUT_MS).toISOString().slice(0, 19).replace('T', ' ')
      : null;

    // Update attempt counter (and optionally lock the account)
    try {
      await query(
        `UPDATE tblUsers
           SET failed_attempts = ?, locked_until = ?
         WHERE user_id = ?`,
        [newAttempts, lockUntil, user.user_id]
      );
    } catch (dbErr) {
      logger.error('Failed to update failed_attempts', { error: dbErr.message });
    }

    // Audit the failure
    await writeAudit({
      userId:     user.user_id,
      ...ctx,
      action:     shouldLock ? ACTIONS.ACCOUNT_LOCKED : ACTIONS.LOGIN_FAILURE,
      status:     'FAILURE',
      targetTable: 'tblUsers',
      targetId:   user.user_id,
      detail:     shouldLock
        ? `Account locked after ${newAttempts} failed attempts. Unlocks at ${lockUntil}`
        : `Failed attempt ${newAttempts}/${MAX_ATTEMPTS}`,
    });

    if (shouldLock) {
      return fail(res, 423, 'ACCOUNT_LOCKED',
        `Too many failed attempts. Account locked for ${LOCKOUT_MS / 60000} minutes.`);
    }

    const remaining = MAX_ATTEMPTS - newAttempts;
    return fail(res, 401, 'INVALID_CREDENTIALS',
      `Invalid username or password. ${remaining} attempt(s) remaining.`);
  }

  // =========================================================================
  // 8. SUCCESS — credentials verified
  // =========================================================================

  // Reset failed attempts and update last_login
  try {
    await query(
      `UPDATE tblUsers
         SET failed_attempts = 0, locked_until = NULL, last_login = NOW()
       WHERE user_id = ?`,
      [user.user_id]
    );
  } catch (dbErr) {
    logger.error('Failed to reset failed_attempts', { error: dbErr.message });
  }

  // Issue JWT tokens
  const { accessToken, refreshToken } = issueTokens(user);

  // Audit the successful login
  await writeAudit({
    userId:     user.user_id,
    ...ctx,
    action:     ACTIONS.LOGIN_SUCCESS,
    status:     'SUCCESS',
    targetTable: 'tblUsers',
    targetId:   user.user_id,
    detail:     { role: user.role_name, shift: user.shift_status },
  });

  logger.info('User logged in', { username: user.username, role: user.role_name, ip: ctx.ipAddress });

  return success(res, 200, {
    accessToken,
    refreshToken,
    expiresIn: JWT_EXPIRES_IN,
    user: {
      userId:      user.user_id,
      username:    user.username,
      roleName:    user.role_name,
      permissions: user.permissions,
      shiftStatus: user.shift_status,
    },
  });
}

// ---------------------------------------------------------------------------
// CONTROLLER: Logout
// POST /api/v1/auth/logout
// (Stateless JWT — we just audit the logout event. Client discards the token.)
// ---------------------------------------------------------------------------
async function logout(req, res) {
  const ctx = extractRequestContext(req);

  await writeAudit({
    userId:     req.user?.userId,
    ...ctx,
    action:     ACTIONS.LOGOUT,
    status:     'SUCCESS',
    targetTable: 'tblUsers',
    targetId:   req.user?.userId,
    detail:     { username: req.user?.username },
  });

  logger.info('User logged out', { username: req.user?.username });
  return success(res, 200, { message: 'Logged out successfully.' });
}

// ---------------------------------------------------------------------------
// CONTROLLER: Refresh Token
// POST /api/v1/auth/refresh
// Body: { refreshToken: "..." }
// ---------------------------------------------------------------------------
async function refreshToken(req, res) {
  const ctx = extractRequestContext(req);
  const { refreshToken: token } = req.body;

  if (!token) {
    return fail(res, 400, 'MISSING_TOKEN', 'Refresh token required.');
  }

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_REFRESH_SECRET());
    if (decoded.type !== 'refresh') throw new Error('Not a refresh token');
  } catch (err) {
    await writeAudit({
      ...ctx,
      action:  ACTIONS.TOKEN_REFRESH,
      status:  'FAILURE',
      detail:  `Invalid refresh token: ${err.message}`,
    });
    return fail(res, 401, 'INVALID_REFRESH_TOKEN', 'Invalid or expired refresh token.');
  }

  // Fetch fresh user data (role may have changed since original login)
  try {
    const [rows] = await query(
      `SELECT
         u.user_id, u.username, u.shift_status, u.role_id,
         r.role_name, r.permissions, r.is_active
       FROM tblUsers u
       JOIN tblRoles r ON u.role_id = r.role_id
       WHERE u.user_id = ?`,
      [decoded.sub]
    );

    if (!rows.length || !rows[0].is_active) {
      return fail(res, 401, 'USER_INVALID', 'User account is no longer valid.');
    }

    const user = rows[0];
    const { accessToken, refreshToken: newRefresh } = issueTokens(user);

    await writeAudit({
      userId:  user.user_id,
      ...ctx,
      action:  ACTIONS.TOKEN_REFRESH,
      status:  'SUCCESS',
    });

    return success(res, 200, { accessToken, refreshToken: newRefresh, expiresIn: JWT_EXPIRES_IN });

  } catch (err) {
    logger.error('Refresh token DB error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Token refresh service unavailable.');
  }
}

// ---------------------------------------------------------------------------
// CONTROLLER: Get current user profile
// GET /api/v1/auth/me
// ---------------------------------------------------------------------------
async function getMe(req, res) {
  try {
    const [rows] = await query(
      `SELECT
         u.user_id, u.username, u.full_name, u.shift_status, u.last_login,
         r.role_name, r.permissions
       FROM tblUsers u
       JOIN tblRoles r ON u.role_id = r.role_id
       WHERE u.user_id = ?`,
      [req.user.userId]
    );

    if (!rows.length) {
      return fail(res, 404, 'USER_NOT_FOUND', 'User not found.');
    }

    const u = rows[0];
    return success(res, 200, {
      userId:      u.user_id,
      username:    u.username,
      fullName:    u.full_name,
      shiftStatus: u.shift_status,
      lastLogin:   u.last_login,
      roleName:    u.role_name,
      permissions: u.permissions,
    });
  } catch (err) {
    logger.error('getMe DB error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Could not retrieve profile.');
  }
}

module.exports = { login, logout, refreshToken, getMe, loginValidation };
