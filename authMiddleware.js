/**
 * sukuma-lango/backend/src/middleware/authMiddleware.js
 *
 * Two middleware functions:
 *   1. authenticate  — verifies the Bearer JWT and attaches req.user
 *   2. authorize     — checks that req.user has the required permission(s)
 *
 * Every failed auth attempt is written to tblForensicAudits.
 */

'use strict';

const jwt                                 = require('jsonwebtoken');
const { query }                           = require('../config/database');
const { writeAudit, extractRequestContext, ACTIONS } = require('../utils/auditLogger');
const logger                              = require('../utils/logger');

// ---------------------------------------------------------------------------
// Helper: send a standardised error response
// ---------------------------------------------------------------------------
function sendAuthError(res, statusCode, code, message) {
  return res.status(statusCode).json({
    success: false,
    error:   { code, message },
  });
}

// ---------------------------------------------------------------------------
// MIDDLEWARE 1: authenticate
// Verifies the JWT from Authorization: Bearer <token>
// On success: attaches { userId, username, roleId, roleName, permissions, shiftStatus }
// to req.user and calls next().
// ---------------------------------------------------------------------------
async function authenticate(req, res, next) {
  const ctx = extractRequestContext(req);

  // 1. Extract token from header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    await writeAudit({
      ...ctx,
      action: ACTIONS.UNAUTHORIZED_ACCESS,
      status: 'FAILURE',
      detail: 'Missing or malformed Authorization header',
    });
    return sendAuthError(res, 401, 'MISSING_TOKEN', 'Authentication token required.');
  }

  const token = authHeader.slice(7);   // Strip "Bearer "

  // 2. Verify JWT signature and expiry
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    const isExpired = err.name === 'TokenExpiredError';
    await writeAudit({
      ...ctx,
      action:  ACTIONS.UNAUTHORIZED_ACCESS,
      status:  'FAILURE',
      detail:  isExpired ? 'Token expired' : `Invalid token: ${err.message}`,
    });
    return sendAuthError(
      res,
      401,
      isExpired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN',
      isExpired ? 'Session expired. Please log in again.' : 'Invalid authentication token.'
    );
  }

  // 3. Look up the user in the database (ensures token isn't stale after role change)
  try {
    const [rows] = await query(
      `SELECT
         u.user_id, u.username, u.shift_status,
         u.locked_until, u.role_id,
         r.role_name, r.permissions, r.is_active AS role_active
       FROM tblUsers u
       JOIN tblRoles r ON u.role_id = r.role_id
       WHERE u.user_id = ?`,
      [decoded.sub]
    );

    if (rows.length === 0) {
      await writeAudit({
        userId:  decoded.sub,
        ...ctx,
        action:  ACTIONS.UNAUTHORIZED_ACCESS,
        status:  'FAILURE',
        detail:  'User not found in database',
      });
      return sendAuthError(res, 401, 'USER_NOT_FOUND', 'Authentication failed.');
    }

    const user = rows[0];

    // 4. Check if account is locked
    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      await writeAudit({
        userId:     user.user_id,
        ...ctx,
        action:     ACTIONS.UNAUTHORIZED_ACCESS,
        status:     'FAILURE',
        targetTable: 'tblUsers',
        targetId:   user.user_id,
        detail:     'Access attempted on locked account',
      });
      return sendAuthError(res, 403, 'ACCOUNT_LOCKED', 'Account is temporarily locked. Please contact your administrator.');
    }

    // 5. Check if the role is still active
    if (!user.role_active) {
      await writeAudit({
        userId:     user.user_id,
        ...ctx,
        action:     ACTIONS.FORBIDDEN_ACCESS,
        status:     'FAILURE',
        detail:     'Role has been deactivated',
      });
      return sendAuthError(res, 403, 'ROLE_INACTIVE', 'Your role has been deactivated. Contact an administrator.');
    }

    // 6. Attach user context to request (available in all downstream middleware/controllers)
    req.user = {
      userId:      user.user_id,
      username:    user.username,
      roleId:      user.role_id,
      roleName:    user.role_name,
      permissions: user.permissions,   // JSON array from DB (mysql2 auto-parses JSON columns)
      shiftStatus: user.shift_status,
    };

    logger.debug('Authenticated request', {
      userId:   req.user.userId,
      username: req.user.username,
      path:     ctx.requestPath,
    });

    return next();

  } catch (err) {
    logger.error('authenticate middleware DB error', { error: err.message });
    return sendAuthError(res, 500, 'SERVER_ERROR', 'Authentication service unavailable.');
  }
}

// ---------------------------------------------------------------------------
// MIDDLEWARE 2: authorize
// Factory function — returns a middleware that checks for required permission(s).
// Usage: router.get('/admin/logs', authenticate, authorize('view_all_logs'), handler)
// ---------------------------------------------------------------------------
function authorize(...requiredPermissions) {
  return async function (req, res, next) {
    const ctx = extractRequestContext(req);

    if (!req.user) {
      // Should never happen if authenticate ran first, but guard anyway
      return sendAuthError(res, 401, 'UNAUTHENTICATED', 'Not authenticated.');
    }

    const userPerms = Array.isArray(req.user.permissions)
      ? req.user.permissions
      : [];

    // Check that the user holds ALL required permissions
    const hasAll = requiredPermissions.every(perm => userPerms.includes(perm));

    if (!hasAll) {
      const missing = requiredPermissions.filter(p => !userPerms.includes(p));

      await writeAudit({
        userId:     req.user.userId,
        ...ctx,
        action:     ACTIONS.FORBIDDEN_ACCESS,
        status:     'FAILURE',
        detail:     { required: requiredPermissions, missing, role: req.user.roleName },
      });

      logger.warn('Permission denied', {
        userId:   req.user.userId,
        username: req.user.username,
        missing,
        path:     ctx.requestPath,
      });

      return sendAuthError(
        res,
        403,
        'INSUFFICIENT_PERMISSIONS',
        `Access denied. Required permission(s): ${missing.join(', ')}.`
      );
    }

    return next();
  };
}

// ---------------------------------------------------------------------------
// MIDDLEWARE 3: requireOnDuty
// Guards must be on duty to register visitors or log exits.
// ---------------------------------------------------------------------------
async function requireOnDuty(req, res, next) {
  if (req.user?.shiftStatus !== 'on_duty') {
    const ctx = extractRequestContext(req);
    await writeAudit({
      userId:     req.user?.userId,
      ...ctx,
      action:     ACTIONS.FORBIDDEN_ACCESS,
      status:     'WARNING',
      detail:     `Shift status: ${req.user?.shiftStatus}. Required: on_duty`,
    });
    return sendAuthError(
      res,
      403,
      'NOT_ON_DUTY',
      'You must be on duty to perform this action. Contact your supervisor.'
    );
  }
  return next();
}

module.exports = { authenticate, authorize, requireOnDuty };
