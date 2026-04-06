/**
 * sukuma-lango/backend/src/controllers/auditController.js
 *
 * Admin-only forensic audit module:
 *   GET  /api/v1/audit/logs       — query the forensic audit trail
 *   GET  /api/v1/audit/anomalies  — flag suspicious activity patterns
 *   POST /api/v1/audit/export     — export logs to encrypted CSV / PDF (metadata)
 *   GET  /api/v1/audit/occupancy  — real-time occupancy count
 */

'use strict';

const { query }              = require('../config/database');
const { decrypt }            = require('../utils/crypto');
const { writeAudit, extractRequestContext, ACTIONS } = require('../utils/auditLogger');
const logger                 = require('../utils/logger');

function success(res, code, data) { return res.status(code).json({ success: true, data }); }
function fail(res, code, errCode, msg) { return res.status(code).json({ success: false, error: { code: errCode, message: msg } }); }

// ---------------------------------------------------------------------------
// GET /api/v1/audit/logs
// Paginated view of the forensic audit trail (admin only)
// ---------------------------------------------------------------------------
async function getAuditLogs(req, res) {
  const ctx = extractRequestContext(req);

  const page    = Math.max(1, parseInt(req.query.page, 10)   || 1);
  const limit   = Math.min(200, parseInt(req.query.limit, 10) || 100);
  const offset  = (page - 1) * limit;
  const action  = req.query.action  || null;
  const status  = req.query.status  || null;
  const userId  = req.query.userId  || null;
  const from    = req.query.from    || null;
  const to      = req.query.to      || null;

  const conditions = [];
  const params     = [];

  if (action)  { conditions.push('fa.action_taken = ?');   params.push(action); }
  if (status)  { conditions.push('fa.status = ?');          params.push(status); }
  if (userId)  { conditions.push('fa.user_id = ?');         params.push(userId); }
  if (from)    { conditions.push('fa.timestamp >= ?');       params.push(from + ' 00:00:00'); }
  if (to)      { conditions.push('fa.timestamp <= ?');       params.push(to   + ' 23:59:59'); }

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

  try {
    const [countRows] = await query(
      `SELECT COUNT(*) AS total FROM tblForensicAudits fa ${where}`, params
    );
    const total = countRows[0].total;

    const [rows] = await query(
      `SELECT
         fa.audit_id, fa.action_taken, fa.target_table, fa.target_id,
         fa.ip_address, fa.user_agent, fa.request_path,
         fa.status, fa.timestamp,
         u.username
       FROM tblForensicAudits fa
       LEFT JOIN tblUsers u ON fa.user_id = u.user_id
       ${where}
       ORDER BY fa.timestamp DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    // Don't decrypt detail_enc here — it's too sensitive for bulk export
    // Individual record drill-down can be added as a separate endpoint

    await writeAudit({
      userId:  req.user.userId,
      ...ctx,
      action:  ACTIONS.LOG_VIEWED,
      status:  'SUCCESS',
      detail:  { type: 'AUDIT_TRAIL', page, limit, filters: { action, status, from, to } },
    });

    return success(res, 200, { total, page, limit, logs: rows });

  } catch (err) {
    logger.error('getAuditLogs error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Failed to retrieve audit logs.');
  }
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit/anomalies
// Detects suspicious patterns (frequent visitor, after-hours, failed logins)
// ---------------------------------------------------------------------------
async function getAnomalies(req, res) {
  const ctx = extractRequestContext(req);

  try {
    const results = {};

    // Pattern 1: Visitors who entered more than 3 times in 24 hours
    const [freqRows] = await query(
      `SELECT
         visitor_id,
         COUNT(*) AS visit_count,
         MIN(entry_time) AS first_visit,
         MAX(entry_time) AS last_visit
       FROM tblVisitLogs
       WHERE entry_time >= NOW() - INTERVAL 24 HOUR
       GROUP BY visitor_id
       HAVING COUNT(*) > 3
       ORDER BY visit_count DESC`
    );
    results.frequentVisitors = freqRows;

    // Pattern 2: Visits without exit (overnight / abandoned)
    const [longRows] = await query(
      `SELECT
         log_id, visitor_id, entry_time, gate_entry,
         TIMESTAMPDIFF(HOUR, entry_time, NOW()) AS hours_inside
       FROM tblVisitLogs
       WHERE exit_time IS NULL
         AND entry_time < NOW() - INTERVAL 12 HOUR
       ORDER BY entry_time ASC`
    );
    results.longStay = longRows;

    // Pattern 3: Multiple failed logins from same IP in last hour
    const [failedRows] = await query(
      `SELECT
         ip_address,
         COUNT(*) AS failure_count,
         MAX(timestamp) AS last_attempt
       FROM tblForensicAudits
       WHERE action_taken = 'LOGIN_FAILURE'
         AND timestamp >= NOW() - INTERVAL 1 HOUR
       GROUP BY ip_address
       HAVING COUNT(*) >= 3
       ORDER BY failure_count DESC`
    );
    results.bruteForceAttempts = failedRows;

    // Pattern 4: After-hours entries (before 6am or after 10pm)
    const [afterHoursRows] = await query(
      `SELECT
         log_id, visitor_id, entry_time, gate_entry,
         HOUR(entry_time) AS hour_of_entry
       FROM tblVisitLogs
       WHERE entry_time >= NOW() - INTERVAL 7 DAY
         AND (HOUR(entry_time) < 6 OR HOUR(entry_time) >= 22)
       ORDER BY entry_time DESC
       LIMIT 50`
    );
    results.afterHoursEntries = afterHoursRows;

    await writeAudit({
      userId:     req.user.userId,
      ...ctx,
      action:     ACTIONS.LOG_VIEWED,
      status:     'SUCCESS',
      detail:     'Anomaly report generated',
    });

    return success(res, 200, {
      generatedAt: new Date().toISOString(),
      anomalies:   results,
    });

  } catch (err) {
    logger.error('getAnomalies error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Failed to generate anomaly report.');
  }
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit/occupancy
// Real-time occupancy: count of visitors currently inside
// ---------------------------------------------------------------------------
async function getOccupancy(req, res) {
  try {
    const [rows] = await query(
      `SELECT
         COUNT(*) AS total_inside,
         COUNT(CASE WHEN vehicle_plate IS NOT NULL THEN 1 END) AS with_vehicles
       FROM tblVisitLogs
       WHERE exit_time IS NULL`
    );

    const [gateBreakdown] = await query(
      `SELECT gate_entry, COUNT(*) AS count
       FROM tblVisitLogs
       WHERE exit_time IS NULL
       GROUP BY gate_entry`
    );

    return success(res, 200, {
      timestamp:      new Date().toISOString(),
      totalInside:    rows[0].total_inside,
      withVehicles:   rows[0].with_vehicles,
      byGate:         gateBreakdown,
    });

  } catch (err) {
    logger.error('getOccupancy error', { error: err.message });
    return fail(res, 500, 'SERVER_ERROR', 'Failed to get occupancy data.');
  }
}

// ---------------------------------------------------------------------------
// POST /api/v1/audit/export
// Returns visit log data as JSON (ready for client-side PDF/CSV generation)
// ---------------------------------------------------------------------------
async function exportLogs(req, res) {
  const ctx = extractRequestContext(req);

  const { from, to, format = 'json' } = req.body;

  if (!from || !to) {
    return fail(res, 400, 'MISSING_PARAMS', 'from and to date parameters are required.');
  }

  try {
    const [rows] = await query(
      `SELECT
         vl.log_id, vl.visitor_id, vl.entry_time, vl.exit_time,
         vl.gate_entry, vl.gate_exit, vl.host_dept, vl.vehicle_plate,
         vl.host_name_enc, vl.record_hash,
         u.username AS guard_username,
         v.visitor_name_enc, v.phone_num_enc
       FROM tblVisitLogs vl
       JOIN tblUsers u    ON vl.user_id   = u.user_id
       JOIN tblVisitors v ON vl.visitor_id = v.visitor_id
       WHERE vl.entry_time BETWEEN ? AND ?
       ORDER BY vl.entry_time ASC`,
      [from + ' 00:00:00', to + ' 23:59:59']
    );

    // Decrypt for export
    const exported = rows.map(row => ({
      logId:        row.log_id,
      visitorId:    row.visitor_id,
      visitorName:  decrypt(row.visitor_name_enc),
      phoneNum:     decrypt(row.phone_num_enc),
      guardUsername: row.guard_username,
      hostName:     decrypt(row.host_name_enc),
      hostDept:     row.host_dept,
      vehiclePlate: row.vehicle_plate,
      gateEntry:    row.gate_entry,
      gateExit:     row.gate_exit,
      entryTime:    row.entry_time,
      exitTime:     row.exit_time,
      recordHash:   row.record_hash,    // For legal integrity verification
    }));

    await writeAudit({
      userId:     req.user.userId,
      ...ctx,
      action:     ACTIONS.LOG_EXPORTED,
      status:     'SUCCESS',
      detail:     { from, to, format, count: exported.length },
    });

    logger.info('Logs exported', { admin: req.user.username, from, to, count: exported.length });

    return success(res, 200, {
      exportedAt: new Date().toISOString(),
      exportedBy: req.user.username,
      period:     { from, to },
      count:      exported.length,
      records:    exported,
    });

  } catch (err) {
    logger.error('exportLogs error', { error: err.message });
    await writeAudit({
      userId:   req.user.userId,
      ...ctx,
      action:   ACTIONS.LOG_EXPORTED,
      status:   'FAILURE',
      detail:   err.message,
    });
    return fail(res, 500, 'SERVER_ERROR', 'Export failed.');
  }
}

module.exports = { getAuditLogs, getAnomalies, getOccupancy, exportLogs };
