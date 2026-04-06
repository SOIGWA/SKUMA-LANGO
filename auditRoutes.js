/**
 * sukuma-lango/backend/src/routes/auditRoutes.js
 * All routes require authentication + admin-level permissions.
 */
'use strict';

const express  = require('express');
const {
  getAuditLogs, getAnomalies, getOccupancy, exportLogs,
} = require('../controllers/auditController');
const { authenticate, authorize } = require('../middleware/authMiddleware');

const router = express.Router();

router.use(authenticate);

// GET  /api/v1/audit/logs
router.get('/logs',        authorize('view_audit_trail'), getAuditLogs);

// GET  /api/v1/audit/anomalies
router.get('/anomalies',   authorize('view_audit_trail'), getAnomalies);

// GET  /api/v1/audit/occupancy   (guards + admins)
router.get('/occupancy',   authorize('view_occupancy'),  getOccupancy);

// POST /api/v1/audit/export
router.post('/export',     authorize('export_logs'),     exportLogs);

module.exports = router;
