/**
 * sukuma-lango/backend/src/routes/visitorRoutes.js
 */
'use strict';

const express  = require('express');
const {
  registerVisitor, logExit, getActiveVisitors,
  getVisitLogs, getVisitorById,
  registerValidation, exitValidation,
} = require('../controllers/visitorController');
const { authenticate, authorize, requireOnDuty } = require('../middleware/authMiddleware');

const router = express.Router();

// All visitor routes require a valid JWT
router.use(authenticate);

// GET  /api/v1/visitors/active  — any authenticated user
router.get('/active',       authorize('view_occupancy'), getActiveVisitors);

// GET  /api/v1/visitors/logs   — admin only
router.get('/logs',         authorize('view_all_logs'), getVisitLogs);

// GET  /api/v1/visitors/:id    — admin or guard
router.get('/:id',          authorize('view_own_logs', 'view_all_logs'), getVisitorById);

// POST /api/v1/visitors/register — guard must be on duty
router.post('/register',    authorize('register_visitor'), requireOnDuty, registerValidation, registerVisitor);

// PATCH /api/v1/visitors/:logId/exit
router.patch('/:logId/exit', authorize('log_exit'), requireOnDuty, exitValidation, logExit);

module.exports = router;
