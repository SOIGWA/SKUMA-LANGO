/**
 * sukuma-lango/backend/src/routes/authRoutes.js
 * Auth endpoints — no authentication required (public)
 * except /logout and /me which require a valid JWT.
 */

'use strict';

const express        = require('express');
const rateLimit      = require('express-rate-limit');
const {
  login, logout, refreshToken, getMe, loginValidation,
} = require('../controllers/authController');
const { authenticate } = require('../middleware/authMiddleware');

const router = express.Router();

// Strict rate limit on login to prevent brute-force
const loginLimiter = rateLimit({
  windowMs:          parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
  max:               parseInt(process.env.LOGIN_RATE_LIMIT_MAX, 10) || 10,
  standardHeaders:   true,
  legacyHeaders:     false,
  message:           {
    success: false,
    error:   { code: 'RATE_LIMITED', message: 'Too many login attempts. Please try again later.' },
  },
  skip:              (req) => process.env.NODE_ENV === 'test',
});

// POST /api/v1/auth/login
router.post('/login',   loginLimiter, loginValidation, login);

// POST /api/v1/auth/logout  (requires valid token)
router.post('/logout',  authenticate, logout);

// POST /api/v1/auth/refresh
router.post('/refresh', refreshToken);

// GET  /api/v1/auth/me
router.get('/me',       authenticate, getMe);

module.exports = router;
