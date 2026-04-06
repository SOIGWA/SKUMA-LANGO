/**
 * sukuma-lango/backend/src/config/database.js
 * MySQL connection pool using mysql2 with promise support.
 * InnoDB + full ACID compliance enforced at connection level.
 */

'use strict';

const mysql = require('mysql2/promise');
const logger = require('../utils/logger');

// ---------------------------------------------------------------------------
// Connection pool configuration
// ---------------------------------------------------------------------------
const poolConfig = {
  host:               process.env.DB_HOST     || '127.0.0.1',
  port:               parseInt(process.env.DB_PORT, 10) || 3306,
  database:           process.env.DB_NAME     || 'sukuma_lango',
  user:               process.env.DB_USER     || 'sukuma_app',
  password:           process.env.DB_PASSWORD,
  charset:            'utf8mb4',
  timezone:           '+03:00',           // East Africa Time (EAT)
  connectionLimit:    20,
  waitForConnections: true,
  queueLimit:         0,
  enableKeepAlive:    true,
  keepAliveInitialDelay: 10000,
  // Enforce InnoDB and secure session settings on every connection
  multipleStatements: false,              // Prevent multi-statement injection
  ssl:                false,              // Closed LAN — no TLS needed
};

// ---------------------------------------------------------------------------
// Create the pool
// ---------------------------------------------------------------------------
const pool = mysql.createPool(poolConfig);

/**
 * Execute a SQL query on the pool.
 * @param {string} sql  - Parameterised SQL string
 * @param {Array}  params - Bound parameters (always use parameterisation)
 * @returns {Promise<[rows, fields]>}
 */
async function query(sql, params = []) {
  try {
    const [rows, fields] = await pool.execute(sql, params);
    return [rows, fields];
  } catch (err) {
    logger.error('DB query error', {
      sql:    sql.substring(0, 200),  // Truncate for log safety
      error:  err.message,
      code:   err.code,
    });
    throw err;
  }
}

/**
 * Get a dedicated connection for transactions.
 * Remember to call conn.release() in a finally block.
 */
async function getConnection() {
  const conn = await pool.getConnection();
  // Ensure InnoDB session settings
  await conn.execute("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO'");
  return conn;
}

/**
 * Test the database connection at startup.
 */
async function testConnection() {
  try {
    const [rows] = await query('SELECT NOW() AS server_time, VERSION() AS version');
    logger.info('Database connected', {
      server_time: rows[0].server_time,
      version:     rows[0].version,
    });
    return true;
  } catch (err) {
    logger.error('Database connection FAILED', { error: err.message });
    return false;
  }
}

module.exports = { query, getConnection, testConnection, pool };
