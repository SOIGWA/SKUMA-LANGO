/**
 * sukuma-lango/backend/src/utils/seeder.js
 * Run ONCE after schema.sql is loaded:
 *   node src/utils/seeder.js
 *
 * Creates the default superadmin user with a bcrypt-hashed password.
 * CHANGE THE PASSWORD immediately after first login.
 */

'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });

const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { query, testConnection, pool } = require('../config/database');

const DEFAULT_USERNAME = 'superadmin';
const DEFAULT_PASSWORD = 'Admin@SukumaLango2024';   // CHANGE AFTER FIRST LOGIN
const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;

async function seed() {
  console.log('\n🌱  Sukuma Lango — Database Seeder\n');

  const connected = await testConnection();
  if (!connected) {
    console.error('❌  Cannot connect to database. Check your .env file.');
    process.exit(1);
  }

  try {
    // Check if superadmin already exists
    const [existing] = await query(
      'SELECT user_id FROM tblUsers WHERE username = ?', [DEFAULT_USERNAME]
    );

    if (existing.length) {
      console.log(`ℹ️   User "${DEFAULT_USERNAME}" already exists. Skipping seed.`);
      process.exit(0);
    }

    // Hash the password
    console.log('🔐  Hashing default password (this may take a moment)…');
    const hash = await bcrypt.hash(DEFAULT_PASSWORD, SALT_ROUNDS);

    // Get the SUPER_ADMIN role ID
    const [roles] = await query("SELECT role_id FROM tblRoles WHERE role_name = 'SUPER_ADMIN'");
    if (!roles.length) {
      console.error('❌  Role SUPER_ADMIN not found. Run schema.sql first.');
      process.exit(1);
    }

    const roleId = roles[0].role_id;
    const userId = uuidv4();

    // Insert the superadmin user
    await query(
      `INSERT INTO tblUsers (user_id, role_id, username, password_hash, full_name, shift_status)
       VALUES (?, ?, ?, ?, 'System Administrator', 'on_duty')`,
      [userId, roleId, DEFAULT_USERNAME, hash]
    );

    console.log('\n✅  Default superadmin created successfully!');
    console.log('─────────────────────────────────────────');
    console.log(`   Username : ${DEFAULT_USERNAME}`);
    console.log(`   Password : ${DEFAULT_PASSWORD}`);
    console.log(`   User ID  : ${userId}`);
    console.log('─────────────────────────────────────────');
    console.log('⚠️   CHANGE THE PASSWORD IMMEDIATELY after first login!\n');

  } catch (err) {
    console.error('❌  Seeder error:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

seed();
