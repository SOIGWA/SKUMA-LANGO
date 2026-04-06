/**
 * sukuma-lango/backend/src/utils/crypto.js
 * AES-256-CBC encryption/decryption for PII fields stored in the database.
 * Every encryption call generates a fresh IV (randomised) and prepends it
 * to the cipher text so each stored value is unique even for identical inputs.
 *
 * Format stored in DB: `<hex_iv>:<base64_ciphertext>`
 */

'use strict';

const crypto = require('crypto');
const logger = require('./logger');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const ALGORITHM  = 'aes-256-cbc';
const IV_LENGTH  = 16;      // AES block size = 16 bytes
const KEY_LENGTH = 32;      // AES-256 = 32-byte key

// ---------------------------------------------------------------------------
// Derive the 32-byte key from the hex env variable
// ---------------------------------------------------------------------------
function getKey() {
  const hexKey = process.env.AES_ENCRYPTION_KEY;
  if (!hexKey || hexKey.length < 64) {
    throw new Error('AES_ENCRYPTION_KEY must be a 64-character hex string (32 bytes). Run: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }
  return Buffer.from(hexKey.slice(0, 64), 'hex');
}

// ---------------------------------------------------------------------------
// Encrypt a plain-text string → stored cipher string
// ---------------------------------------------------------------------------
/**
 * @param {string|null} plaintext
 * @returns {string|null}  '<hex_iv>:<base64_cipher>' or null
 */
function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) return null;
  if (typeof plaintext !== 'string') plaintext = String(plaintext);

  const key = getKey();
  const iv  = crypto.randomBytes(IV_LENGTH);         // Fresh IV per encryption
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  // Prepend IV so we can decrypt without storing IV separately
  return `${iv.toString('hex')}:${encrypted.toString('base64')}`;
}

// ---------------------------------------------------------------------------
// Decrypt a stored cipher string → plain text
// ---------------------------------------------------------------------------
/**
 * @param {string|null} ciphertext  '<hex_iv>:<base64_cipher>'
 * @returns {string|null}
 */
function decrypt(ciphertext) {
  if (!ciphertext) return null;

  try {
    const [ivHex, encBase64] = ciphertext.split(':');
    if (!ivHex || !encBase64) throw new Error('Invalid cipher format');

    const key       = getKey();
    const iv        = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encBase64, 'base64');

    const decipher  = crypto.createDecipheriv(ALGORITHM, key, iv);
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  } catch (err) {
    logger.error('Decryption failed', { error: err.message });
    return '[DECRYPTION ERROR]';
  }
}

// ---------------------------------------------------------------------------
// Hash a value (SHA-256) — used for log integrity hashes
// ---------------------------------------------------------------------------
/**
 * @param  {...string} parts  Strings to concatenate before hashing
 * @returns {string}  64-char hex digest
 */
function sha256(...parts) {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
}

module.exports = { encrypt, decrypt, sha256 };
