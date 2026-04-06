-- =============================================================================
-- SUKUMA LANGO: Integrated Digital Access Control & Visitor Forensic Logging
-- Database Schema — MySQL 8.0+ | InnoDB | ACID Compliant
-- Author: Andy Abuga Ombasa | KCA University | Dept: Info Security & Forensics
-- =============================================================================

-- Create and select the database
CREATE DATABASE IF NOT EXISTS sukuma_lango
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE sukuma_lango;

-- Disable FK checks during setup
SET FOREIGN_KEY_CHECKS = 0;

-- =============================================================================
-- TABLE 1: tblRoles
-- Defines system roles and their permission sets (RBAC foundation)
-- =============================================================================
CREATE TABLE IF NOT EXISTS tblRoles (
  role_id       TINYINT UNSIGNED    NOT NULL AUTO_INCREMENT,
  role_name     VARCHAR(50)         NOT NULL UNIQUE,
  -- JSON array of permission strings e.g. ["log_visitor","view_own_logs"]
  permissions   JSON                NOT NULL,
  is_active     TINYINT(1)          NOT NULL DEFAULT 1,
  created_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (role_id),
  INDEX idx_role_active (is_active)
) ENGINE=InnoDB
  COMMENT='RBAC role definitions. Permissions stored as JSON array.';

-- =============================================================================
-- TABLE 2: tblUsers
-- System operators: Guards and Admins. UUID primary key for forensic traceability.
-- Sensitive fields (email) encrypted at application layer (AES-256).
-- =============================================================================
CREATE TABLE IF NOT EXISTS tblUsers (
  user_id       CHAR(36)            NOT NULL,       -- UUID v4
  role_id       TINYINT UNSIGNED    NOT NULL,
  username      VARCHAR(100)        NOT NULL UNIQUE,
  password_hash VARCHAR(255)        NOT NULL,       -- bcrypt hash (cost=12)
  full_name     VARCHAR(200)        NOT NULL,
  -- AES-256 encrypted at rest (stored as Base64 cipher text)
  email_enc     TEXT                    NULL,
  phone_enc     TEXT                    NULL,
  shift_status  ENUM('on_duty','off_duty','suspended') NOT NULL DEFAULT 'off_duty',
  last_login    DATETIME                NULL,
  failed_attempts TINYINT UNSIGNED  NOT NULL DEFAULT 0,
  locked_until  DATETIME                NULL,
  created_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  FOREIGN KEY fk_user_role (role_id)
    REFERENCES tblRoles(role_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  INDEX idx_user_shift (shift_status),
  INDEX idx_user_role  (role_id)
) ENGINE=InnoDB
  COMMENT='System users (Guards/Admins). UUIDs ensure forensic traceability.';

-- =============================================================================
-- TABLE 3: tblVisitors
-- Visitor identity registry. National ID is the natural primary key.
-- PII (name, phone, email) encrypted with AES-256 at application layer.
-- =============================================================================
CREATE TABLE IF NOT EXISTS tblVisitors (
  visitor_id    VARCHAR(20)         NOT NULL,       -- National ID / Passport No.
  -- AES-256 encrypted PII fields
  visitor_name_enc  TEXT            NOT NULL,       -- Encrypted full name
  phone_num_enc     TEXT            NOT NULL,       -- Encrypted phone number
  email_enc         TEXT                NULL,       -- Encrypted email (optional)
  -- Non-sensitive searchable fields
  id_type       ENUM('national_id','passport','alien_card') NOT NULL DEFAULT 'national_id',
  photo_path    VARCHAR(500)            NULL,       -- Local path to photo capture
  is_blacklisted TINYINT(1)         NOT NULL DEFAULT 0,
  blacklist_reason VARCHAR(500)         NULL,
  first_seen    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen     DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (visitor_id),
  INDEX idx_visitor_blacklist (is_blacklisted)
) ENGINE=InnoDB
  COMMENT='Visitor PII registry. All sensitive fields AES-256 encrypted at rest.';

-- =============================================================================
-- TABLE 4: tblVisitLogs
-- Core transaction table. Immutable entry/exit records with UUID log IDs.
-- exit_time NULL = visitor currently inside premises.
-- =============================================================================
CREATE TABLE IF NOT EXISTS tblVisitLogs (
  log_id        CHAR(36)            NOT NULL,       -- UUID v4 (immutable record ID)
  visitor_id    VARCHAR(20)         NOT NULL,
  user_id       CHAR(36)            NOT NULL,       -- Guard who logged the entry
  -- Host info encrypted (PII protection for staff/residents)
  host_name_enc TEXT                NOT NULL,
  host_dept     VARCHAR(200)            NULL,
  purpose_enc   TEXT                    NULL,       -- Encrypted visit purpose
  vehicle_plate VARCHAR(20)             NULL,       -- Optionally captured
  -- QR code payload (signed JWT-like token for the local pass)
  local_pass_token TEXT                 NULL,
  entry_time    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
  exit_time     DATETIME                NULL,       -- NULL = still inside
  exit_user_id  CHAR(36)                NULL,       -- Guard who logged exit
  gate_entry    VARCHAR(50)         NOT NULL DEFAULT 'Main Gate',
  gate_exit     VARCHAR(50)             NULL,
  -- Integrity hash: SHA-256 of (log_id+visitor_id+entry_time+user_id)
  record_hash   CHAR(64)            NOT NULL,
  created_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (log_id),
  FOREIGN KEY fk_log_visitor (visitor_id)
    REFERENCES tblVisitors(visitor_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY fk_log_user (user_id)
    REFERENCES tblUsers(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY fk_log_exit_user (exit_user_id)
    REFERENCES tblUsers(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  INDEX idx_log_entry_time  (entry_time),
  INDEX idx_log_exit_time   (exit_time),
  INDEX idx_log_visitor     (visitor_id),
  INDEX idx_log_user        (user_id),
  INDEX idx_log_active      (exit_time, entry_time)  -- Active visitors query
) ENGINE=InnoDB
  COMMENT='Core visit transaction log. Immutable after creation. record_hash ensures integrity.';

-- =============================================================================
-- TABLE 5: tblForensicAudits
-- Append-only audit ledger. NEVER update or delete rows here.
-- Captures ALL CRUD operations on the system for legal chain-of-custody.
-- =============================================================================
CREATE TABLE IF NOT EXISTS tblForensicAudits (
  audit_id      BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
  user_id       CHAR(36)                NULL,       -- NULL for system/anonymous actions
  action_taken  VARCHAR(100)        NOT NULL,       -- e.g. LOGIN_SUCCESS, VISITOR_REGISTERED
  target_table  VARCHAR(50)             NULL,       -- Table affected by the action
  target_id     VARCHAR(100)            NULL,       -- PK of affected record
  -- Request context
  ip_address    VARCHAR(45)         NOT NULL,       -- IPv4 or IPv6
  user_agent    VARCHAR(500)            NULL,
  request_path  VARCHAR(255)            NULL,
  -- Outcome details
  status        ENUM('SUCCESS','FAILURE','WARNING') NOT NULL DEFAULT 'SUCCESS',
  detail_enc    TEXT                    NULL,       -- Encrypted extra detail (PII-safe)
  -- Immutable timestamp
  timestamp     DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (audit_id),
  FOREIGN KEY fk_audit_user (user_id)
    REFERENCES tblUsers(user_id)
    ON UPDATE CASCADE ON DELETE SET NULL,
  INDEX idx_audit_timestamp (timestamp),
  INDEX idx_audit_user      (user_id),
  INDEX idx_audit_action    (action_taken),
  INDEX idx_audit_status    (status)
) ENGINE=InnoDB
  COMMENT='Append-only forensic ledger. No UPDATEs or DELETEs permitted on this table.';

-- Re-enable FK checks
SET FOREIGN_KEY_CHECKS = 1;

-- =============================================================================
-- SEED DATA: Default Roles
-- =============================================================================
INSERT INTO tblRoles (role_name, permissions) VALUES
  ('SUPER_ADMIN', JSON_ARRAY(
    'manage_users', 'manage_roles', 'view_all_logs', 'export_logs',
    'view_audit_trail', 'register_visitor', 'log_exit',
    'blacklist_visitor', 'view_occupancy', 'manage_gates'
  )),
  ('ADMIN', JSON_ARRAY(
    'view_all_logs', 'export_logs', 'view_audit_trail',
    'register_visitor', 'log_exit', 'blacklist_visitor',
    'view_occupancy', 'manage_gates'
  )),
  ('GUARD', JSON_ARRAY(
    'register_visitor', 'log_exit', 'view_own_logs', 'view_occupancy'
  ));

-- =============================================================================
-- SEED DATA: Default Admin User
-- Password: Admin@SukumaLango2024 (bcrypt hash generated at app startup)
-- IMPORTANT: Change this password immediately after first login!
-- =============================================================================
INSERT INTO tblUsers (
  user_id, role_id, username, password_hash, full_name, shift_status
) VALUES (
  '00000000-0000-0000-0000-000000000001',
  1,
  'superadmin',
  -- This is a placeholder. The actual bcrypt hash is injected by the setup script.
  '$BCRYPT_PLACEHOLDER$',
  'System Administrator',
  'on_duty'
);

-- =============================================================================
-- VIEWS for common queries
-- =============================================================================

-- Active visitors (currently inside premises)
CREATE OR REPLACE VIEW vw_active_visitors AS
  SELECT
    vl.log_id,
    vl.visitor_id,
    vl.entry_time,
    vl.gate_entry,
    vl.host_dept,
    vl.vehicle_plate,
    u.username AS guard_username
  FROM tblVisitLogs vl
  JOIN tblUsers u ON vl.user_id = u.user_id
  WHERE vl.exit_time IS NULL;

-- Daily summary count
CREATE OR REPLACE VIEW vw_daily_summary AS
  SELECT
    DATE(entry_time)          AS log_date,
    COUNT(*)                  AS total_entries,
    SUM(exit_time IS NULL)    AS still_inside,
    SUM(exit_time IS NOT NULL) AS exited
  FROM tblVisitLogs
  GROUP BY DATE(entry_time)
  ORDER BY log_date DESC;

-- =============================================================================
-- STORED PROCEDURE: Safe audit log insertion
-- Use this procedure to write to tblForensicAudits from any context.
-- =============================================================================
DELIMITER $$

CREATE PROCEDURE IF NOT EXISTS sp_write_audit(
  IN p_user_id       CHAR(36),
  IN p_action        VARCHAR(100),
  IN p_target_table  VARCHAR(50),
  IN p_target_id     VARCHAR(100),
  IN p_ip_address    VARCHAR(45),
  IN p_user_agent    VARCHAR(500),
  IN p_request_path  VARCHAR(255),
  IN p_status        ENUM('SUCCESS','FAILURE','WARNING'),
  IN p_detail_enc    TEXT
)
BEGIN
  INSERT INTO tblForensicAudits (
    user_id, action_taken, target_table, target_id,
    ip_address, user_agent, request_path, status, detail_enc
  ) VALUES (
    p_user_id, p_action, p_target_table, p_target_id,
    p_ip_address, p_user_agent, p_request_path, p_status, p_detail_enc
  );
END$$

DELIMITER ;

SELECT 'Sukuma Lango schema deployed successfully.' AS status;
