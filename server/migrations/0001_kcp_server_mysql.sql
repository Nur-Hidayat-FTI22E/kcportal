-- # 3. kcp_server — MySQL 8 / MariaDB, di server fleet (§6.4 desain)
-- #   Berbeda dialek dari dua bagian di atas (bukan SQLite) — dijalankan di
-- #   VPS/laptop pengembang, BUKAN di perangkat Pi. Divalidasi nyata di
-- #   MariaDB 10.11: FK dan ENUM terbukti menolak data yang tidak sah.
-- #   Catatan privasi (DD-11): server TIDAK PERNAH menyimpan MAC mentah,
-- #   hanya client_ref (HMAC). Kunci enkripsi pii_enc dari environment
-- #   (KCP_PII_KEY), bukan dari tabel manapun di sini.
-- #############################################################################

CREATE TABLE tenants (
  id CHAR(26) PRIMARY KEY, slug VARCHAR(64) NOT NULL UNIQUE, name VARCHAR(160) NOT NULL,
  retention_days SMALLINT NOT NULL DEFAULT 30, created_at DATETIME(3) NOT NULL);

CREATE TABLE locations (
  id CHAR(26) PRIMARY KEY, tenant_id CHAR(26) NOT NULL, name VARCHAR(160) NOT NULL,
  timezone VARCHAR(48) NOT NULL DEFAULT 'Asia/Makassar',
  profile_name VARCHAR(32) NOT NULL, portal_config JSON NOT NULL,
  created_at DATETIME(3) NOT NULL, FOREIGN KEY (tenant_id) REFERENCES tenants(id));

CREATE TABLE units (
  id VARCHAR(40) PRIMARY KEY,                       -- device_id (FR-COM-001)
  location_id CHAR(26) NOT NULL, serial VARCHAR(32) NOT NULL UNIQUE, batch VARCHAR(32),
  status ENUM('provisioned','active','suspended','retired') NOT NULL DEFAULT 'provisioned',
  token_hash BINARY(32) NULL, enroll_code_hash BINARY(32) NULL, enroll_expires_at DATETIME(3) NULL,
  fw_version VARCHAR(48), fw_slot CHAR(1), profile_ver VARCHAR(24), apps JSON,
  last_poll_at DATETIME(3), last_ip VARBINARY(16), health JSON,
  created_at DATETIME(3) NOT NULL, FOREIGN KEY (location_id) REFERENCES locations(id));

CREATE TABLE commands (
  id CHAR(26) PRIMARY KEY, unit_id VARCHAR(40) NOT NULL,
  type ENUM('apply_profile','install_app','update_firmware','backup_now','sync_now',
            'collect_support_bundle','deauth_guest','purge_guest_data') NOT NULL,
  params JSON NOT NULL,
  state ENUM('queued','delivered','succeeded','failed','expired','cancelled') NOT NULL DEFAULT 'queued',
  not_before DATETIME(3) NULL, expires_at DATETIME(3) NOT NULL,
  delivered_at DATETIME(3) NULL, acked_at DATETIME(3) NULL, result JSON NULL,
  created_by VARCHAR(64) NOT NULL, created_at DATETIME(3) NOT NULL,
  INDEX idx_cmd_unit_state (unit_id, state), FOREIGN KEY (unit_id) REFERENCES units(id));

CREATE TABLE artifacts (
  id CHAR(26) PRIMARY KEY, kind ENUM('firmware','app','profile') NOT NULL,
  name VARCHAR(64) NOT NULL, version VARCHAR(48) NOT NULL, channel VARCHAR(16),
  sha256 BINARY(32) NOT NULL, size BIGINT NOT NULL, path VARCHAR(255) NOT NULL, sig_path VARCHAR(255) NOT NULL,
  min_compatible_version VARCHAR(48), created_at DATETIME(3) NOT NULL,
  UNIQUE KEY uq_artifact (kind, name, version));

CREATE TABLE rollouts (
  id CHAR(26) PRIMARY KEY, artifact_id CHAR(26) NOT NULL, channel VARCHAR(16) NOT NULL,
  percent TINYINT UNSIGNED NOT NULL, cohort_salt VARCHAR(48) NOT NULL,
  state ENUM('active','paused','halted') NOT NULL DEFAULT 'active', created_at DATETIME(3) NOT NULL);

CREATE TABLE guest_leads (                            -- DD-11: pengganti MAC mentah demi privasi
  id BIGINT AUTO_INCREMENT PRIMARY KEY, location_id CHAR(26) NOT NULL,
  client_ref BINARY(32) NOT NULL, started_at DATETIME(3) NOT NULL, expires_at DATETIME(3) NOT NULL,
  consent_marketing TINYINT(1) NOT NULL, terms_version VARCHAR(16),
  pii_enc VARBINARY(1024) NULL,                       -- AES-256-GCM: {name, phone, email}; NULL bila tanpa consent
  received_at DATETIME(3) NOT NULL,
  UNIQUE KEY uq_lead (location_id, client_ref, started_at),
  INDEX idx_lead_loc_time (location_id, started_at));

CREATE TABLE backups (
  id CHAR(26) PRIMARY KEY, unit_id VARCHAR(40) NOT NULL, kind VARCHAR(16) NOT NULL,
  size BIGINT NOT NULL, sha256 BINARY(32) NOT NULL, path VARCHAR(255) NOT NULL, created_at DATETIME(3) NOT NULL);

CREATE TABLE unit_events (id BIGINT AUTO_INCREMENT PRIMARY KEY, unit_id VARCHAR(40) NOT NULL,
  ts DATETIME(3) NOT NULL, type VARCHAR(48) NOT NULL, payload JSON, INDEX (unit_id, ts));

CREATE TABLE audit_server (id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DATETIME(3) NOT NULL,
  actor VARCHAR(64) NOT NULL, action VARCHAR(64) NOT NULL, target VARCHAR(96), detail JSON);

