-- state.db — Appendix D (kotacloud-wifi.md v0.4) + delta desain (§8, migrasi
-- 0002), sudah digabung oleh sumber aslinya (kotacloud-wifi-skema.sql).
-- Sudah diuji nyata dengan sqlite3: constraint CHECK/UNIQUE/FK bekerja
-- (mis. devices.state menolak nilai di luar enum-nya).
--
-- PRAGMA journal_mode/synchronous/foreign_keys TIDAK disertakan di sini —
-- store.Open() sudah menyetelnya lewat DSN (_pragma=...) sebelum migrasi
-- ini jalan; PRAGMA di tengah skrip migrasi berisiko tidak konsisten
-- antar-driver.

CREATE TABLE zones (
  id INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 16),
  name TEXT NOT NULL UNIQUE,
  vlan INTEGER UNIQUE,                 -- NULL = zona logis (tanpa VLAN)
  subnet TEXT NOT NULL,
  internet INTEGER NOT NULL DEFAULT 1,
  vpn_policy TEXT NOT NULL DEFAULT 'off' CHECK (vpn_policy IN ('off','preferred','required')),
  isolate_clients INTEGER NOT NULL DEFAULT 0,
  lan_allow TEXT NOT NULL DEFAULT '[]',
  bw_limit_kbps INTEGER
);

CREATE TABLE ssids (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  zone_id INTEGER NOT NULL REFERENCES zones(id),
  security TEXT NOT NULL CHECK (security IN ('wpa2','wpa2_wpa3')),
  bouncer_mode TEXT NOT NULL DEFAULT 'enforce' CHECK (bouncer_mode IN ('enforce','bypass','portal')),
  band TEXT NOT NULL DEFAULT 'dual',
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE devices (
  mac TEXT PRIMARY KEY,
  name TEXT,
  state TEXT NOT NULL CHECK (state IN ('waiting','approved','blocked','expired','dormant')),
  zone_id INTEGER REFERENCES zones(id),
  vendor TEXT,
  hostname TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  approved_by TEXT,
  approved_at INTEGER,
  expires_at INTEGER
);
CREATE INDEX idx_devices_state ON devices(state);

CREATE TABLE vpn_tunnels (
  id TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK (mode IN ('client','server')),
  routing_mode TEXT NOT NULL DEFAULT 'split' CHECK (routing_mode IN ('split','full')),
  corp_domains TEXT NOT NULL DEFAULT '[]',   -- split DNS
  psk_ref TEXT,                              -- referensi ke secrets, bukan nilai PSK
  public_key TEXT NOT NULL,                  -- kunci privat TIDAK di DB (SEC-010)
  endpoint TEXT,
  allowed_ips TEXT NOT NULL,
  dns TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  diff TEXT,
  prev_hash BLOB NOT NULL,
  hash BLOB NOT NULL                 -- SHA-256(prev_hash || ts || actor || action || target || diff)
);

CREATE TABLE profile_state (name TEXT PRIMARY KEY, version TEXT NOT NULL, applied_at INTEGER NOT NULL, params TEXT NOT NULL);
CREATE TABLE apps (id TEXT PRIMARY KEY, version TEXT NOT NULL, prev_version TEXT, state TEXT NOT NULL, installed_at INTEGER NOT NULL);

-- guest_sessions: kolom dasar (spec v0.4) + kolom delta (desain §8) sudah digabung
CREATE TABLE guest_sessions (
  mac TEXT NOT NULL,
  tenant_id TEXT,
  started_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consent_marketing INTEGER NOT NULL DEFAULT 0,
  synced INTEGER NOT NULL DEFAULT 0,
  payload TEXT,                        -- data pemasaran minimal; retensi & hapus (FR-CPT-006)
  -- kolom tambahan (desain §8):
  session_id TEXT,                     -- ID sesi portal-edge (IF-01)
  client_ref BLOB,                     -- HMAC-SHA256(kunci_tenant, MAC) — DD-11, dikirim ke server, BUKAN mac mentah
  voucher_code TEXT,
  terms_version TEXT,
  lang TEXT,
  closed_at INTEGER,
  PRIMARY KEY (mac, started_at)
);
CREATE INDEX idx_guest_unsynced ON guest_sessions(synced) WHERE synced = 0;

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- --- tabel tambahan dari desain (§8), migrasi 0002 asli ---

CREATE TABLE ip_leases (                       -- DD-03: IPAM perangkat approved (+ cache lease)
  mac TEXT PRIMARY KEY,
  zone_id INTEGER REFERENCES zones(id),
  ip4 TEXT UNIQUE,
  ip6 TEXT,
  reserved INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE vouchers (
  code TEXT PRIMARY KEY,
  duration_s INTEGER NOT NULL,
  max_uses INTEGER NOT NULL DEFAULT 1,
  used INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE command_log (                      -- idempotensi perintah fleet (IF-04)
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  finished_at INTEGER,
  status TEXT,
  result TEXT
);

-- Catatan: schema_migrations TIDAK didefinisikan di sini — store.go
-- membuatnya sendiri (CREATE TABLE IF NOT EXISTS) sebelum menjalankan
-- migrasi apa pun, supaya bisa mencatat riwayat migrasi sejak awal.
