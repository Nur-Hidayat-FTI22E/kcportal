-- # 2. pos.db — SQLite, di dalam App Pack pos-cafe (kontainer rootless)
-- #   PRAGMA berbeda dari state.db: synchronous=FULL (DD-12) — wajib, karena
-- #   NFR-POS-03 menuntut 0 transaksi hilang saat listrik mati mendadak, dan
-- #   `NORMAL` di WAL TIDAK menjamin itu (lihat ERR-06 di §3.2 desain).
-- #############################################################################

PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

-- --- dari Appendix H.1 (spec v0.4) ---

CREATE TABLE categories (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE products (
  id INTEGER PRIMARY KEY,
  category_id INTEGER REFERENCES categories(id),
  name TEXT NOT NULL,
  price INTEGER NOT NULL,              -- rupiah, int64 di Go; sudah termasuk pajak (asumsi §6.14.1 spec / Q-19)
  sku TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  track_stock INTEGER NOT NULL DEFAULT 0,
  stock_qty INTEGER
);

CREATE TABLE cashiers (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  pin_hash TEXT NOT NULL,              -- argon2id (FR-POS-012)
  role TEXT NOT NULL CHECK (role IN ('kasir','admin')),
  active INTEGER NOT NULL DEFAULT 1
);

-- shifts: kolom dasar + is_open (delta) sudah digabung
CREATE TABLE shifts (
  id INTEGER PRIMARY KEY,
  cashier_id INTEGER NOT NULL REFERENCES cashiers(id),
  opened_at INTEGER NOT NULL,
  closed_at INTEGER,
  opening_cash INTEGER NOT NULL,
  closing_cash INTEGER,                -- diisi kasir saat tutup
  expected_cash INTEGER,               -- dihitung sistem: opening + total tunai paid
  note TEXT,
  is_open INTEGER NOT NULL DEFAULT 1   -- (desain §5.3) dipakai partial unique index di bawah
);
-- Menegakkan "satu shift terbuka pada satu waktu" (Appendix H.2 spec) DI LEVEL DATABASE,
-- bukan hanya di kode Go — sudah diuji nyata: INSERT shift kedua saat is_open=1 ditolak
-- dengan "UNIQUE constraint failed: shifts.is_open".
CREATE UNIQUE INDEX one_open_shift ON shifts(is_open) WHERE is_open = 1;

-- orders: + order_no (delta, penomoran struk 'YYMMDD-0007')
CREATE TABLE orders (
  id INTEGER PRIMARY KEY,
  shift_id INTEGER NOT NULL REFERENCES shifts(id),   -- FR-POS-003: shift harus terbuka
  table_label TEXT,
  status TEXT NOT NULL CHECK (status IN ('open','paid','void','refunded')),
  subtotal INTEGER NOT NULL DEFAULT 0,
  discount INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  closed_at INTEGER,
  void_reason TEXT,
  void_by INTEGER REFERENCES cashiers(id),
  order_no TEXT
);

CREATE TABLE order_items (
  id INTEGER PRIMARY KEY,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  qty INTEGER NOT NULL CHECK (qty > 0),
  unit_price INTEGER NOT NULL,         -- disalin dari products.price saat ditambahkan (harga historis)
  note TEXT,
  discount INTEGER NOT NULL DEFAULT 0
);

-- payments: + tendered, change_given (delta, aturan kembalian §5.3)
CREATE TABLE payments (
  id INTEGER PRIMARY KEY,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  method TEXT NOT NULL CHECK (method IN ('cash','qris','other')),
  amount INTEGER NOT NULL,
  reference TEXT,                      -- mis. ID referensi EDC/QRIS; TIDAK PERNAH data kartu (SEC-029)
  paid_at INTEGER NOT NULL,
  tendered INTEGER,                    -- tunai diterima (hanya relevan utk method='cash')
  change_given INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit_log_pos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  cashier_id INTEGER REFERENCES cashiers(id),
  action TEXT NOT NULL,                -- void_order | refund_order | shift_open | shift_close | product_price_change | ...
  target TEXT,                         -- mis. "order:123"
  detail TEXT
);

-- --- tabel baru dari desain (§5.3), migrasi 0002 ---

CREATE TABLE counters (day TEXT PRIMARY KEY, n INTEGER NOT NULL);   -- nomor urut struk per hari (dalam tx buat order)

CREATE TABLE idempotency_keys (               -- POST /orders/{id}/pay wajib header Idempotency-Key
  key TEXT PRIMARY KEY,
  request_hash BLOB NOT NULL,
  response_status INTEGER NOT NULL,
  response_body BLOB NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE print_jobs (                     -- ditulis dalam TRANSAKSI YANG SAMA dengan payments (FR-POS-007)
  id INTEGER PRIMARY KEY,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  kind TEXT NOT NULL CHECK (kind IN ('receipt','reprint')),
  status TEXT NOT NULL CHECK (status IN ('queued','printed','failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  printed_at INTEGER
);
CREATE INDEX idx_print_status ON print_jobs(status);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_shift ON orders(shift_id);
