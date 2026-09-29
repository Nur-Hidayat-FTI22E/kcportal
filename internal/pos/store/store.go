// Package store owns pos.db (§6.5): a SQLite database SEPARATE from
// kcportald's state.db, living on the pos-cafe container's /data
// volume. The DD-12/ERR-06 discipline is enforced here, not suggested:
// synchronous=FULL (0 lost transactions on power cut, NFR-POS-03) and
// exactly ONE write connection (WAL + concurrent writers = busy
// storms; the PoS workload is one cashier at a time).
package store

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	_ "modernc.org/sqlite"
)

//go:embed schema/*.sql
var schemaFS embed.FS

// ErrConflict marks user-facing conflicts (shift already open, order
// not open, wrong PIN) as distinct from internal failures.
var ErrConflict = errors.New("pos: conflict")

// DB wraps the handle plus the derived knobs the queries need.
type DB struct {
	*sql.DB
	now func() time.Time
}

// Open creates/opens path and applies migrations. The returned handle
// has its write path serialized: one connection.
func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("pos store: open: %w", err)
	}
	// DD-12: single writer. Reads share it too for simplicity — the
	// workload is one cashier; correctness beats a second pool.
	db.SetMaxOpenConns(1)
	// Versioned migrations: schema_migrations records which files ran,
	// so 0001's plain CREATE TABLEs only execute on a fresh database
	// (caught live: second boot died on "table categories already
	// exists"). Future migrations append as 0002_*.sql.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	entries, err := schemaFS.ReadDir("schema")
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var done int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, e.Name()).Scan(&done); err != nil {
			db.Close()
			return nil, err
		}
		if done > 0 {
			continue
		}
		// Adopt pre-versioned databases: if the baseline tables already
		// exist (created by the pre-M4.3-GUI binary), record 0001 as
		// applied instead of failing on them.
		if e.Name() == "0001_base.sql" {
			var baseline int
			if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('categories','products','cashiers','shifts','orders','payments')`).Scan(&baseline); err != nil {
				db.Close()
				return nil, err
			}
			if baseline == 6 {
				if _, err := db.Exec(`INSERT INTO schema_migrations (name, applied_at) VALUES ('0001_base.sql', ?)`, time.Now().Unix()); err != nil {
					db.Close()
					return nil, err
				}
				continue
			}
		}
		raw, err := schemaFS.ReadFile("schema/" + e.Name())
		if err != nil {
			db.Close()
			return nil, err
		}
		// PRAGMA lines (synchronous/journal in the original dump) cannot
		// run inside a transaction — the DSN owns them. Strip them so the
		// migration executes cleanly as one tx.
		var stmts []string
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "PRAGMA ") || strings.HasPrefix(trimmed, "pragma ") {
				continue
			}
			stmts = append(stmts, line)
		}
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			return nil, err
		}
		if _, err := tx.Exec(strings.Join(stmts, "\n")); err != nil {
			tx.Rollback()
			db.Close()
			return nil, fmt.Errorf("pos store: migrate %s: %w", e.Name(), err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)`, e.Name(), time.Now().Unix()); err != nil {
			tx.Rollback()
			db.Close()
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &DB{DB: db, now: time.Now}, nil
}

// SetNow overrides the clock (tests).
func (d *DB) SetNow(f func() time.Time) { d.now = f }

// --- cashiers (PIN argon2id, FR-POS-012) ---

// CreateCashier seeds a cashier with a hashed PIN. Used by onboarding/
// ops; the MVP has no self-service signup.
func (d *DB) CreateCashier(name, pin, role string) (int64, error) {
	if role != "kasir" && role != "admin" {
		return 0, fmt.Errorf("pos store: role %q must be kasir|admin", role)
	}
	hash, err := hashPIN(pin)
	if err != nil {
		return 0, err
	}
	res, err := d.Exec(`INSERT INTO cashiers (name, pin_hash, role) VALUES (?, ?, ?)`, name, hash, role)
	if err != nil {
		return 0, fmt.Errorf("pos store: create cashier: %w", err)
	}
	return res.LastInsertId()
}

// Login verifies a PIN and returns the cashier id + role.
func (d *DB) Login(name, pin string) (int64, string, error) {
	var id int64
	var hash, role string
	err := d.QueryRow(`SELECT id, pin_hash, role FROM cashiers WHERE name = ? AND active = 1`, name).
		Scan(&id, &hash, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", ErrConflict
	}
	if err != nil {
		return 0, "", err
	}
	if !verifyPIN(hash, pin) {
		return 0, "", ErrConflict
	}
	return id, role, nil
}

func hashPIN(pin string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(pin), salt, 1, 64*1024, 2, 32)
	return fmt.Sprintf("argon2id$1$65536$2$%x$%x", salt, sum), nil
}

func verifyPIN(stored, pin string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return false
	}
	salt := hexDecode(parts[4])
	want := hexDecode(parts[5])
	if len(salt) == 0 || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pin), salt, 1, 64*1024, 2, 32)
	return constantTimeEq(got, want)
}

func hexDecode(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return nil
		}
		out[i/2] = hi<<4 | lo
	}
	return out
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func constantTimeEq(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// --- shifts (one open at a time — DB partial unique index enforces) ---

// OpenShift opens the working shift with the counted opening cash.
func (d *DB) OpenShift(cashierID int64, openingCash int64) (int64, error) {
	res, err := d.Exec(`INSERT INTO shifts (cashier_id, opened_at, opening_cash, is_open) VALUES (?, ?, ?, 1)`,
		cashierID, d.now().Unix(), openingCash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, fmt.Errorf("%w: a shift is already open", ErrConflict)
		}
		return 0, err
	}
	return res.LastInsertId()
}

// CloseShift closes the open shift: stores the counted closing cash and
// the system-expected total, and returns the difference (kurang/lebih).
func (d *DB) CloseShift(cashierID int64, closingCash int64, note string) (shiftID, expected, diff int64, err error) {
	tx, err := d.Begin()
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.QueryRow(`SELECT id, opening_cash + COALESCE((
		SELECT SUM(p.amount) FROM payments p
		JOIN orders o ON o.id = p.order_id
		WHERE o.shift_id = shifts.id AND p.method = 'cash'
	), 0)
		FROM shifts WHERE is_open = 1`).Scan(&shiftID, &expected)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, 0, fmt.Errorf("%w: no open shift", ErrConflict)
	}
	if err != nil {
		return 0, 0, 0, err
	}
	diff = closingCash - expected
	now := d.now().Unix()
	if _, err = tx.Exec(`UPDATE shifts SET closed_at = ?, closing_cash = ?, expected_cash = ?, note = ?, is_open = 0 WHERE id = ?`,
		now, closingCash, expected, note, shiftID); err != nil {
		return 0, 0, 0, err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log_pos (ts, cashier_id, action, target, detail) VALUES (?, ?, 'shift_close', ?, ?)`,
		now, cashierID, fmt.Sprintf("shift:%d", shiftID),
		fmt.Sprintf("counted=%d expected=%d diff=%d", closingCash, expected, diff)); err != nil {
		return 0, 0, 0, err
	}
	return shiftID, expected, diff, tx.Commit()
}

// OpenShiftID reports the currently open shift (0 = none).
func (d *DB) OpenShiftID() (int64, error) {
	var id int64
	err := d.QueryRow(`SELECT id FROM shifts WHERE is_open = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// --- orders & payments (numbering + print job in the SAME tx) ---

// CreateOrder opens an order on the open shift.
func (d *DB) CreateOrder(tableLabel string) (int64, string, error) {
	shiftID, err := d.OpenShiftID()
	if err != nil {
		return 0, "", err
	}
	if shiftID == 0 {
		return 0, "", fmt.Errorf("%w: open a shift first", ErrConflict)
	}
	tx, err := d.Begin()
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = tx.Rollback() }()
	now := d.now()
	day := now.Format("060102")
	var n int64
	if err := tx.QueryRow(`SELECT n FROM counters WHERE day = ?`, day).Scan(&n); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			n = 0
		} else {
			return 0, "", err
		}
	}
	n++
	if _, err := tx.Exec(`INSERT INTO counters (day, n) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET n = excluded.n`, day, n); err != nil {
		return 0, "", err
	}
	orderNo := fmt.Sprintf("%s-%04d", day, n)
	res, err := tx.Exec(`INSERT INTO orders (shift_id, table_label, status, created_at, order_no) VALUES (?, ?, 'open', ?, ?)`,
		shiftID, tableLabel, now.Unix(), orderNo)
	if err != nil {
		return 0, "", err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, "", err
	}
	return id, orderNo, tx.Commit()
}

// AddItem appends a product line at the product's current price
// (historical price discipline) and refreshes the order totals.
func (d *DB) AddItem(orderID, productID, qty int64, note string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var price int64
	var active, trackStock bool
	err = tx.QueryRow(`SELECT price, is_active, COALESCE(track_stock,0)=1 FROM products WHERE id = ?`, productID).
		Scan(&price, &active, &trackStock)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: unknown product", ErrConflict)
	}
	if err != nil {
		return err
	}
	if !active {
		return fmt.Errorf("%w: product inactive", ErrConflict)
	}
	if _, err := tx.Exec(`INSERT INTO order_items (order_id, product_id, qty, unit_price, note) VALUES (?, ?, ?, ?, ?)`,
		orderID, productID, qty, price, note); err != nil {
		return err
	}
	if trackStock {
		if _, err := tx.Exec(`UPDATE products SET stock_qty = stock_qty - ? WHERE id = ? AND (stock_qty IS NULL OR stock_qty >= ?)`,
			qty, productID, qty); err != nil {
			return err
		}
	}
	if err := refreshTotals(tx, orderID); err != nil {
		return err
	}
	return tx.Commit()
}

func refreshTotals(tx *sql.Tx, orderID int64) error {
	_, err := tx.Exec(`UPDATE orders SET
		subtotal = (SELECT COALESCE(SUM(qty * unit_price),0) FROM order_items WHERE order_id = ?),
		total = (SELECT COALESCE(SUM(qty * unit_price),0) FROM order_items WHERE order_id = ?)
		WHERE id = ?`, orderID, orderID, orderID)
	return err
}

// PayInput is one payment call. IdempotencyKey makes /pay retry-safe
// (crash between pay and receipt print must not double-charge).
type PayInput struct {
	OrderID        int64
	CashierID      int64
	Method         string // cash | qris | other
	Amount         int64
	Reference      string // QRIS/EDC reference — never card data (SEC-029)
	Tendered       int64  // cash only
	IdempotencyKey string
}

// PayResult carries what the UI needs after a (possibly replayed) pay.
type PayResult struct {
	PaymentID   int64
	ChangeGiven int64
	Replayed    bool
}

// Pay settles the order in ONE transaction (FR-POS-007): payment row +
// order → paid + print_jobs row committed together. A replayed
// Idempotency-Key returns the stored response untouched.
func (d *DB) Pay(in PayInput) (PayResult, error) {
	switch in.Method {
	case "cash", "qris", "other":
	default:
		return PayResult{}, fmt.Errorf("%w: method must be cash|qris|other", ErrConflict)
	}
	if in.IdempotencyKey == "" {
		return PayResult{}, fmt.Errorf("%w: Idempotency-Key required", ErrConflict)
	}
	tx, err := d.Begin()
	if err != nil {
		return PayResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// Idempotent replay: same key + same request → stored response.
	var status int64
	var body []byte
	err = tx.QueryRow(`SELECT response_status, response_body FROM idempotency_keys WHERE key = ?`, in.IdempotencyKey).
		Scan(&status, &body)
	if err == nil {
		var stored PayResult
		if err := unmarshalJSON(body, &stored); err != nil {
			return PayResult{}, err
		}
		stored.Replayed = true
		return stored, tx.Commit() // commit is a no-op; explicit for clarity
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PayResult{}, err
	}

	var openStatus string
	err = tx.QueryRow(`SELECT status FROM orders WHERE id = ?`, in.OrderID).Scan(&openStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return PayResult{}, fmt.Errorf("%w: unknown order", ErrConflict)
	}
	if err != nil {
		return PayResult{}, err
	}
	if openStatus != "open" {
		return PayResult{}, fmt.Errorf("%w: order is %s", ErrConflict, openStatus)
	}
	var total int64
	if err := tx.QueryRow(`SELECT total FROM orders WHERE id = ?`, in.OrderID).Scan(&total); err != nil {
		return PayResult{}, err
	}
	if in.Amount < total {
		return PayResult{}, fmt.Errorf("%w: amount %d < total %d", ErrConflict, in.Amount, total)
	}
	change := int64(0)
	if in.Method == "cash" {
		if in.Tendered < in.Amount {
			return PayResult{}, fmt.Errorf("%w: tendered %d < amount %d", ErrConflict, in.Tendered, in.Amount)
		}
		change = in.Tendered - in.Amount
	}
	now := d.now().Unix()
	res, err := tx.Exec(`INSERT INTO payments (order_id, method, amount, reference, paid_at, tendered, change_given)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		in.OrderID, in.Method, in.Amount, in.Reference, now, nullIfZero(in.Tendered), change)
	if err != nil {
		return PayResult{}, err
	}
	payID, err := res.LastInsertId()
	if err != nil {
		return PayResult{}, err
	}
	if _, err := tx.Exec(`UPDATE orders SET status = 'paid', closed_at = ? WHERE id = ?`, now, in.OrderID); err != nil {
		return PayResult{}, err
	}
	// FR-POS-007: the receipt job rides the SAME transaction — a crash
	// between commit and print leaves a queued job, never a paid order
	// without one.
	if _, err := tx.Exec(`INSERT INTO print_jobs (order_id, kind, status, created_at) VALUES (?, 'receipt', 'queued', ?)`,
		in.OrderID, now); err != nil {
		return PayResult{}, err
	}
	if _, err := tx.Exec(`INSERT INTO audit_log_pos (ts, cashier_id, action, target, detail) VALUES (?, ?, 'order_pay', ?, ?)`,
		now, in.CashierID, fmt.Sprintf("order:%d", in.OrderID),
		fmt.Sprintf("method=%s amount=%d change=%d", in.Method, in.Amount, change)); err != nil {
		return PayResult{}, err
	}

	out := PayResult{PaymentID: payID, ChangeGiven: change}
	body, err = marshalJSON(out)
	if err != nil {
		return PayResult{}, err
	}
	if _, err := tx.Exec(`INSERT INTO idempotency_keys (key, request_hash, response_status, response_body, created_at)
		VALUES (?, ?, 200, ?, ?)`, in.IdempotencyKey, []byte("v1"), body, now); err != nil {
		return PayResult{}, err
	}
	return out, tx.Commit()
}

// VoidOrder cancels an open order (admin role, reason audited).
func (d *DB) VoidOrder(orderID, adminID int64, reason string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE orders SET status = 'void', closed_at = ?, void_reason = ?, void_by = ?
		WHERE id = ? AND status = 'open'`, d.now().Unix(), reason, adminID, orderID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: order not open", ErrConflict)
	}
	if _, err := tx.Exec(`INSERT INTO audit_log_pos (ts, cashier_id, action, target, detail) VALUES (?, ?, 'void_order', ?, ?)`,
		d.now().Unix(), adminID, fmt.Sprintf("order:%d", orderID), reason); err != nil {
		return err
	}
	return tx.Commit()
}

// ReceiptData is everything the printer needs for one receipt.
type ReceiptData struct {
	OrderNo  string
	Lines    []ReceiptLine
	Total    int64
	Method   string
	Tendered int64
	Change   int64
	ClosedAt time.Time
}

// ReceiptLine is one printed order line.
type ReceiptLine struct {
	Name string
	Qty  int64
	Unit int64
}

// Receipt reads the paid order for printing.
func (d *DB) Receipt(orderID int64) (ReceiptData, error) {
	var r ReceiptData
	var closedAt int64
	err := d.QueryRow(`SELECT order_no, total, closed_at FROM orders WHERE id = ?`, orderID).
		Scan(&r.OrderNo, &r.Total, &closedAt)
	if err != nil {
		return r, err
	}
	rows, err := d.Query(`SELECT COALESCE(p.name,'?'), i.qty, i.unit_price
		FROM order_items i LEFT JOIN products p ON p.id = i.product_id WHERE i.order_id = ?`, orderID)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var l ReceiptLine
		if err := rows.Scan(&l.Name, &l.Qty, &l.Unit); err != nil {
			return r, err
		}
		r.Lines = append(r.Lines, l)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}
	err = d.QueryRow(`SELECT method, COALESCE(tendered,0), change_given FROM payments WHERE order_id = ? LIMIT 1`, orderID).
		Scan(&r.Method, &r.Tendered, &r.Change)
	if err != nil {
		return r, err
	}
	r.ClosedAt = time.Unix(closedAt, 0)
	return r, nil
}

// NextQueuedReceipt pops the oldest queued print job's order id.
func (d *DB) NextQueuedReceipt() (jobID, orderID int64, err error) {
	err = d.QueryRow(`SELECT id, order_id FROM print_jobs WHERE status = 'queued' ORDER BY id LIMIT 1`).
		Scan(&jobID, &orderID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, nil
	}
	return jobID, orderID, err
}

// MarkPrinted / MarkPrintFailed keep print_jobs' state machine.
func (d *DB) MarkPrinted(jobID int64) error {
	_, err := d.Exec(`UPDATE print_jobs SET status = 'printed', printed_at = ? WHERE id = ?`, d.now().Unix(), jobID)
	return err
}

// MarkPrintFailed increments attempts; the job stays queued for retry
// until maxed by the worker's policy.
func (d *DB) MarkPrintFailed(jobID int64, lastErr string) error {
	_, err := d.Exec(`UPDATE print_jobs SET attempts = attempts + 1, last_error = ? WHERE id = ?`, lastErr, jobID)
	return err
}

// EnsureSeedCatalog inserts the pilot menu when the products table is
// empty (idempotent onboarding convenience).
func (d *DB) EnsureSeedCatalog(items map[string]int64) error {
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM products`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if _, err := d.Exec(`INSERT INTO categories (id, name) VALUES (1, 'Umum')`); err != nil {
		return err
	}
	for name, price := range items {
		if _, err := d.Exec(`INSERT INTO products (category_id, name, price) VALUES (1, ?, ?)`, name, price); err != nil {
			return err
		}
	}
	return nil
}

func nullIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
