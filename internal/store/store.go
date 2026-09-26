// Package store opens and migrates the device's state.db.
//
// §8 is explicit that state.db uses WAL + synchronous=NORMAL ("kehilangan
// <=1 transaksi terakhir saat cabut daya dapat dipulihkan oleh reconcile")
// — deliberately different from pos.db, which the PoS app opens itself
// with synchronous=FULL (DD-12/ERR-06: "0 order hilang saat cabut daya").
// Do not reuse this package for pos.db.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	_ "modernc.org/sqlite" // pure-Go driver: no CGO, cross-compiles cleanly to the Pi's arm64 target
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Open opens (creating if absent) the state.db at path and applies every
// migration under migrations/ that hasn't run yet, in filename order.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)",
		path,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// PD-3 ("satu penulis"): one connection, so SQLITE_BUSY simply can't
	// happen from within this process — no retry-loop needed.
	db.SetMaxOpenConns(1)

	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("store: read migrations dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // "0001_*", "0002_*", ... — filename order IS apply order

	for _, name := range names {
		var applied int
		row := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, name)
		if err := row.Scan(&applied); err != nil {
			return fmt.Errorf("store: check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}

		sqlBytes, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: read migration %s: %w", name, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin tx for %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (?, unixepoch())`, name,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %s: %w", name, err)
		}
	}
	return nil
}
