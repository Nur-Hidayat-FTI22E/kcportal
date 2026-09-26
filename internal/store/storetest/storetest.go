// Package storetest hands other packages' tests a fresh, fully migrated
// state.db — the same pattern as net/http/httptest. It lives outside
// package store so the helper is part of a normal (non-test) build.
package storetest

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"kotacloud-portal/internal/store"
)

// Open opens a fresh, migrated state.db in t.TempDir() and registers
// Close via t.Cleanup. Fails the test on error.
func Open(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("storetest.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
