package core

import "time"

// Result is returned by Actor.Do for every Command (IF-02: "Result struct{
// Err error; ChangeID string; Deadline time.Time }").
//
// A non-zero Deadline means the change was applied provisionally and must
// be confirmed (typically by a follow-up admin/GUI call) before Deadline,
// or the reconciler rolls it back. This is the commit-confirm pattern used
// for anything that could strand the admin who requested it — e.g. a zone
// policy change pushed over the same Wi-Fi it might cut off.
type Result struct {
	Err      error
	ChangeID string
	Deadline time.Time
}

// NeedsConfirm reports whether this result requires a follow-up
// confirmation before its Deadline to avoid being rolled back.
func (r Result) NeedsConfirm() bool {
	return !r.Deadline.IsZero()
}
