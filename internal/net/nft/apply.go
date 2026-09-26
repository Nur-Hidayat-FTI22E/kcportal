package nft

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Applier installs rendered rulesets through the nft binary, fail-closed
// (§4.3 notes + NFR-REL-04): when `nft -c` rejects the new ruleset the
// previously installed one stays in place and the caller gets an error
// to turn into a `config.rejected` event; when `nft -f` fails midway the
// kernel rolls the whole transaction back by itself.
type Applier struct {
	// NftBin is the nftables binary; empty means "nft" from $PATH.
	NftBin string
	// Dir is where kcp.nft is written before validation/install.
	Dir string
	// DryRun makes the applier touch neither the parser's netlink cache
	// nor the kernel: the ruleset is written to Dir and nothing else. Used
	// by -dev mode on machines without root (nft -c itself needs
	// CAP_NET_ADMIN to initialise its netlink cache) and by tests.
	DryRun bool
}

// Apply validates and installs the rendered ruleset. It returns the path
// of the file that was installed (useful for the drift check's diff and
// for audit logs).
func (a *Applier) Apply(ctx context.Context, ruleset []byte) (string, error) {
	if err := os.MkdirAll(a.Dir, 0o750); err != nil {
		return "", fmt.Errorf("nft: mkdir %s: %w", a.Dir, err)
	}
	path := filepath.Join(a.Dir, "kcp.nft")
	// 0640: ruleset contains no secrets, but it is not world-business
	// either; the dir is 0750 anyway.
	if err := os.WriteFile(path, ruleset, 0o640); err != nil {
		return "", fmt.Errorf("nft: write %s: %w", path, err)
	}

	// DD-04 / fail-closed: `nft -c -f` parses and kernel-checks the file
	// WITHOUT touching the live ruleset. Any failure here leaves the old
	// ruleset untouched. (Skipped entirely under DryRun — see above.)
	if !a.DryRun {
		if out, err := a.run(ctx, "-c", "-f", path); err != nil {
			return path, &CheckError{Path: path, Output: out, Err: err}
		}
		if out, err := a.run(ctx, "-f", path); err != nil {
			return path, fmt.Errorf("nft: install %s failed (kernel rolled the transaction back): %s: %w",
				path, out, err)
		}
	}
	return path, nil
}

// ApplyBoot installs the static bootstrap ruleset (P-01). Same
// validate-then-install flow, different filename so it never collides
// with kcp.nft in the drift check.
func (a *Applier) ApplyBoot(ctx context.Context) (string, error) {
	if err := os.MkdirAll(a.Dir, 0o750); err != nil {
		return "", fmt.Errorf("nft: mkdir %s: %w", a.Dir, err)
	}
	path := filepath.Join(a.Dir, "kcp-boot.nft")
	if err := os.WriteFile(path, []byte(BootRuleset), 0o640); err != nil {
		return "", fmt.Errorf("nft: write %s: %w", path, err)
	}
	if !a.DryRun {
		if out, err := a.run(ctx, "-c", "-f", path); err != nil {
			return path, &CheckError{Path: path, Output: out, Err: err}
		}
		if out, err := a.run(ctx, "-f", path); err != nil {
			return path, fmt.Errorf("nft: install %s failed (kernel rolled the transaction back): %s: %w",
				path, out, err)
		}
	}
	return path, nil
}

// CheckError reports a ruleset that `nft -c` rejected. Callers map this
// to the `config.rejected` bus event (NFR-REL-04) and keep serving with
// the previous ruleset.
type CheckError struct {
	Path   string
	Output string
	Err    error
}

func (e *CheckError) Error() string {
	return fmt.Sprintf("nft: ruleset %s rejected by `nft -c` (previous ruleset kept, config.rejected): %s: %v",
		e.Path, e.Output, e.Err)
}

func (e *CheckError) Unwrap() error { return e.Err }

func (a *Applier) run(ctx context.Context, args ...string) (string, error) {
	bin := a.NftBin
	if bin == "" {
		bin = "nft"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String() + stderr.String()
	return out, err
}
