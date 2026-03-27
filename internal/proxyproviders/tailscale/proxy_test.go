// SPDX-FileCopyrightText: 2025 Paulo Almeida <almeidapaulopt@gmail.com>
// SPDX-License-Identifier: MIT

package tailscale

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func TestRemoveStaleFiles_RemovesBothFiles(t *testing.T) {
	dir := t.TempDir()

	// Create both stale files
	for _, name := range []string{"tailscaled.state", "tsdproxy.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	p := &Proxy{
		log:     zerolog.Nop(),
		datadir: dir,
	}

	p.removeStaleFiles()

	for _, name := range []string{"tailscaled.state", "tsdproxy.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should have been removed", name)
		}
	}
}

func TestRemoveStaleFiles_HandlesAlreadyMissing(t *testing.T) {
	dir := t.TempDir()

	// Only create one file; the other is already missing
	if err := os.WriteFile(filepath.Join(dir, "tailscaled.state"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &Proxy{
		log:     zerolog.Nop(),
		datadir: dir,
	}

	// Should not panic or error when tsdproxy.yaml doesn't exist
	p.removeStaleFiles()

	if _, err := os.Stat(filepath.Join(dir, "tailscaled.state")); !os.IsNotExist(err) {
		t.Error("tailscaled.state should have been removed")
	}
}

func TestRemoveStaleFiles_PreservesOtherFiles(t *testing.T) {
	dir := t.TempDir()

	// Create stale files and an unrelated file
	for _, name := range []string{"tailscaled.state", "tsdproxy.yaml", "other.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	p := &Proxy{
		log:     zerolog.Nop(),
		datadir: dir,
	}

	p.removeStaleFiles()

	if _, err := os.Stat(filepath.Join(dir, "other.txt")); err != nil {
		t.Error("other.txt should not have been removed")
	}
}
