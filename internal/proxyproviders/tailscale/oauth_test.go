// SPDX-FileCopyrightText: 2025 Paulo Almeida <almeidapaulopt@gmail.com>
// SPDX-License-Identifier: MIT

package tailscale

import (
	"testing"
	"time"
)

func TestOAuthIsExpired_ZeroTime(t *testing.T) {
	o := &oauth{Authkey: "key"}
	if !o.isExpired() {
		t.Error("zero Expires should be treated as expired")
	}
}

func TestOAuthIsExpired_FutureExpiry(t *testing.T) {
	o := &oauth{
		Authkey: "key",
		Expires: time.Now().Add(1 * time.Hour),
	}
	if o.isExpired() {
		t.Error("key expiring in 1 hour should not be expired")
	}
}

func TestOAuthIsExpired_PastExpiry(t *testing.T) {
	o := &oauth{
		Authkey: "key",
		Expires: time.Now().Add(-1 * time.Hour),
	}
	if !o.isExpired() {
		t.Error("key that expired 1 hour ago should be expired")
	}
}

func TestOAuthIsExpired_WithinBuffer(t *testing.T) {
	// Expires in 3 minutes — within the 5-minute buffer.
	o := &oauth{
		Authkey: "key",
		Expires: time.Now().Add(3 * time.Minute),
	}
	if !o.isExpired() {
		t.Error("key expiring within 5-minute buffer should be treated as expired")
	}
}

func TestOAuthIsExpired_JustOutsideBuffer(t *testing.T) {
	// Expires in 6 minutes — outside the 5-minute buffer.
	o := &oauth{
		Authkey: "key",
		Expires: time.Now().Add(6 * time.Minute),
	}
	if o.isExpired() {
		t.Error("key expiring in 6 minutes should not be treated as expired")
	}
}
