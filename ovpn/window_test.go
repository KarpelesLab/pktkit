package ovpn

import "testing"

func TestWindowSequential(t *testing.T) {
	w := newWindow()
	for i := uint32(0); i < 100; i++ {
		if !w.check(i) {
			t.Fatalf("sequential ID %d rejected", i)
		}
	}
}

func TestWindowDuplicate(t *testing.T) {
	w := newWindow()
	if !w.check(42) {
		t.Fatal("first check of 42 should succeed")
	}
	if w.check(42) {
		t.Fatal("duplicate 42 should be rejected")
	}
}

func TestWindowOutOfOrder(t *testing.T) {
	w := newWindow()
	// Mark 0, 1, 2
	w.check(0)
	w.check(1)
	w.check(2)
	// Skip to 10
	if !w.check(10) {
		t.Fatal("ID 10 should be accepted")
	}
	// Go back within window
	if !w.check(5) {
		t.Fatal("ID 5 within window should be accepted")
	}
	// Check it's now marked
	if w.check(5) {
		t.Fatal("duplicate 5 should be rejected")
	}
}

func TestWindowOldReject(t *testing.T) {
	w := newWindow()
	// Advance window past 2048+100
	for i := uint32(0); i < replayWindowSize+100; i++ {
		w.check(i)
	}
	// Very old ID should be rejected
	if w.check(0) {
		t.Fatal("very old ID 0 should be rejected")
	}
	if w.check(50) {
		t.Fatal("old ID 50 should be rejected")
	}
}

func TestWindowReset(t *testing.T) {
	w := newWindow()
	w.check(0)
	w.check(1)

	// Jump far ahead — should reset window
	farAhead := uint32(replayWindowSize * 2)
	if !w.check(farAhead) {
		t.Fatal("far-ahead ID should be accepted and reset window")
	}
	// Old IDs should now be rejected
	if w.check(0) {
		t.Fatal("ID 0 should be rejected after window reset")
	}
	// ID just before the far-ahead should also be rejected (too old)
	if w.check(1) {
		t.Fatal("ID 1 should be rejected after window reset")
	}
}

func TestWindowLargeGap(t *testing.T) {
	w := newWindow()
	w.check(0)
	// Gap within window — should advance without reset
	gap := uint32(replayWindowSize - 100)
	if !w.check(gap) {
		t.Fatal("ID within window should be accepted")
	}
	// IDs between 0 and gap should still be acceptable
	if !w.check(gap / 2) {
		t.Fatal("ID in middle of gap should be accepted")
	}
}

func TestWindowInit(t *testing.T) {
	w := newWindow()
	// First call with non-zero ID
	if !w.check(1000) {
		t.Fatal("first call with 1000 should succeed")
	}
	// Duplicate
	if w.check(1000) {
		t.Fatal("duplicate 1000 should be rejected")
	}
	// Earlier ID near 1000 should work
	if !w.check(999) {
		t.Fatal("ID 999 should be accepted")
	}
}
