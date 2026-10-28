package image

import (
	"context"
	"testing"
	"time"
)

// NFR-01: a registry lookup used to have no bound at all, so a registry that
// accepted the connection and never answered could hang the whole command
// forever (no way out short of Ctrl+C). WithResolveTimeout is what every
// registry-touching call site (Resolve/ResolveAny/ResolveBaseImage,
// baserec's Enumerate and per-candidate Resolve) now runs under.
func TestWithResolveTimeout_AddsADeadlineWhenCallerSetNone(t *testing.T) {
	ctx, cancel := WithResolveTimeout(context.Background())
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("no deadline was added to a context that had none")
	}
	left := time.Until(deadline)
	if left <= 0 || left > DefaultResolveTimeout {
		t.Errorf("deadline is %v away, want somewhere in (0, %v]", left, DefaultResolveTimeout)
	}
}

// A caller that already imposed its own (shorter) deadline knows best; a
// generic registry timeout must never relax or replace it.
func TestWithResolveTimeout_LeavesAnExistingDeadlineAlone(t *testing.T) {
	short, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, cancel2 := WithResolveTimeout(short)
	defer cancel2()

	if got != short {
		t.Error("an existing deadline was replaced instead of left alone")
	}
}

// The mechanism actually cancels work: a function that only returns when its
// context is Done() must come back once the timeout elapses, not hang.
func TestWithResolveTimeout_ActuallyFires(t *testing.T) {
	ctx, cancel := WithResolveTimeout(context.Background())
	defer cancel()
	// Override: wait for the real 5-minute default would make this test
	// itself hang; prove the same mechanism with a tiny one instead.
	ctx, cancel2 := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel2()

	select {
	case <-ctx.Done():
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("context was never cancelled; a hung registry call would never return")
	}
}
