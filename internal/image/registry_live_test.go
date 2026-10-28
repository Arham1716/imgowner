package image

import (
	"context"
	"testing"
	"time"
)

// Live proof, not just of the helper in isolation but of the production path:
// Resolve against an address nothing answers on (10.255.255.1 is reserved,
// unroutable) must come back once the deadline we set elapses, not hang.
// A short caller deadline is used so the test itself stays fast; it also
// proves WithResolveTimeout's "the caller's deadline wins" rule holds for
// the real registry call, not just the helper function.
func TestResolve_UnreachableRegistryFailsInBoundedTime(t *testing.T) {
	if testing.Short() {
		t.Skip("touches the network")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	_, err := Resolve(ctx, "10.255.255.1:5000/x:y", "")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("resolving an unreachable registry unexpectedly succeeded")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("took %v to fail; the caller's 3s deadline should have bounded it", elapsed)
	}
	t.Logf("failed after %v: %v", elapsed, err)
}
