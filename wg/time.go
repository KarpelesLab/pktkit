// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wg

import (
	"sync"
	"time"
)

// NowFunc is the function used by the WireGuard package to obtain the current
// time. The default is time.Now. Override this to provide a cached or
// monotonic clock in environments where syscalls are expensive (e.g. SGX).
var NowFunc func() time.Time = time.Now

// now returns the current time via NowFunc.
func now() time.Time {
	return NowFunc()
}

// UseCachedTime replaces NowFunc with a goroutine-cached clock that updates
// every d. This avoids per-call syscall overhead at the cost of d resolution.
// Call with 0 to restore time.Now.
func UseCachedTime(d time.Duration) {
	if d <= 0 {
		NowFunc = time.Now
		return
	}

	var (
		mu  sync.RWMutex
		val = time.Now()
	)

	go func() {
		t := time.NewTicker(d)
		defer t.Stop()
		for n := range t.C {
			mu.Lock()
			val = n
			mu.Unlock()
		}
	}()

	NowFunc = func() time.Time {
		mu.RLock()
		defer mu.RUnlock()
		return val
	}
}
