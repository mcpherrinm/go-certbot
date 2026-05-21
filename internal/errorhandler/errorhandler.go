// Package errorhandler maintains a stack of cleanup callbacks that fire on
// uncaught panic OR signal exit. Mirrors certbot._internal.error_handler:
// plugins register an "undo this on failure" func when they make a mutating
// change, and a SIGINT or panic walks the stack LIFO (most-recent first)
// before propagating.
//
// Usage:
//
//	handle := errorhandler.Register(func() { plugin.rollback() })
//	defer handle.Discard()  // cancel on clean success
//
// The Run* helpers below are called by main.go from the signal goroutine
// and the top-level defer recover().
package errorhandler

import (
	"fmt"
	"os"
	"sync"
)

var (
	mu    sync.Mutex
	stack []entry
)

type entry struct {
	id int
	fn func()
}

// Handle is a registration receipt that can be Discard()'d to cancel the
// callback before exit. Mirrors certbot's "remove on success" pattern.
type Handle struct {
	id int
}

var nextID int

// Register pushes fn onto the cleanup stack. Returns a Handle that can be
// used to Discard the registration on clean success.
func Register(fn func()) Handle {
	if fn == nil {
		return Handle{}
	}
	mu.Lock()
	defer mu.Unlock()
	nextID++
	id := nextID
	stack = append(stack, entry{id: id, fn: fn})
	return Handle{id: id}
}

// Discard cancels a registered callback.
func (h Handle) Discard() {
	if h.id == 0 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	out := stack[:0]
	for _, e := range stack {
		if e.id != h.id {
			out = append(out, e)
		}
	}
	stack = out
}

// RunAll walks the stack LIFO and calls every registered callback. Used by
// main.go from the SIGINT/SIGTERM handler and the panic recovery path.
// Errors raised by callbacks are surfaced to stderr but don't stop the
// walk — every cleanup runs, even if an earlier one panics.
func RunAll() {
	mu.Lock()
	pending := stack
	stack = nil
	mu.Unlock()
	for i := len(pending) - 1; i >= 0; i-- {
		fn := pending[i].fn
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintln(os.Stderr, "error_handler: cleanup panicked:", r)
				}
			}()
			fn()
		}()
	}
}
