package dns

import (
	"os"
	"sync/atomic"
)

// resolvConf is the path to the system resolver configuration.
const resolvConf = "/etc/resolv.conf"

// osReadFile is an indirection over os.ReadFile so tests can inject a stub
// resolv.conf without touching the real filesystem.
func osReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// atomicBool wraps atomic.Bool.
type atomicBool struct{ b atomic.Bool }

// Set stores the value.
func (a *atomicBool) Set(v bool) { a.b.Store(v) }

// Get returns the value.
func (a *atomicBool) Get() bool { return a.b.Load() }

// atomicInt64 wraps atomic.Int64.
type atomicInt64 struct{ v atomic.Int64 }

// Add adds delta.
func (a *atomicInt64) Add(d int64) { a.v.Add(d) }

// Get returns the value.
func (a *atomicInt64) Get() int64 { return a.v.Load() }
