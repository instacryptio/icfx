//go:build linux && !android && !nohw

package chalresp

import (
	"syscall"
	"testing"
)

// TestHidRunPinsOneThread proves the property the macOS fix relies on: every
// job runs on the same OS thread for the life of the process, no matter which
// goroutine submitted it.
func TestHidRunPinsOneThread(t *testing.T) {
	tid := func() int {
		var id int
		_ = hidRun(func() error { id = syscall.Gettid(); return nil })
		return id
	}
	first := tid()
	if first == 0 {
		t.Fatal("could not read the worker's thread id")
	}
	done := make(chan int)
	for i := 0; i < 8; i++ {
		go func() { done <- tid() }()
	}
	for i := 0; i < 8; i++ {
		if got := <-done; got != first {
			t.Fatalf("job ran on thread %d, want the worker thread %d", got, first)
		}
	}
	if syscall.Gettid() == first {
		t.Fatal("the worker thread must not be the test goroutine's thread")
	}
}
