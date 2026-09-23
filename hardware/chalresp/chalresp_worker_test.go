//go:build !android && !ios && !nohw

package chalresp

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// The HID worker never touches hardware in these tests: they exercise hidRun's
// contract — every job runs on the one worker, one at a time, and nothing a job
// does can take the worker down.

func TestHidRunReturnsJobError(t *testing.T) {
	want := errors.New("job failed")
	if got := hidRun(func() error { return want }); !errors.Is(got, want) {
		t.Fatalf("hidRun error = %v, want %v", got, want)
	}
	if got := hidRun(func() error { return nil }); got != nil {
		t.Fatalf("hidRun error = %v, want nil", got)
	}
}

func TestHidRunSurvivesPanic(t *testing.T) {
	err := hidRun(func() error { panic("boom") })
	if err == nil || err.Error() != "chalresp: hid worker panic: boom" {
		t.Fatalf("panicking job must surface as an error, got %v", err)
	}
	// The worker must still be alive and serving.
	ran := false
	if err := hidRun(func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("worker did not serve the next job after a panic: ran=%v err=%v", ran, err)
	}
}

func TestHidRunSerializesJobs(t *testing.T) {
	const n = 64
	var inJob atomic.Int32
	var overlaps atomic.Int32
	var completed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = hidRun(func() error {
				if inJob.Add(1) != 1 {
					overlaps.Add(1)
				}
				completed.Add(1)
				inJob.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	if overlaps.Load() != 0 {
		t.Fatalf("%d jobs overlapped; the worker must run one job at a time", overlaps.Load())
	}
	if completed.Load() != n {
		t.Fatalf("completed %d of %d jobs", completed.Load(), n)
	}
}
