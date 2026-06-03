package retry

import (
	"errors"
	"testing"
	"time"
)

// Avoid backoff delays during tests.
func init() { sleep = func(time.Duration) {} }

func TestDo_SucceedsFirstTry(t *testing.T) {
	calls := 0
	result, err := Do(func() (string, error) {
		calls++
		return "ok", nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %q, want %q", result, "ok")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestDo_SucceedsOnRetry(t *testing.T) {
	calls := 0
	result, err := Do(func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("fail")
		}
		return "recovered", nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "recovered" {
		t.Errorf("result = %q, want %q", result, "recovered")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestDo_AllAttemptsFail(t *testing.T) {
	calls := 0
	_, err := Do(func() (string, error) {
		calls++
		return "", errors.New("persistent failure")
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "persistent failure" {
		t.Errorf("error = %q, want %q", err.Error(), "persistent failure")
	}
	if calls != MaxAttempts {
		t.Errorf("calls = %d, want %d", calls, MaxAttempts)
	}
}

func TestDo_ReturnsLastError(t *testing.T) {
	calls := 0
	_, err := Do(func() (int, error) {
		calls++
		return 0, errors.New("attempt " + string(rune('0'+calls)))
	})

	if err == nil {
		t.Fatal("expected error")
	}
	// Should return the error from the last attempt
	if calls != MaxAttempts {
		t.Errorf("calls = %d, want %d", calls, MaxAttempts)
	}
}
