package retry

import (
	"time"
)

const (
	MaxAttempts = 3
	BaseDelay   = 1 * time.Second
)

// Do retries fn up to MaxAttempts times with exponential backoff.
// Returns the result from the first successful call, or the last error.
func Do[T any](fn func() (T, error)) (T, error) {
	var result T
	var err error

	for attempt := range MaxAttempts {
		result, err = fn()
		if err == nil {
			return result, nil
		}

		// Don't sleep after the last attempt
		if attempt < MaxAttempts-1 {
			time.Sleep(BaseDelay * time.Duration(1<<uint(attempt)))
		}
	}

	return result, err
}
