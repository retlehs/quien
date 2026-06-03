package retry

import (
	"time"
)

const (
	MaxAttempts = 3
	BaseDelay   = 1 * time.Second
)

var sleep = time.Sleep

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
			sleep(BaseDelay * time.Duration(1<<attempt))
		}
	}

	return result, err
}
