package display

import (
	"testing"
	"time"
)

func TestRelativeTime(t *testing.T) {
	// Fixed reference instant so calendar-day labels are deterministic
	// regardless of the time of day the test runs.
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"today", now, "today"},
		{"earlier today", now.Add(-8 * time.Hour), "today"},
		{"later today", now.Add(8 * time.Hour), "today"},
		{"yesterday", now.AddDate(0, 0, -1), "yesterday"},
		{"tomorrow", now.AddDate(0, 0, 1), "tomorrow"},
		// <24h away but on an adjacent calendar date: labeled by date, not hours.
		{"late yesterday within 24h", now.Add(-20 * time.Hour), "yesterday"},
		{"early tomorrow within 24h", now.Add(20 * time.Hour), "tomorrow"},
		// Different zone: civil date 06-24 (what dateRow prints) is the next day
		// even though the instant is only ~3h after now.
		{"next date in another zone", time.Date(2026, 6, 24, 0, 0, 0, 0, time.FixedZone("JST", 9*3600)), "tomorrow"},
		{"5 days ago", now.AddDate(0, 0, -5), "5 days ago"},
		{"2 months ago", now.AddDate(0, 0, -60), "2 months ago"},
		{"1 year ago", now.AddDate(0, 0, -365), "1 year ago"},
		{"future", now.AddDate(0, 0, 95), "3 months from now"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relativeTimeFrom(now, tt.t)
			if got != tt.want {
				t.Errorf("relativeTimeFrom() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		days int
		want string
	}{
		{1, "1 day"},
		{2, "2 days"},
		{15, "15 days"},
		{30, "1 month"},
		{90, "3 months"},
		{365, "1 year"},
		{400, "1 year, 1 month"},
		{730, "2 years"},
		{800, "2 years, 2 months"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			d := time.Duration(tt.days) * 24 * time.Hour
			got := formatDuration(d)
			if got != tt.want {
				t.Errorf("formatDuration(%d days) = %q, want %q", tt.days, got, tt.want)
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxWidth int
		want     int // expected number of lines
	}{
		{"short string", "hello", 20, 1},
		{"exact fit", "hello world", 11, 1},
		{"needs wrap", "hello world foo bar", 10, 3},
		{"long word", "superlongword", 5, 3},
		{"empty", "", 10, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := wrapText(tt.input, tt.maxWidth)
			if len(lines) != tt.want {
				t.Errorf("wrapText(%q, %d) = %d lines %v, want %d", tt.input, tt.maxWidth, len(lines), lines, tt.want)
			}
			// Verify no line exceeds maxWidth
			for i, line := range lines {
				if len(line) > tt.maxWidth {
					t.Errorf("line %d length %d exceeds max %d: %q", i, len(line), tt.maxWidth, line)
				}
			}
		})
	}
}
