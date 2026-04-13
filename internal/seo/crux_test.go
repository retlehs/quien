package seo

import (
	"encoding/json"
	"testing"
)

func TestExtractMetric_Rating(t *testing.T) {
	tests := []struct {
		name       string
		metricName string
		p75        float64
		wantRating string
	}{
		// LCP thresholds: good <= 2500, poor > 4000
		{"LCP good", "largest_contentful_paint", 1200, "good"},
		{"LCP at boundary", "largest_contentful_paint", 2500, "good"},
		{"LCP needs improvement", "largest_contentful_paint", 3000, "needs-improvement"},
		{"LCP at poor boundary", "largest_contentful_paint", 4000, "needs-improvement"},
		{"LCP poor", "largest_contentful_paint", 5000, "poor"},

		// INP thresholds: good <= 200, poor > 500
		{"INP good", "interaction_to_next_paint", 150, "good"},
		{"INP needs improvement", "interaction_to_next_paint", 300, "needs-improvement"},
		{"INP poor", "interaction_to_next_paint", 600, "poor"},

		// CLS thresholds: good <= 0.1, poor > 0.25
		{"CLS good", "cumulative_layout_shift", 0.05, "good"},
		{"CLS at boundary", "cumulative_layout_shift", 0.1, "good"},
		{"CLS needs improvement", "cumulative_layout_shift", 0.15, "needs-improvement"},
		{"CLS poor", "cumulative_layout_shift", 0.3, "poor"},

		// FCP thresholds: good <= 1800, poor > 3000
		{"FCP good", "first_contentful_paint", 1000, "good"},
		{"FCP needs improvement", "first_contentful_paint", 2500, "needs-improvement"},
		{"FCP poor", "first_contentful_paint", 3500, "poor"},

		// TTFB thresholds: good <= 800, poor > 1800
		{"TTFB good", "experimental_time_to_first_byte", 500, "good"},
		{"TTFB needs improvement", "experimental_time_to_first_byte", 1000, "needs-improvement"},
		{"TTFB poor", "experimental_time_to_first_byte", 2000, "poor"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := cruxMetric{
				Histogram: []cruxBucket{
					{Density: 0.5},
					{Density: 0.3},
					{Density: 0.2},
				},
			}
			m.Percentiles.P75 = json.Number(floatToString(tt.p75))

			result := extractMetric(m, tt.metricName)
			if result == nil {
				t.Fatal("extractMetric returned nil")
			}
			if result.Rating != tt.wantRating {
				t.Errorf("rating = %q, want %q (p75=%v)", result.Rating, tt.wantRating, tt.p75)
			}
		})
	}
}

func TestExtractMetric_Histogram(t *testing.T) {
	m := cruxMetric{
		Histogram: []cruxBucket{
			{Density: 0.75},
			{Density: 0.15},
			{Density: 0.10},
		},
	}
	m.Percentiles.P75 = json.Number("1200")

	result := extractMetric(m, "largest_contentful_paint")
	if result == nil {
		t.Fatal("extractMetric returned nil")
	}

	if result.Good != 75.0 {
		t.Errorf("Good = %v, want 75.0", result.Good)
	}
	if result.NI != 15.0 {
		t.Errorf("NI = %v, want 15.0", result.NI)
	}
	if result.Poor != 10.0 {
		t.Errorf("Poor = %v, want 10.0", result.Poor)
	}
	if result.P75 != 1200 {
		t.Errorf("P75 = %v, want 1200", result.P75)
	}
}

func TestExtractMetric_EmptyHistogram(t *testing.T) {
	m := cruxMetric{}
	result := extractMetric(m, "largest_contentful_paint")
	if result != nil {
		t.Errorf("expected nil for empty histogram, got %+v", result)
	}
}

func TestExtractHistoryP75(t *testing.T) {
	m := cruxHistoryMetric{}
	m.PercentilesTimeseries.P75s = []json.Number{"1200", "1300", "1100"}

	vals := extractHistoryP75(m)
	if len(vals) != 3 {
		t.Fatalf("len = %d, want 3", len(vals))
	}
	if vals[0] != 1200 || vals[1] != 1300 || vals[2] != 1100 {
		t.Errorf("vals = %v, want [1200 1300 1100]", vals)
	}
}

func TestExtractHistoryP75_Empty(t *testing.T) {
	m := cruxHistoryMetric{}
	vals := extractHistoryP75(m)
	if len(vals) != 0 {
		t.Errorf("expected empty, got %v", vals)
	}
}

func TestMetricThresholds(t *testing.T) {
	tests := []struct {
		name     string
		wantGood float64
		wantPoor float64
	}{
		{"largest_contentful_paint", 2500, 4000},
		{"interaction_to_next_paint", 200, 500},
		{"cumulative_layout_shift", 0.1, 0.25},
		{"first_contentful_paint", 1800, 3000},
		{"experimental_time_to_first_byte", 800, 1800},
		{"unknown_metric", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			good, poor := metricThresholds(tt.name)
			if good != tt.wantGood {
				t.Errorf("good = %v, want %v", good, tt.wantGood)
			}
			if poor != tt.wantPoor {
				t.Errorf("poor = %v, want %v", poor, tt.wantPoor)
			}
		})
	}
}

func floatToString(f float64) string {
	return json.Number(func() string {
		b, _ := json.Marshal(f)
		return string(b)
	}()).String()
}
