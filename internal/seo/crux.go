package seo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// CWVData holds Core Web Vitals field data from the CrUX API.
type CWVData struct {
	Scope string        `json:"scope"` // "origin" or "url"
	LCP   *MetricBucket `json:"lcp,omitempty"`
	INP   *MetricBucket `json:"inp,omitempty"`
	CLS   *MetricBucket `json:"cls,omitempty"`
	FCP   *MetricBucket `json:"fcp,omitempty"`
	TTFB  *MetricBucket `json:"ttfb,omitempty"`
}

// MetricBucket holds a single CWV metric's percentile and distribution.
type MetricBucket struct {
	P75    float64 `json:"p75"`
	Good   float64 `json:"good_pct"`
	NI     float64 `json:"needs_improvement_pct"`
	Poor   float64 `json:"poor_pct"`
	Rating string  `json:"rating"` // "good", "needs-improvement", "poor"
}

// CWVTrend holds weekly CrUX history for sparkline rendering.
type CWVTrend struct {
	Periods []string  `json:"periods"`
	LCP     []float64 `json:"lcp_p75,omitempty"`
	INP     []float64 `json:"inp_p75,omitempty"`
	CLS     []float64 `json:"cls_p75,omitempty"`
}

const cruxAPI = "https://chromeuxreport.googleapis.com/v1/records:queryRecord"
const cruxHistoryAPI = "https://chromeuxreport.googleapis.com/v1/records:queryHistoryRecord"

// fetchCrUX populates CWV and Trend on Result if QUIEN_CRUX_API_KEY is set.
// It tries origins in order, using the first that returns data. This handles
// cases where CrUX indexes data under the bare domain but the site redirects
// to www (or vice versa).
func fetchCrUX(r *Result, origins ...string) {
	apiKey := os.Getenv("QUIEN_CRUX_API_KEY")
	if apiKey == "" {
		return
	}
	r.CrUXKeySet = true

	// Deduplicate origins (e.g. when there's no redirect)
	seen := make(map[string]bool)
	var unique []string
	for _, o := range origins {
		if !seen[o] {
			seen[o] = true
			unique = append(unique, o)
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Current field data — try each origin until one has data
	for _, origin := range unique {
		if cwv, err := queryCrUXRecord(client, apiKey, origin); err == nil {
			r.CWV = cwv
			// Use the same origin that had record data for history
			if trend, err := queryCrUXHistory(client, apiKey, origin); err == nil {
				r.Trend = trend
			}
			return
		}
	}
}

func queryCrUXRecord(client *http.Client, apiKey, origin string) (*CWVData, error) {
	body := fmt.Sprintf(`{"origin":"%s"}`, origin)
	url := cruxAPI + "?key=" + apiKey

	resp, err := client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CrUX API returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, err
	}

	var raw cruxResponse
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	cwv := &CWVData{Scope: "origin"}
	cwv.LCP = extractMetric(raw.Record.Metrics["largest_contentful_paint"], "largest_contentful_paint")
	cwv.INP = extractMetric(raw.Record.Metrics["interaction_to_next_paint"], "interaction_to_next_paint")
	cwv.CLS = extractMetric(raw.Record.Metrics["cumulative_layout_shift"], "cumulative_layout_shift")
	cwv.FCP = extractMetric(raw.Record.Metrics["first_contentful_paint"], "first_contentful_paint")
	cwv.TTFB = extractMetric(raw.Record.Metrics["experimental_time_to_first_byte"], "experimental_time_to_first_byte")

	return cwv, nil
}

func queryCrUXHistory(client *http.Client, apiKey, origin string) (*CWVTrend, error) {
	body := fmt.Sprintf(`{"origin":"%s"}`, origin)
	url := cruxHistoryAPI + "?key=" + apiKey

	resp, err := client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CrUX History API returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	var raw cruxHistoryResponse
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	trend := &CWVTrend{}

	// Extract collection periods
	if cp := raw.Record.CollectionPeriods; len(cp) > 0 {
		for _, p := range cp {
			trend.Periods = append(trend.Periods, p.LastDate.format())
		}
	}

	trend.LCP = extractHistoryP75(raw.Record.Metrics["largest_contentful_paint"])
	trend.INP = extractHistoryP75(raw.Record.Metrics["interaction_to_next_paint"])
	trend.CLS = extractHistoryP75(raw.Record.Metrics["cumulative_layout_shift"])

	if len(trend.Periods) == 0 {
		return nil, fmt.Errorf("no history data")
	}

	return trend, nil
}

// --- CrUX API response types ---

type cruxResponse struct {
	Record struct {
		Metrics map[string]cruxMetric `json:"metrics"`
	} `json:"record"`
}

type cruxMetric struct {
	Histogram   []cruxBucket `json:"histogram"`
	Percentiles struct {
		P75 json.Number `json:"p75"`
	} `json:"percentiles"`
}

type cruxBucket struct {
	Start   json.Number `json:"start"`
	End     json.Number `json:"end,omitempty"`
	Density float64     `json:"density"`
}

type cruxHistoryResponse struct {
	Record struct {
		Metrics           map[string]cruxHistoryMetric `json:"metrics"`
		CollectionPeriods []collectionPeriod           `json:"collectionPeriods"`
	} `json:"record"`
}

type cruxHistoryMetric struct {
	PercentilesTimeseries struct {
		P75s []json.Number `json:"p75s"`
	} `json:"percentilesTimeseries"`
}

type collectionPeriod struct {
	LastDate cruxDate `json:"lastDate"`
}

type cruxDate struct {
	Year  int `json:"year"`
	Month int `json:"month"`
	Day   int `json:"day"`
}

func (d cruxDate) format() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day)
}

// --- Metric extraction ---

func extractMetric(m cruxMetric, metricName string) *MetricBucket {
	if len(m.Histogram) == 0 {
		return nil
	}

	p75, _ := m.Percentiles.P75.Float64()

	mb := &MetricBucket{P75: p75}

	// Histogram: [good, needs-improvement, poor]
	if len(m.Histogram) >= 3 {
		mb.Good = m.Histogram[0].Density * 100
		mb.NI = m.Histogram[1].Density * 100
		mb.Poor = m.Histogram[2].Density * 100
	}

	// Rating based on Google's published p75 thresholds:
	// https://web.dev/articles/vitals
	good, poor := metricThresholds(metricName)
	switch {
	case p75 <= good:
		mb.Rating = "good"
	case p75 <= poor:
		mb.Rating = "needs-improvement"
	default:
		mb.Rating = "poor"
	}

	return mb
}

// metricThresholds returns the (good, poor) p75 thresholds for a CrUX metric.
func metricThresholds(name string) (float64, float64) {
	switch name {
	case "largest_contentful_paint":
		return 2500, 4000 // ms
	case "interaction_to_next_paint":
		return 200, 500 // ms
	case "cumulative_layout_shift":
		return 0.1, 0.25
	case "first_contentful_paint":
		return 1800, 3000 // ms
	case "experimental_time_to_first_byte":
		return 800, 1800 // ms
	default:
		return 0, 0
	}
}

func extractHistoryP75(m cruxHistoryMetric) []float64 {
	var vals []float64
	for _, v := range m.PercentilesTimeseries.P75s {
		f, _ := v.Float64()
		vals = append(vals, f)
	}
	return vals
}
