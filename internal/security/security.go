package security

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	Found      bool
	URL        string
	StatusCode int
	Content    string
	Fields     map[string][]string
}

const timeout = 10 * time.Second

var wellKnownPaths = []string{
	"/.well-known/security.txt",
	"/security.txt",
}

func Lookup(domain string) (*Result, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}

	for _, path := range wellKnownPaths {
		for _, scheme := range []string{"https", "http"} {
			url := scheme + "://" + domain + path
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusOK {
				body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
				if err != nil {
					return nil, err
				}

				content := string(body)
				return &Result{
					Found:      true,
					URL:        url,
					StatusCode: resp.StatusCode,
					Content:    content,
					Fields:     parseFields(content),
				}, nil
			}
		}
	}

	return &Result{Found: false}, nil
}

// Valid security.txt fields per RFC 9116
var validFields = map[string]bool{
	"contact":             true,
	"encryption":          true,
	"preferences":         true,
	"preferred-languages": true,
	"hiring":              true,
	"policy":              true,
	"canonical":           true,
	"acknowledgments":     true,
}

func parseFields(content string) map[string][]string {
	fields := make(map[string][]string)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		if !validFields[key] {
			continue
		}

		value := strings.TrimSpace(parts[1])
		fields[key] = append(fields[key], value)
	}

	return fields
}
