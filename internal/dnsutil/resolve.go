package dnsutil

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const resolveTimeout = 5 * time.Second

// HostResolution pairs a hostname with its resolved IP addresses (and reverse
// DNS). Err is set instead of IPs when the forward lookup fails.
type HostResolution struct {
	Host string
	IPs  []HostIP
	Err  string `json:",omitempty"`
}

// HostIP is a single resolved address and its reverse DNS names (if any). An
// address can map to more than one PTR record, so all are kept.
type HostIP struct {
	IP   string
	PTRs []string `json:",omitempty"`
}

// hostResolver is the subset of *net.Resolver used by resolveHosts, extracted
// so the resolution logic can be tested without real DNS.
type hostResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// ResolveHosts looks up A/AAAA records and reverse DNS for each host
// concurrently, using the configured resolver. It returns one HostResolution
// per input host, in the same order.
func ResolveHosts(hosts []string) []HostResolution {
	return resolveHosts(hosts, GoResolver(resolveTimeout))
}

func resolveHosts(hosts []string, resolver hostResolver) []HostResolution {
	out := make([]HostResolution, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			out[i].Host = host
			ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
			defer cancel()
			addrs, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				out[i].Err = err.Error()
				return
			}
			ips := make([]HostIP, len(addrs))
			var inner sync.WaitGroup
			for j, a := range addrs {
				ips[j].IP = a.IP.String()
				inner.Add(1)
				go func(j int, ip string) {
					defer inner.Done()
					rctx, rcancel := context.WithTimeout(context.Background(), resolveTimeout)
					defer rcancel()
					names, err := resolver.LookupAddr(rctx, ip)
					if err != nil {
						return
					}
					for _, name := range names {
						ips[j].PTRs = append(ips[j].PTRs, strings.TrimSuffix(name, "."))
					}
				}(j, ips[j].IP)
			}
			inner.Wait()
			out[i].IPs = ips
		}(i, h)
	}
	wg.Wait()
	return out
}
