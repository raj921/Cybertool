package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

type ResolveResult struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
	CNAME  string   `json:"cname,omitempty"`
	Error  string   `json:"error,omitempty"`
}

func BulkResolve(domains []string, concurrency int) []ResolveResult {
	if concurrency <= 0 {
		concurrency = 50
	}

	results := make([]ResolveResult, len(domains))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}
	_ = resolver

	for i, domain := range domains {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, d string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := ResolveResult{Domain: d}

			ips, err := net.LookupHost(d)
			if err != nil {
				result.Error = err.Error()
			} else {
				result.IPs = ips
			}

			cname, err := net.LookupCNAME(d)
			if err == nil && cname != d+"." {
				result.CNAME = cname
			}

			results[idx] = result
		}(i, domain)
	}

	wg.Wait()
	return results
}

func BulkResolveJSON(inputJSON string) string {
	var input struct {
		Domains     []string `json:"domains"`
		Concurrency int      `json:"concurrency"`
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Sprintf(`{"error": "%s"}`, err.Error())
	}
	results := BulkResolve(input.Domains, input.Concurrency)
	out, _ := json.Marshal(results)
	return string(out)
}
