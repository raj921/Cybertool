package fuzzer

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type FuzzRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Payload string            `json:"payload"`
	Param   string            `json:"param"`
}

type FuzzResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	BodyLength int    `json:"body_length"`
	Payload    string `json:"payload"`
	Param      string `json:"param"`
	TimeTaken  int64  `json:"time_taken_ms"`
	Error      string `json:"error,omitempty"`
}

type FuzzConfig struct {
	Concurrency int `json:"concurrency"`
	Timeout     int `json:"timeout_ms"`
	RateLimit   int `json:"rate_limit_per_sec"`
}

func DefaultConfig() FuzzConfig {
	return FuzzConfig{
		Concurrency: 50,
		Timeout:     10000,
		RateLimit:   100,
	}
}

func Fuzz(requests []FuzzRequest, config FuzzConfig) []FuzzResult {
	if config.Concurrency <= 0 {
		config.Concurrency = 50
	}
	if config.Timeout <= 0 {
		config.Timeout = 10000
	}

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        config.Concurrency,
			MaxIdleConnsPerHost: config.Concurrency,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var results []FuzzResult
	var mu sync.Mutex
	var processed int64

	sem := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	for _, req := range requests {
		wg.Add(1)
		sem <- struct{}{}

		go func(r FuzzRequest) {
			defer wg.Done()
			defer func() { <-sem }()

			result := executeSingle(client, r)
			atomic.AddInt64(&processed, 1)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(req)
	}

	wg.Wait()
	return results
}

func executeSingle(client *http.Client, r FuzzRequest) FuzzResult {
	start := time.Now()
	result := FuzzResult{
		URL:     r.URL,
		Payload: r.Payload,
		Param:   r.Param,
	}

	var body io.Reader
	if r.Method == "POST" && r.Payload != "" {
		body = strings.NewReader(r.Payload)
	}

	req, err := http.NewRequest(r.Method, r.URL, body)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		result.TimeTaken = time.Since(start).Milliseconds()
		return result
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 50_000))

	result.StatusCode = resp.StatusCode
	result.BodyLength = len(respBody)
	result.TimeTaken = time.Since(start).Milliseconds()

	return result
}

func FuzzJSON(inputJSON string) string {
	var input struct {
		Requests []FuzzRequest `json:"requests"`
		Config   FuzzConfig    `json:"config"`
	}

	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Sprintf(`{"error": "%s"}`, err.Error())
	}

	if input.Config.Concurrency == 0 {
		input.Config = DefaultConfig()
	}

	results := Fuzz(input.Requests, input.Config)
	out, _ := json.Marshal(results)
	return string(out)
}
