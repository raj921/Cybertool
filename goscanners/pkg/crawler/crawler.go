package crawler

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CrawlResult struct {
	URLs       []string          `json:"urls"`
	Forms      []FormInfo        `json:"forms"`
	JSFiles    []string          `json:"js_files"`
	Endpoints  []string          `json:"endpoints"`
	TotalPages int               `json:"total_pages"`
	Errors     []string          `json:"errors,omitempty"`
}

type FormInfo struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
}

var (
	linkRe     = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)
	formRe     = regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	actionRe   = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']+)["']`)
	methodRe   = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']+)["']`)
	inputRe    = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']+)["']`)
	endpointRe = regexp.MustCompile(`["'](/api/[a-zA-Z0-9/_-]+)["']`)
)

func Crawl(baseURL string, maxPages int, concurrency int) CrawlResult {
	if maxPages <= 0 {
		maxPages = 100
	}
	if concurrency <= 0 {
		concurrency = 10
	}

	result := CrawlResult{}
	visited := make(map[string]bool)
	var mu sync.Mutex
	queue := []string{baseURL}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}

	sem := make(chan struct{}, concurrency)

	for len(queue) > 0 && len(visited) < maxPages {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		sem <- struct{}{}
		func(pageURL string) {
			defer func() { <-sem }()

			resp, err := client.Get(pageURL)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 500_000))
			bodyStr := string(body)

			mu.Lock()
			result.URLs = append(result.URLs, pageURL)
			result.TotalPages++

			// Extract links
			for _, match := range linkRe.FindAllStringSubmatch(bodyStr, -1) {
				href := match[1]
				resolved := resolveURL(parsedBase, href)
				if resolved != "" && strings.Contains(resolved, parsedBase.Host) && !visited[resolved] {
					queue = append(queue, resolved)
				}
				if strings.HasSuffix(href, ".js") {
					result.JSFiles = append(result.JSFiles, resolveURL(parsedBase, href))
				}
			}

			// Extract forms
			for _, formMatch := range formRe.FindAllStringSubmatch(bodyStr, -1) {
				form := FormInfo{Method: "GET"}
				if am := actionRe.FindStringSubmatch(formMatch[0]); len(am) > 1 {
					form.Action = resolveURL(parsedBase, am[1])
				}
				if mm := methodRe.FindStringSubmatch(formMatch[0]); len(mm) > 1 {
					form.Method = strings.ToUpper(mm[1])
				}
				for _, im := range inputRe.FindAllStringSubmatch(formMatch[1], -1) {
					form.Inputs = append(form.Inputs, im[1])
				}
				result.Forms = append(result.Forms, form)
			}

			// Extract API endpoints
			for _, em := range endpointRe.FindAllStringSubmatch(bodyStr, -1) {
				result.Endpoints = append(result.Endpoints, em[1])
			}

			mu.Unlock()
		}(current)
	}

	return result
}

func resolveURL(base *url.URL, href string) string {
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func CrawlJSON(inputJSON string) string {
	var input struct {
		URL         string `json:"url"`
		MaxPages    int    `json:"max_pages"`
		Concurrency int    `json:"concurrency"`
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Sprintf(`{"error": "%s"}`, err.Error())
	}
	result := Crawl(input.URL, input.MaxPages, input.Concurrency)
	out, _ := json.Marshal(result)
	return string(out)
}
