package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/cyberhunter/goscanners/pkg/crawler"
	"github.com/cyberhunter/goscanners/pkg/dns"
	"github.com/cyberhunter/goscanners/pkg/fuzzer"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: goscanners <command>\nCommands: fuzz, crawl, resolve\n")
		os.Exit(1)
	}

	command := os.Args[1]
	input, _ := io.ReadAll(os.Stdin)
	inputStr := string(input)

	var output string

	switch command {
	case "fuzz":
		output = fuzzer.FuzzJSON(inputStr)
	case "crawl":
		output = crawler.CrawlJSON(inputStr)
	case "resolve":
		output = dns.BulkResolveJSON(inputStr)
	default:
		result := map[string]string{"error": fmt.Sprintf("unknown command: %s", command)}
		out, _ := json.Marshal(result)
		output = string(out)
	}

	fmt.Print(output)
}
