// tx_push.go – Pushes any signed transaction JSON to the XuChain mempool
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	file := flag.String("file", "", "Path to signed transaction JSON file")
	api := flag.String("api", "http://localhost:8080/send", "XuChain /send endpoint")
	flag.Parse()

	if *file == "" {
		fmt.Println("Usage: go run tx_push.go -file=signed_tx.json [-api=http://localhost:8080/send]")
		os.Exit(1)
	}

	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Println("❌ Failed to read file:", err)
		os.Exit(1)
	}

	// Optional: validate JSON structure
	var test map[string]interface{}
	if err := json.Unmarshal(raw, &test); err != nil {
		fmt.Println("❌ Invalid JSON in file:", err)
		os.Exit(1)
	}

	res, err := http.Post(*api, "application/json", bytes.NewReader(raw))
	if err != nil {
		fmt.Println("❌ Failed to POST transaction:", err)
		os.Exit(1)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != http.StatusOK {
		fmt.Printf("❌ Server rejected TX (%s):\n%s\n", res.Status, string(body))
		os.Exit(1)
	}

	fmt.Printf("✅ Server Response (%s):\n%s\n", res.Status, string(body))
}