package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	genesisAddr  = "Cadcc809699584cca9"
	genesisFunds = 10000000
)

func main() {
	// Remove all persistent state
	files := []string{"carp_mempool.json", "carp_state.json"}
	for _, f := range files {
		err := os.Remove(f)
		if err == nil {
			fmt.Printf("🧹 Deleted %s\n", f)
		}
	}

	// Delete all block log files in blocks/ directory
	blockFiles, _ := os.ReadDir("blocks")
	for _, entry := range blockFiles {
		if !entry.IsDir() && len(entry.Name()) > 4 && entry.Name()[len(entry.Name())-4:] == ".log" {
			os.Remove("blocks/" + entry.Name())
			fmt.Printf("🧹 Deleted blocks/%s\n", entry.Name())
		}
	}

	// Recreate empty mempool
	os.WriteFile("carp_mempool.json", []byte("[]"), 0644)

	// Set initial wallet state
	state := map[string]interface{}{
		"wallet": map[string]int64{
			genesisAddr: genesisFunds,
		},
		"nonces": map[string]uint64{},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile("carp_state.json", data, 0644)

	fmt.Printf("✅ CARP Chain reset. %d CARP minted to %s\n", genesisFunds, genesisAddr)
}
