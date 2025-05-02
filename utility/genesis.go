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

	// Delete all carp_blocks_*.log files
	entries, _ := os.ReadDir(".")
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && len(name) > 16 && name[:14] == "carp_blocks_" && name[len(name)-4:] == ".log" {
			os.Remove(name)
			fmt.Printf("🧹 Deleted %s\n", name)
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
