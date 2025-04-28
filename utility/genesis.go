package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	genesisAddr  = "Caeee0442cce"
	genesisFunds = 10000
)

func main() {
	// Remove all persistent state
	files := []string{"carp_blocks.log", "carp_mempool.json", "carp_state.json"}
	for _, f := range files {
		err := os.Remove(f)
		if err == nil {
			fmt.Printf("🧹 Deleted %s\n", f)
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
