package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	genesisAddr  = "Xueee0442cce"
	genesisFunds = 1000
)

func main() {
	// Remove all persistent state
	files := []string{"xu_blocks.log", "xu_mempool.json", "xu_state.json"}
	for _, f := range files {
		err := os.Remove(f)
		if err == nil {
			fmt.Printf("🧹 Deleted %s\n", f)
		}
	}

	// Recreate empty mempool
	os.WriteFile("xu_mempool.json", []byte("[]"), 0644)

	// Set initial wallet state
	state := map[string]interface{}{
		"wallet": map[string]int64{
			genesisAddr: genesisFunds,
		},
		"nonces": map[string]uint64{},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile("xu_state.json", data, 0644)

	fmt.Printf("✅ XuChain reset. %d Xu minted to %s\n", genesisFunds, genesisAddr)
}
