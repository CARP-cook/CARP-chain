// producer.go – periodically processes the mempool into blocks, invalid TXs are discarded
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
	"xu/app"
)

const (
	mempoolFile = "xu_mempool.json"
	blocksFile  = "xu_blocks.log"
)

func main() {
	xuApp := app.NewXuApp()

	fmt.Println("⏳ Lazy Block Producer started (30s interval)")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	blockHeight := getLastBlockHeight() + 1

	for {
		<-ticker.C
		txs := loadMempool()
		if len(txs) == 0 {
			fmt.Printf("⏭️  Skipping block – mempool empty\n")
			emptyMempool()
			continue
		}

		fmt.Printf("⛓️  Block %d: processing %d TXs\n", blockHeight, len(txs))
		var accepted []app.SignedTx
		for _, tx := range txs {
			res, err := xuApp.ApplySignedTxJSON(tx)
			if err != nil {
				fmt.Println("🚫 TX error:", err)
				continue // ❌ Invalid TX is discarded
			}
			fmt.Println("✅ TX OK:", string(res))
			accepted = append(accepted, tx)
		}

		if len(accepted) > 0 {
			xuApp.SaveState()
			appendBlockToLog(blockHeight, accepted)
			blockHeight++
		}
		emptyMempool()
	}
}

func loadMempool() []app.SignedTx {
	var txs []app.SignedTx
	if raw, err := os.ReadFile(mempoolFile); err == nil {
		json.Unmarshal(raw, &txs)
	}
	return txs
}

func appendBlockToLog(height int, txs []app.SignedTx) {
	entry := map[string]interface{}{
		"height": height,
		"timestamp": time.Now().Format(time.RFC3339),
		"txs": txs,
	}
	data, _ := json.Marshal(entry)
	f, _ := os.OpenFile(blocksFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.Write(append(data, '\n'))
}

func emptyMempool() {
	os.WriteFile(mempoolFile, []byte("[]"), 0644)
}

func getLastBlockHeight() int {
	data, err := os.ReadFile(blocksFile)
	if err != nil {
		return 0
	}
	lines := bytes.Split(data, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines[i]) == 0 {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal(lines[i], &entry); err == nil {
			if h, ok := entry["height"].(float64); ok {
				return int(h)
			}
		}
	}
	return 0
}

