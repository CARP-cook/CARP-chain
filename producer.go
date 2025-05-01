// producer.go – periodically processes the mempool into blocks, invalid TXs are discarded
package main

import (
	"bytes"
	"carp/app"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func init() {
	godotenv.Load()
}

const (
	mempoolFile = "carp_mempool.json"
	blocksFile  = "carp_blocks.log"
)

func main() {
	carpApp := app.NewCarpApp()

	// Decode admin pubkey from base64
	adminPubKeyB64 := os.Getenv("CARP_ADMIN_PUBKEY")
	adminPubKey, err := base64.StdEncoding.DecodeString(adminPubKeyB64)
	if err != nil || len(adminPubKey) != 32 {
		fmt.Println("❌ Invalid CARP_ADMIN_PUBKEY in .env")
		os.Exit(1)
	}

	fmt.Println("⏳ Lazy Block Producer started (30s interval)")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	blockHeight := getLastBlockHeight() + 1

	for {
		<-ticker.C

		txs := loadMempool()
		fmt.Printf("🪄 Parsed %d TXs from mempool\n", len(txs))

		if len(txs) == 0 {
			fmt.Println("⏭️  Skipping block – mempool empty")
			continue
		}

		fmt.Printf("⛓️  Block %d: processing %d TXs\n", blockHeight, len(txs))
		var accepted []app.SignedTx
		seen := make(map[string]bool)
		for i, tx := range txs {
			fmt.Printf("🔍 TX[%d]: type=%s, from=%s, to=%s, amount=%d, nonce=%d\n",
				i, tx.Tx.Type, tx.Tx.From, tx.Tx.To, tx.Tx.Amount, tx.Tx.Nonce)

			// Only admin can do mint
			if tx.Tx.Type == "mint" {
				txPubKey, err := base64.StdEncoding.DecodeString(tx.PubKey)
				if err != nil || !bytes.Equal(txPubKey, adminPubKey) {
					fmt.Println("🚫 Mint rejected: not signed by admin")
					continue
				}
			}

			// Set hash for the transaction
			tx.Tx.Hash = app.ComputeTxHash(tx.Tx)

			// Nonce validation is handled inside ApplySignedTxJSON

			if seen[tx.Tx.Hash] {
				fmt.Println("🚫 Duplicate TX hash detected, skipping:", tx.Tx.Hash)
				continue
			}
			seen[tx.Tx.Hash] = true

			// apply tx
			res, err := carpApp.ApplySignedTxJSON(tx)
			if err != nil {
				fmt.Println("🚫 TX error:", err)
				continue
			}

			fmt.Println("✅ TX OK:", string(res))
			accepted = append(accepted, tx)
		}

		if len(accepted) > 0 {
			carpApp.SaveState()
			appendBlockToLog(blockHeight, accepted)
			blockHeight++
		}
		emptyMempool()
	}
}

func loadMempool() []app.SignedTx {
	var txs []app.SignedTx
	raw, err := os.ReadFile(mempoolFile)
	if err != nil {
		fmt.Println("⚠️ Could not read mempool file:", err)
		return txs
	}
	if err := json.Unmarshal(raw, &txs); err != nil {
		fmt.Println("⚠️ Failed to unmarshal mempool:", err)
	}
	return txs
}

func appendBlockToLog(height int, txs []app.SignedTx) {
	// Compute tx hashes
	var txEntries []map[string]interface{}
	var txHashes []string
	for _, signed := range txs {
		hash := app.ComputeTxHash(signed.Tx)
		txHashes = append(txHashes, hash)
		txEntries = append(txEntries, map[string]interface{}{
			"tx":   signed.Tx,
			"hash": hash,
		})
	}

	// Sort hashes and compute block hash
	sort.Strings(txHashes)
	blockHashInput := []byte(strings.Join(txHashes, ""))
	blockHash := fmt.Sprintf("%x", sha256.Sum256(blockHashInput))

	entry := map[string]interface{}{
		"height":    height,
		"timestamp": time.Now().Format(time.RFC3339),
		"blockhash": blockHash,
		"txs":       txEntries,
	}

	data, _ := json.Marshal(entry)
	f, _ := os.OpenFile(blocksFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.Write(append(data, '\n'))
	fmt.Printf("🧱 Block %d written to log (%d TXs)\n", height, len(txs))
}

func emptyMempool() {
	err := os.WriteFile(mempoolFile, []byte("[]\n"), 0644)
	if err != nil {
		fmt.Println("❌ Failed to clear mempool:", err)
	} else {
		fmt.Println("🧹 Mempool cleared")
	}
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
