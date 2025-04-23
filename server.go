// server.go – XuChain REST-API with live state and mempool display
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"xu/app"

	"github.com/joho/godotenv"
)

var xuApp *app.XuApp
var mempool []app.SignedTx
var mempoolMu sync.Mutex

const mempoolFile = "xu_mempool.json"

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️ No .env file found – falling back to system env")
	}
}

func main() {
	xuApp = app.NewXuApp()

	http.HandleFunc("/balance", withCORS(handleBalance))
	http.HandleFunc("/nonce", withCORS(handleNonce))
	http.HandleFunc("/send", withCORS(handleSendToMempool))
	http.HandleFunc("/mempool", withCORS(handleMempool))
	http.HandleFunc("/blocks", withCORS(handleBlocks))
	http.HandleFunc("/send-multi", withCORS(handleMultiSendToMempool))

	fmt.Println("🌐 XuChain API running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func withCORS(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		fn(w, r)
	}
}

func handleBalance(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if !app.IsValidAddress(addr) {
		http.Error(w, "Invalid address", http.StatusBadRequest)
		return
	}
	freshApp := app.NewXuApp()
	bal := freshApp.GetBalance(addr)
	json.NewEncoder(w).Encode(map[string]interface{}{"address": addr, "balance": bal})
}

func handleNonce(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if !app.IsValidAddress(addr) {
		http.Error(w, "Invalid address", http.StatusBadRequest)
		return
	}
	freshApp := app.NewXuApp()
	nonce := freshApp.GetNonce(addr)
	json.NewEncoder(w).Encode(map[string]interface{}{"address": addr, "nonce": nonce})
}

func handleSendToMempool(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var tx app.SignedTx
	if err := json.Unmarshal(body, &tx); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(tx.PubKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}
	if !app.VerifyCanonicalSignature(tx.Tx, tx.Signature, pubKeyBytes) {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	adminPubKey := os.Getenv("XU_ADMIN_PUBKEY")
	if tx.Tx.Type == "mint" && tx.PubKey != adminPubKey {
		http.Error(w, "Unauthorized: only admin can mint", http.StatusForbidden)
		return
	}

	mempoolMu.Lock()
	if tx.Tx.Hash == "" {
		tx.Tx.Hash = app.ComputeTxHash(tx.Tx)
	}
	defer mempoolMu.Unlock()

	// 🧠 Neue Version liest die Datei → aktualisiert → schreibt zurück
	var mempool []app.SignedTx
	if raw, err := os.ReadFile(mempoolFile); err == nil {
		json.Unmarshal(raw, &mempool)
	}
	mempool = append(mempool, tx)

	data, _ := json.MarshalIndent(mempool, "", "  ")
	os.WriteFile(mempoolFile, data, 0644)

	w.Write([]byte("📝 TX added to mempool"))
}

func handleMempool(w http.ResponseWriter, r *http.Request) {
	mempoolMu.Lock()
	defer mempoolMu.Unlock()

	raw, err := os.ReadFile(mempoolFile)
	if err != nil {
		http.Error(w, "Mempool not available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func handleBlocks(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("xu_blocks.log")
	if err != nil {
		http.Error(w, "Log file not found", http.StatusInternalServerError)
		return
	}
	lines := bytes.Split(data, []byte("\n"))
	var blocks []map[string]interface{}
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var b map[string]interface{}
		if err := json.Unmarshal(line, &b); err == nil {
			blocks = append(blocks, b)
		}
	}
	json.NewEncoder(w).Encode(blocks)
}

func handleMultiSendToMempool(w http.ResponseWriter, r *http.Request) {
	type MultiPayload struct {
		Txs []app.SignedTx `json:"txs"`
	}

	var payload MultiPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	adminPubKey := os.Getenv("XU_ADMIN_PUBKEY")

	mempoolMu.Lock()
	defer mempoolMu.Unlock()

	var mempool []app.SignedTx
	if raw, err := os.ReadFile(mempoolFile); err == nil {
		json.Unmarshal(raw, &mempool)
	}

	var results []string

	for i, tx := range payload.Txs {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(tx.PubKey)
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			results = append(results, fmt.Sprintf("tx[%d]: invalid pubkey", i))
			continue
		}
		if !app.VerifyCanonicalSignature(tx.Tx, tx.Signature, pubKeyBytes) {
			results = append(results, fmt.Sprintf("tx[%d]: invalid signature", i))
			continue
		}
		if tx.Tx.Type == "mint" && tx.PubKey != adminPubKey {
			results = append(results, fmt.Sprintf("tx[%d]: unauthorized mint", i))
			continue
		}
		if tx.Tx.Hash == "" {
			tx.Tx.Hash = app.ComputeTxHash(tx.Tx)
		}
		mempool = append(mempool, tx)
		results = append(results, fmt.Sprintf("tx[%d]: accepted", i))
	}

	data, _ := json.MarshalIndent(mempool, "", "  ")
	os.WriteFile(mempoolFile, data, 0644)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"results": results,
	})
}
