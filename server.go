// server.go – XuChain REST-API with live state and mempool display
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"xu/app"
)

var xuApp *app.XuApp
var mempool []app.SignedTx
var mempoolMu sync.Mutex

const mempoolFile = "xu_mempool.json"

func main() {
	xuApp = app.NewXuApp()
	loadMempool()

	http.HandleFunc("/balance", withCORS(handleBalance))
	http.HandleFunc("/nonce", withCORS(handleNonce))
	http.HandleFunc("/send", withCORS(handleSendToMempool))
	http.HandleFunc("/faucet", withCORS(handleFaucet))
	http.HandleFunc("/mempool", withCORS(handleMempool))
	http.HandleFunc("/blocks", withCORS(handleBlocks))

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
	freshApp := app.NewXuApp() // always reload
	bal := freshApp.GetBalance(addr)
	json.NewEncoder(w).Encode(map[string]interface{}{"address": addr, "balance": bal})
}

func handleNonce(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if !app.IsValidAddress(addr) {
		http.Error(w, "Invalid address", http.StatusBadRequest)
		return
	}
	freshApp := app.NewXuApp() // always reload
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
	txBytes, _ := json.Marshal(tx.Tx)
	pubKeyBytes, err := base64Decode(tx.PubKey)
	if err != nil || !app.VerifySignature(txBytes, tx.Signature, pubKeyBytes) {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}
	mempoolMu.Lock()
	mempool = append(mempool, tx)
	saveMempool()
	mempoolMu.Unlock()
	w.Write([]byte("📝 TX added to mempool"))
}

func handleFaucet(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if !app.IsValidAddress(addr) {
		http.Error(w, "Invalid address", http.StatusBadRequest)
		return
	}
	tx := app.Tx{
		Type:   "mint",
		To:     addr,
		Amount: 100,
	}
	res, err := xuApp.ApplyTx(tx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	xuApp.SaveState()
	w.Write(res)
}

func handleMempool(w http.ResponseWriter, r *http.Request) {
	mempoolMu.Lock()
	defer mempoolMu.Unlock()
	json.NewEncoder(w).Encode(mempool)
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

func saveMempool() {
	data, _ := json.MarshalIndent(mempool, "", "  ")
	os.WriteFile(mempoolFile, data, 0644)
}

func loadMempool() {
	if raw, err := os.ReadFile(mempoolFile); err == nil {
		json.Unmarshal(raw, &mempool)
	}
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

