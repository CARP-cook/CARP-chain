// server.go – CARP Chain REST-API with live state and mempool display
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"carp/app"

	"github.com/joho/godotenv"
)

var CarpApp *app.CarpApp
var mempool []app.SignedTx
var mempoolMu sync.Mutex
var redeemLocks sync.Map    // map[address]time.Time
var pendingRedeems sync.Map // map[carpAddress]burnTxHash

const mempoolFile = "carp_mempool.json"

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️ No .env file found – falling back to system env")
	}
}

func main() {
	CarpApp = app.NewCarpApp()

	http.HandleFunc("/balance", withCORS(handleBalance))
	http.HandleFunc("/nonce", withCORS(handleNonce))
	http.HandleFunc("/send", withCORS(handleSendToMempool))
	http.HandleFunc("/mempool", withCORS(handleMempool))
	http.HandleFunc("/blocks", withCORS(handleBlocks))
	http.HandleFunc("/send-multi", withCORS(handleMultiSendToMempool))
	http.HandleFunc("/redeem", withCORS(handleRedeem))

	fmt.Println("🌐 CARP Chain API running at http://localhost:8080")
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
	freshApp := app.NewCarpApp()
	bal := freshApp.GetBalance(addr)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"address": addr, "balance": bal})
}

func handleNonce(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if !app.IsValidAddress(addr) {
		http.Error(w, "Invalid address", http.StatusBadRequest)
		return
	}
	freshApp := app.NewCarpApp()
	nonce := freshApp.GetNonce(addr)
	w.Header().Set("Content-Type", "application/json")
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

	adminPubKey := os.Getenv("CARP_ADMIN_PUBKEY")
	if tx.Tx.Type == "mint" && tx.PubKey != adminPubKey {
		http.Error(w, "Unauthorized: only admin can mint", http.StatusForbidden)
		return
	}

	mempoolMu.Lock()
	if tx.Tx.Hash == "" {
		tx.Tx.Hash = app.ComputeTxHash(tx.Tx)
	}
	defer mempoolMu.Unlock()

	// New version reads the file → updated → writes back
	var mempool []app.SignedTx
	if raw, err := os.ReadFile(mempoolFile); err == nil {
		json.Unmarshal(raw, &mempool)
	}
	for _, existing := range mempool {
		if existing.Tx.Hash == tx.Tx.Hash {
			http.Error(w, "Duplicate TX: already in mempool", http.StatusConflict)
			return
		}
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
	// Load all blocks/*.log files in order and collect all blocks
	files, err := filepath.Glob("blocks/*.log")
	if err != nil || len(files) == 0 {
		http.Error(w, "Log files not found", http.StatusInternalServerError)
		return
	}
	sort.Strings(files)
	var blocks []map[string]interface{}
	for _, fname := range files {
		f, err := os.Open(fname)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var b map[string]interface{}
			if err := json.Unmarshal(line, &b); err == nil {
				blocks = append(blocks, b)
			}
		}
		f.Close()
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

	adminPubKey := os.Getenv("CARP_ADMIN_PUBKEY")

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

func handleRedeem(w http.ResponseWriter, r *http.Request) {
	type RedeemRequest struct {
		AmountCarp    int64  `json:"amount_carp"`
		Coin          string `json:"coin"`
		CarpAddress   string `json:"carp_address"`
		TargetAddress string `json:"target_address"`
		PubKey        string `json:"pubkey"`
		Signature     string `json:"signature"`
	}
	type RedeemPayload struct {
		RedeemRequest RedeemRequest `json:"redeem_request"`
		BurnTx        app.SignedTx  `json:"burn_tx"`
	}

	var payload RedeemPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	var cliMap = map[string]string{
		"veco": "veco-cli",
		"ltc":  "electrum-ltc",
	}
	req := payload.RedeemRequest
	burnTx := payload.BurnTx

	// Prepare redeem quote
	var quoteStr string
	switch req.Coin {
	case "veco":
		quoteStr = os.Getenv("CARP_REDEEM_QUOTE")
		if quoteStr == "" {
			quoteStr = "1000"
		}
	case "ltc":
		quoteStr = os.Getenv("CARP_REDEEM_QUOTE_LTC")
		if quoteStr == "" {
			quoteStr = "71000000"
		}
	}

	// Check supported coin
	supportedCoins := map[string]bool{
		"veco": true,
		"ltc":  true,
	}
	if !supportedCoins[req.Coin] {
		http.Error(w, "Unsupported coin", http.StatusBadRequest)
		return
	}

	// Prevent parallel redeems for the same address
	if _, locked := pendingRedeems.Load(req.CarpAddress); locked {
		http.Error(w, "Redeem already in progress for this address", http.StatusTooManyRequests)
		return
	}
	// Mark address as redeeming immediately
	pendingRedeems.Store(req.CarpAddress, "lock")
	defer pendingRedeems.Delete(req.CarpAddress)

	// Validate CARP address
	if !app.IsValidAddress(req.CarpAddress) {
		http.Error(w, "Invalid CARP address", http.StatusBadRequest)
		return
	}

	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PubKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	// Verify redeem request signature
	message := fmt.Sprintf("%d|%s|%s", req.AmountCarp, req.CarpAddress, req.Coin)
	if !ed25519.Verify(pubKeyBytes, []byte(message), mustDecodeB64(req.Signature)) {
		http.Error(w, "Invalid redeem signature", http.StatusBadRequest)
		return
	}

	// Verify burnTx correctness
	expectedType := fmt.Sprintf("redeem:%s", req.TargetAddress)
	if !strings.HasPrefix(burnTx.Tx.Type, "redeem:") || burnTx.Tx.From != req.CarpAddress || burnTx.Tx.To != "burn" || burnTx.Tx.Amount != req.AmountCarp {
		http.Error(w, "Burn TX does not match redeem request", http.StatusBadRequest)
		return
	}
	// Additionally verify the redeem coin address inside the type
	if burnTx.Tx.Type != expectedType {
		http.Error(w, "Burn TX Type does not match redeem address", http.StatusBadRequest)
		return
	}
	burnPubKeyBytes, err := base64.StdEncoding.DecodeString(burnTx.PubKey)
	if err != nil || len(burnPubKeyBytes) != ed25519.PublicKeySize {
		http.Error(w, "Invalid burn TX public key", http.StatusBadRequest)
		return
	}
	if !app.VerifyCanonicalSignature(burnTx.Tx, burnTx.Signature, burnPubKeyBytes) {
		http.Error(w, "Invalid burn TX signature", http.StatusBadRequest)
		return
	}

	// Check CARP balance
	freshApp := app.NewCarpApp()
	currentBalance := freshApp.GetBalance(req.CarpAddress)
	if currentBalance < req.AmountCarp {
		http.Error(w, "Insufficient CARP balance", http.StatusPaymentRequired)
		return
	}

	// Reject if under LTC redeem minimum
	if req.Coin == "ltc" {
		ltcQuote, _ := strconv.ParseFloat(quoteStr, 64)
		ltcMinStr := os.Getenv("CARP_REDEEM_MIN_LTC")
		if ltcMinStr == "" {
			ltcMinStr = "0.00001"
		}
		ltcMin, _ := strconv.ParseFloat(ltcMinStr, 64)
		minRequired := int64(math.Ceil(ltcMin * ltcQuote))
		if req.AmountCarp < minRequired {
			http.Error(w, fmt.Sprintf("Minimum redeemable amount for LTC is %d CARP", minRequired), http.StatusBadRequest)
			return
		}
	}

	// Nonce check

	// Validate target coin address and get CLI command prefix
	var validateCmd *exec.Cmd
	var balanceCmd *exec.Cmd
	var sendCmd *exec.Cmd
	targetAddress := req.TargetAddress
	if !isSafeAddress(targetAddress) {
		http.Error(w, "Suspicious target address format", http.StatusBadRequest)
		log.Println("⚠️ Suspicious address format rejected:", targetAddress)
		return
	}
	log.Println("Redeem request for", req.Coin, "to address:", targetAddress)

	cliCmd, ok := cliMap[req.Coin]
	if !ok {
		http.Error(w, "Unsupported coin", http.StatusBadRequest)
		return
	}
	switch req.Coin {
	case "veco":
		validateCmd = exec.Command(cliCmd, "validateaddress", targetAddress)
		balanceCmd = exec.Command(cliCmd, "getbalance")
	case "ltc":
		validateCmd = exec.Command(cliCmd, "validateaddress", targetAddress)
		balanceCmd = exec.Command(cliCmd, "getbalance")
	default:
		http.Error(w, "Unsupported coin", http.StatusBadRequest)
		return
	}

	if req.Coin == "ltc" {
		if string(bytes.TrimSpace(func() []byte {
			out, err := validateCmd.CombinedOutput()
			if err != nil {
				log.Println(req.Coin, "validateaddress error:", string(out))
				http.Error(w, "Failed to validate target address", http.StatusInternalServerError)
				return []byte{}
			}
			return out
		}())) != "true" {
			http.Error(w, "Invalid target address", http.StatusBadRequest)
			return
		}
	} else {
		validateOutput, err := validateCmd.CombinedOutput()
		if err != nil {
			log.Println(req.Coin, "validateaddress error:", string(validateOutput))
			http.Error(w, "Failed to validate target address", http.StatusInternalServerError)
			return
		}
		var validationResult map[string]interface{}
		if err := json.Unmarshal(validateOutput, &validationResult); err != nil {
			http.Error(w, "Invalid response from validateaddress", http.StatusInternalServerError)
			return
		}
		if valid, ok := validationResult["isvalid"].(bool); !ok || !valid {
			http.Error(w, "Invalid target address", http.StatusBadRequest)
			return
		}
	}

	quote, err := strconv.ParseFloat(quoteStr, 64)
	if err != nil || quote <= 0 {
		http.Error(w, "Invalid redeem quote", http.StatusInternalServerError)
		return
	}
	targetAmount := float64(req.AmountCarp) / quote

	// Check available target coin balance
	balanceOutput, err := balanceCmd.CombinedOutput()
	if err != nil {
		log.Println(req.Coin, "getbalance error:", string(balanceOutput))
		http.Error(w, "Failed to check target coin balance", http.StatusInternalServerError)
		return
	}
	targetBalance, err := strconv.ParseFloat(string(bytes.TrimSpace(balanceOutput)), 64)
	if err != nil {
		http.Error(w, "Invalid target coin balance format", http.StatusInternalServerError)
		return
	}
	if targetBalance < targetAmount {
		http.Error(w, fmt.Sprintf("Insufficient %s balance: available %.8f, needed %.8f", req.Coin, targetBalance, targetAmount), http.StatusPaymentRequired)
		return
	}

	// 1. Burn CARP (add burnTx to mempool)
	mempoolMu.Lock()
	defer mempoolMu.Unlock()

	var mempool []app.SignedTx
	if raw, err := os.ReadFile(mempoolFile); err == nil {
		json.Unmarshal(raw, &mempool)
	}
	for _, existing := range mempool {
		if existing.Tx.Hash == burnTx.Tx.Hash {
			http.Error(w, "Duplicate TX: already in mempool", http.StatusConflict)
			return
		}
	}
	mempool = append(mempool, burnTx)

	data, err := json.MarshalIndent(mempool, "", "  ")
	if err != nil {
		http.Error(w, "Failed to encode mempool", http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(mempoolFile, data, 0644); err != nil {
		http.Error(w, "Failed to write to mempool", http.StatusInternalServerError)
		return
	}

	// Wait for burnTx to be included in a block (efficient: only last 1000 lines)
	confirmed := false
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		files, err := filepath.Glob("blocks/*.log")
		if err != nil || len(files) == 0 {
			continue
		}
		sort.Strings(files)
		latestFile := files[len(files)-1]
		f, err := os.Open(latestFile)
		if err != nil {
			continue
		}
		var lines [][]byte
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			lines = append(lines, append([]byte(nil), scanner.Bytes()...))
		}
		f.Close()
		if len(lines) > 1000 {
			lines = lines[len(lines)-1000:]
		}
		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			var blk struct {
				Txs []struct {
					Hash string `json:"hash"`
				} `json:"txs"`
			}
			if err := json.Unmarshal(line, &blk); err == nil {
				for _, tx := range blk.Txs {
					if tx.Hash == burnTx.Tx.Hash {
						confirmed = true
						break
					}
				}
			}
			if confirmed {
				break
			}
		}
		if confirmed {
			break
		}
	}
	if !confirmed {
		http.Error(w, "Burn transaction not confirmed in a block. Please try again later.", http.StatusRequestTimeout)
		return
	}

	// Check if this burnTx has already been used (confirmed before)
	usedTxsFile := "redeemed_burn_hashes.json"
	usedTxs := map[string]bool{}
	if data, err := os.ReadFile(usedTxsFile); err == nil {
		json.Unmarshal(data, &usedTxs)
	}
	if usedTxs[burnTx.Tx.Hash] {
		http.Error(w, "Burn TX has already been processed", http.StatusConflict)
		return
	}
	usedTxs[burnTx.Tx.Hash] = true
	updated, _ := json.MarshalIndent(usedTxs, "", "  ")
	os.WriteFile(usedTxsFile, updated, 0644)

	// 2. Send target coin
	sendCmd = exec.Command(cliCmd, "sendtoaddress", targetAddress, fmt.Sprintf("%.8f", targetAmount))
	if req.Coin == "ltc" {
		sendCmd = exec.Command(cliCmd, "payto", targetAddress, fmt.Sprintf("%.8f", targetAmount))
	}
	sendOutput, err := sendCmd.CombinedOutput()
	if err != nil {
		log.Println("❌ Failed to send", fmt.Sprintf("%.8f", targetAmount), req.Coin, "to", targetAddress)
		log.Println(req.Coin, "send error:", string(sendOutput))
		http.Error(w, "Failed to send target coin", http.StatusInternalServerError)
		return
	}

	txid := strings.TrimSpace(string(sendOutput))

	log.Println("✅ Sent", fmt.Sprintf("%.8f", targetAmount), req.Coin, "to", targetAddress, "TXID:", txid)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                         "success",
		"carp_burned":                    req.AmountCarp,
		fmt.Sprintf("%s_sent", req.Coin): fmt.Sprintf("%.8f", targetAmount),
		fmt.Sprintf("%s_txid", req.Coin): txid,
	})
}

func mustDecodeB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

func isSafeAddress(address string) bool {
	// Only allow alphanumeric characters, 26–42 characters long (typical for BTC/LTC addresses)
	return regexp.MustCompile(`^[a-zA-Z0-9]{26,42}$`).MatchString(address)
}
