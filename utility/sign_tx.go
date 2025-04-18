// sign_tx.go – CLI tool to sign XuChain transactions with nonce, address validation & auto-nonce
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"path/filepath"
	"io/ioutil"

	"xu/app"
)

const nonceFile = "xu_nonce.json"

func main() {
	// CLI flags
	from := flag.String("from", "", "Sender address")
	to := flag.String("to", "", "Recipient address")
	amount := flag.Int64("amount", 0, "Amount (Xu)")
	nonce := flag.Uint64("nonce", 0, "Optional: explicit nonce value")
	privkeyB64 := flag.String("priv", "", "Base64-encoded private key")
	flag.Parse()

	// Input validation
	if *from == "" || *to == "" || *amount <= 0 || *privkeyB64 == "" {
		fmt.Println("Usage: go run sign_tx.go -from=... -to=... -amount=... [-nonce=N] -priv=base64priv")
		os.Exit(1)
	}
	if !isValidAddress(*from) {
		fmt.Println("❌ Invalid sender address")
		os.Exit(1)
	}
	if !isValidAddress(*to) {
		fmt.Println("❌ Invalid recipient address")
		os.Exit(1)
	}

	// Calculate nonce if not set
	useNonce := *nonce
	if useNonce == 0 {
		useNonce = loadAndIncrementNonce(*from)
	}

	// Decode private key
	priv, err := base64.StdEncoding.DecodeString(*privkeyB64)
	if err != nil || len(priv) != 64 {
		fmt.Println("❌ Invalid private key")
		os.Exit(1)
	}
	pub := priv[32:]
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// Create transaction
	tx := app.Tx{
		Type:   "transfer",
		From:   *from,
		To:     *to,
		Amount: *amount,
		Nonce:  useNonce,
	}
	txBytes, _ := json.Marshal(tx)
	sig := app.Sign(txBytes, priv)

	// Create signed transaction
	signed := app.SignedTx{
		Tx:       tx,
		PubKey:   pubB64,
		Signature: sig,
	}

	// Output JSON
	out, _ := json.MarshalIndent(signed, "", "  ")
	fmt.Println(string(out))
}

func isValidAddress(addr string) bool {
	matched, _ := regexp.MatchString(`^Xu[a-f0-9]{10}$`, addr)
	return matched
}

func loadAndIncrementNonce(address string) uint64 {
	// Read file (or initialize map)
	nonces := map[string]uint64{}
	path := filepath.Join(".", nonceFile)
	if data, err := ioutil.ReadFile(path); err == nil {
		json.Unmarshal(data, &nonces)
	}

	// Increment nonce
	n := nonces[address] + 1
	nonces[address] = n

	// Save updated nonces
	out, _ := json.MarshalIndent(nonces, "", "  ")
	ioutil.WriteFile(path, out, 0644)
	return n
}
