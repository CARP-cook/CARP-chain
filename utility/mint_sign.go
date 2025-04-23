// mint_sign.go – Admin CLI tool to sign mint requests using JSON signing
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"xu/app"
)

func main() {
	addr := flag.String("addr", "", "Target address (e.g. Xuabcd123456)")
	amount := flag.Int("amount", 0, "Amount to mint")
	privB64 := flag.String("priv", "", "Base64-encoded private key (64 bytes)")
	flag.Parse()

	if *addr == "" || *amount <= 0 || *privB64 == "" {
		fmt.Println("Usage: go run mint_sign.go -addr=Xu... -amount=123 -priv=BASE64KEY")
		os.Exit(1)
	}

	// Decode private key
	priv, err := base64.StdEncoding.DecodeString(*privB64)
	if err != nil || len(priv) != 64 {
		fmt.Println("❌ Invalid base64 private key")
		os.Exit(1)
	}
	pub := priv[32:]

	// Use official app.Tx structure with explicit nonce and computed hash
	tx := app.Tx{
		Type:   "mint",
		To:     *addr,
		Amount: int64(*amount),
		Nonce:  0,
	}
	tx.Hash = app.ComputeTxHash(tx)

	// Canonical signing
	sig, err := app.SignCanonical(tx, priv)
	if err != nil {
		fmt.Println("❌ Failed to sign TX:", err)
		os.Exit(1)
	}

	// Assemble signed TX
	signed := app.SignedTx{
		Tx:        tx,
		PubKey:    base64.StdEncoding.EncodeToString(pub),
		Signature: sig,
	}

	// Output
	jsonBytes, _ := json.MarshalIndent(signed, "", "  ")
	fmt.Println(string(jsonBytes))
}
