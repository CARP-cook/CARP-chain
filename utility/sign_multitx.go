// sign_multitx.go – CLI tool to create and sign multiple XuChain transactions in one batch
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"xu/app"
)

type Transfer struct {
	To     string `json:"to"`
	Amount int64  `json:"amount"`
}

func main() {
	privKeyB64 := flag.String("priv", "", "Base64-encoded private key")
	fromAddr := flag.String("from", "", "Sender address")
	nonceStartFlag := flag.Uint64("nonce", 0, "Optional: starting nonce (default: current nonce + 1)")
	file := flag.String("file", "", "JSON file with array of {to, amount}")
	flag.Parse()

	xuApp := app.NewXuApp()

	useNonceStart := *nonceStartFlag
	if useNonceStart == 0 {
		current := xuApp.GetNonce(*fromAddr)
		useNonceStart = current + 1
	}

	if *privKeyB64 == "" || *fromAddr == "" || *file == "" {
		fmt.Println("Usage: sign_multitx -priv <base64> -from <addr> -nonce <n> -file <transfers.json>")
		os.Exit(1)
	}

	rawPriv, err := base64.StdEncoding.DecodeString(*privKeyB64)
	if err != nil || len(rawPriv) != ed25519.PrivateKeySize {
		fmt.Println("❌ Invalid private key")
		os.Exit(1)
	}
	priv := ed25519.PrivateKey(rawPriv)
	pub := priv.Public().(ed25519.PublicKey)

	f, err := os.ReadFile(*file)
	if err != nil {
		fmt.Println("❌ Could not read file:", err)
		os.Exit(1)
	}

	var transfers []Transfer
	if err := json.Unmarshal(f, &transfers); err != nil {
		fmt.Println("❌ Failed to parse JSON:", err)
		os.Exit(1)
	}

	var signed []app.SignedTx
	for i, t := range transfers {
		tx := app.Tx{
			Type:   "transfer",
			From:   *fromAddr,
			To:     t.To,
			Amount: t.Amount,
			Nonce:  useNonceStart + uint64(i),
		}

		hash := app.ComputeTxHash(tx)
		tx.Hash = hash
		canon := app.MustCanonicalJSON(tx)
		sig := ed25519.Sign(priv, canon)

		signed = append(signed, app.SignedTx{
			Tx:        tx,
			PubKey:    base64.StdEncoding.EncodeToString(pub),
			Signature: base64.StdEncoding.EncodeToString(sig),
		})
	}

	wrapped := map[string]interface{}{
		"txs": signed,
	}
	data, _ := json.MarshalIndent(wrapped, "", "  ")
	fmt.Println(string(data))
}
