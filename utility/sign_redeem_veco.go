// sign_redeem_veco.go – CLI tool to sign a redeem request for XuChain
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type RedeemPayload struct {
	AmountXu    int64  `json:"amount_xu"`
	XuAddress   string `json:"xu_address"`
	VecoAddress string `json:"veco_address"`
	PubKey      string `json:"pubkey"`
	Signature   string `json:"signature"`
}

func main() {
	privB64 := flag.String("priv", "", "Base64-encoded private key")
	xuAddr := flag.String("xu", "", "Xu address")
	vecoAddr := flag.String("veco", "", "Veco address")
	amount := flag.Int64("amount", 0, "Amount in Xu to redeem")
	flag.Parse()

	if *privB64 == "" || *xuAddr == "" || *vecoAddr == "" || *amount <= 0 {
		fmt.Println("Usage: sign_redeem -priv <privkey> -xu <Xu address> -veco <Veco address> -amount <amount in Xu>")
		os.Exit(1)
	}

	privKey, err := base64.StdEncoding.DecodeString(*privB64)
	if err != nil || len(privKey) != ed25519.PrivateKeySize {
		fmt.Println("❌ Invalid private key")
		os.Exit(1)
	}
	pubKey := privKey[32:]
	pubB64 := base64.StdEncoding.EncodeToString(pubKey)

	message := fmt.Sprintf("%d|%s|%s", *amount, *xuAddr, *vecoAddr)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	payload := RedeemPayload{
		AmountXu:    *amount,
		XuAddress:   *xuAddr,
		VecoAddress: *vecoAddr,
		PubKey:      pubB64,
		Signature:   sigB64,
	}

	out, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(out))
}
