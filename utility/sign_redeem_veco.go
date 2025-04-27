// sign_redeem_veco.go – CLI tool to create a redeem request and signed burn TX (Type: redeem:<Veco Address>)
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

type RedeemRequest struct {
	AmountXu    int64  `json:"amount_xu"`
	XuAddress   string `json:"xu_address"`
	VecoAddress string `json:"veco_address"`
	PubKey      string `json:"pubkey"`
	Signature   string `json:"signature"`
}

type RedeemPayload struct {
	RedeemRequest RedeemRequest `json:"redeem_request"`
	BurnTx        app.SignedTx  `json:"burn_tx"`
}

func main() {
	privB64 := flag.String("priv", "", "Base64-encoded private key")
	xuAddr := flag.String("xu", "", "Xu address")
	vecoAddr := flag.String("veco", "", "Veco address")
	amount := flag.Int64("amount", 0, "Amount in Xu to redeem")
	nonce := flag.Uint64("nonce", 0, "Optional: nonce for the burn TX")
	flag.Parse()

	if *privB64 == "" || *xuAddr == "" || *vecoAddr == "" || *amount <= 0 {
		fmt.Println("Usage: sign_redeem_veco -priv <privkey> -xu <Xu address> -veco <Veco address> -amount <Xu> [-nonce <n>]")
		os.Exit(1)
	}

	// Decode private key
	privKey, err := base64.StdEncoding.DecodeString(*privB64)
	if err != nil || len(privKey) != ed25519.PrivateKeySize {
		fmt.Println("❌ Invalid private key")
		os.Exit(1)
	}
	pubKey := privKey[32:]
	pubB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Build redeem request
	message := fmt.Sprintf("%d|%s|%s", *amount, *xuAddr, *vecoAddr)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	redeemReq := RedeemRequest{
		AmountXu:    *amount,
		XuAddress:   *xuAddr,
		VecoAddress: *vecoAddr,
		PubKey:      pubB64,
		Signature:   sigB64,
	}

	// Build burn TX
	useNonce := *nonce
	if useNonce == 0 {
		xuApp := app.NewXuApp()
		currentNonce := xuApp.GetNonce(*xuAddr)
		useNonce = currentNonce + 1
	}

	tx := app.Tx{
		Type:   fmt.Sprintf("redeem:%s", *vecoAddr),
		From:   *xuAddr,
		To:     "Xu0000000000",
		Amount: *amount,
		Nonce:  useNonce,
	}
	tx.Hash = app.ComputeTxHash(tx)
	canon := app.MustCanonicalJSON(tx)
	txSig := ed25519.Sign(privKey, canon)

	burnTx := app.SignedTx{
		Tx:        tx,
		PubKey:    pubB64,
		Signature: base64.StdEncoding.EncodeToString(txSig),
	}

	payload := RedeemPayload{
		RedeemRequest: redeemReq,
		BurnTx:        burnTx,
	}

	out, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(out))
}
