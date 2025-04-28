// sign_redeem_veco.go – CLI tool to create a redeem request and signed burn TX (Type: redeem:<Veco Address>)
package main

import (
	"carp/app"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type RedeemRequest struct {
	AmountCarp  int64  `json:"amount_carp"`
	CarpAddress string `json:"carp_address"`
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
	carpAddr := flag.String("Ca", "", "CARP address")
	vecoAddr := flag.String("veco", "", "Veco address")
	amount := flag.Int64("amount", 0, "Amount in CARP to redeem")
	nonce := flag.Uint64("nonce", 0, "Optional: nonce for the burn TX")
	flag.Parse()

	if *privB64 == "" || *carpAddr == "" || *vecoAddr == "" || *amount <= 0 {
		fmt.Println("Usage: sign_redeem_veco -priv <privkey> -ca <CARP address> -veco <Veco address> -amount <CARP> [-nonce <n>]")
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
	message := fmt.Sprintf("%d|%s|%s", *amount, *carpAddr, *vecoAddr)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	redeemReq := RedeemRequest{
		AmountCarp:  *amount,
		CarpAddress: *carpAddr,
		VecoAddress: *vecoAddr,
		PubKey:      pubB64,
		Signature:   sigB64,
	}

	// Build burn TX
	useNonce := *nonce
	if useNonce == 0 {
		carpApp := app.NewCarpApp()
		currentNonce := carpApp.GetNonce(*carpAddr)
		useNonce = currentNonce + 1
	}

	tx := app.Tx{
		Type:   fmt.Sprintf("redeem:%s", *vecoAddr),
		From:   *carpAddr,
		To:     "Ca0000000000",
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
