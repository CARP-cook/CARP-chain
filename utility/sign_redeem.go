// redeem_veco.go – CLI tool to create a redeem request and signed burn TX (Type: redeem:<Target Address>)
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
	AmountCarp    int64  `json:"amount_carp"`
	CarpAddress   string `json:"carp_address"`
	TargetAddress string `json:"target_address"`
	PubKey        string `json:"pubkey"`
	Signature     string `json:"signature"`
	Coin          string `json:"coin"`
}

type RedeemPayload struct {
	RedeemRequest RedeemRequest `json:"redeem_request"`
	BurnTx        app.SignedTx  `json:"burn_tx"`
}

func main() {
	privB64 := flag.String("priv", "", "Base64-encoded private key")
	carpAddr := flag.String("Ca", "", "CARP address")
	targetAddr := flag.String("target", "", "Target address on other chain (e.g. Veco or LTC)")
	amount := flag.Int64("amount", 0, "Amount in CARP to redeem")
	nonce := flag.Uint64("nonce", 0, "Optional: nonce for the burn TX")
	coin := flag.String("coin", "veco", "Target coin name (e.g., veco)")
	flag.Parse()

	if *privB64 == "" || *carpAddr == "" || *targetAddr == "" || *amount <= 0 {
		fmt.Println("Usage: sign_redeem -priv <privkey> -Ca <CARP address> -target <Target address> -amount <CARP> [-nonce <n>] [-coin <coin>]")
		os.Exit(1)
	}

	// Decode private key (support seed (32B) or full key (64B))
	privBytes, err := base64.StdEncoding.DecodeString(*privB64)
	if err != nil || (len(privBytes) != ed25519.SeedSize && len(privBytes) != ed25519.PrivateKeySize) {
		fmt.Println("❌ Invalid private key")
		os.Exit(1)
	}
	var privKey ed25519.PrivateKey
	if len(privBytes) == ed25519.SeedSize {
		privKey = ed25519.NewKeyFromSeed(privBytes)
	} else {
		privKey = privBytes
	}
	pubKey := privKey.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Build redeem request
	message := fmt.Sprintf("%d|%s|%s", *amount, *carpAddr, *coin)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	redeemReq := RedeemRequest{
		AmountCarp:    *amount,
		CarpAddress:   *carpAddr,
		TargetAddress: *targetAddr,
		PubKey:        pubB64,
		Signature:     sigB64,
		Coin:          *coin,
	}

	// Build burn TX
	useNonce := *nonce
	if useNonce == 0 {
		carpApp := app.NewCarpApp()
		currentNonce := carpApp.GetNonce(*carpAddr)
		useNonce = currentNonce + 1
	}

	tx := app.Tx{
		Type:   fmt.Sprintf("redeem:%s", *targetAddr),
		From:   *carpAddr,
		To:     "burn",
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
