// wallet.go – simple CLI tool to generate a new XuChain wallet
package main

import (
	"carp/app"
	"encoding/base64"
	"fmt"
)

func main() {
	pub, priv := app.GenerateKeyPair()
	addr := app.PublicKeyToAddress(pub)
	if !app.IsValidAddress(addr) {
		fmt.Println("❌ Generated address is INVALID!")
	} else {
		fmt.Println("✅ Address format and checksum are valid.")
	}

	fmt.Println("🔐 New wallet key generated:")
	fmt.Println("Address :", addr)
	fmt.Println("Public  :", base64.StdEncoding.EncodeToString(pub))
	fmt.Println("Private :", base64.StdEncoding.EncodeToString(priv))
}
